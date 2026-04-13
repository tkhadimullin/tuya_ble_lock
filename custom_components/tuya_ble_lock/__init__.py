"""Tuya BLE Smart Lock integration — hub-based architecture.

One config entry per Tuya cloud account. All locks are devices under that hub.
Per-device BLE credentials are stored in a separate DeviceStore.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.const import Platform
from homeassistant.helpers import device_registry as dr

from .const import (
    DOMAIN,
    CONF_TUYA_EMAIL,
    CONF_TUYA_PASSWORD,
    CONF_TUYA_COUNTRY,
    CONF_TUYA_REGION,
)
from .credential_store import CredentialStore
from .device_store import DeviceStore
from .device_profiles import async_load_profile
from .models import TuyaBLELockData

_LOGGER = logging.getLogger(__name__)

# All platforms — switch is always loaded (persistent connection switch)
ALL_PLATFORMS = [
    Platform.LOCK,
    Platform.SENSOR,
    Platform.BUTTON,
    Platform.SWITCH,
    Platform.SELECT,
    Platform.NUMBER,
]


def _platforms_for_devices(profiles: dict[str, dict]) -> list[Platform]:
    """Determine which platforms to load based on all device profiles."""
    platforms = {Platform.LOCK, Platform.SENSOR, Platform.BUTTON, Platform.SWITCH}
    for profile in profiles.values():
        entities = profile.get("entities", {})
        if "volume_select" in entities:
            platforms.add(Platform.SELECT)
        if "auto_lock_time_number" in entities:
            platforms.add(Platform.NUMBER)
    return list(platforms)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    from .services import async_register_services

    # Migrate legacy per-device entries (v1) to hub model (v2)
    await _async_migrate_legacy_entries(hass)

    await async_register_services(hass)
    return True


async def _async_migrate_legacy_entries(hass: HomeAssistant) -> None:
    """Merge old per-device config entries into a single hub entry."""
    entries = hass.config_entries.async_entries(DOMAIN)
    legacy = [e for e in entries if e.version < 2]
    if not legacy:
        return

    _LOGGER.info("Migrating %d legacy config entries to hub model", len(legacy))

    # Load or create device store
    device_store = DeviceStore(hass)
    await device_store.async_load()

    # Collect cloud creds from first entry that has them
    cloud_creds = {}
    for entry in legacy:
        opts = entry.options or {}
        if opts.get(CONF_TUYA_EMAIL):
            cloud_creds = {
                CONF_TUYA_EMAIL: opts[CONF_TUYA_EMAIL],
                CONF_TUYA_PASSWORD: opts.get(CONF_TUYA_PASSWORD, ""),
                CONF_TUYA_COUNTRY: opts.get(CONF_TUYA_COUNTRY, ""),
                CONF_TUYA_REGION: opts.get(CONF_TUYA_REGION, ""),
            }
            break

    # Move all device data to the store and update credential records
    from .credential_store import CredentialStore
    cred_store = CredentialStore(hass)
    await cred_store.async_load()

    for entry in legacy:
        mac = entry.data.get("device_mac", "").upper()
        if mac and not device_store.get_device(mac):
            await device_store.async_add_device(mac, {
                "uuid": entry.data.get("device_uuid", ""),
                "login_key": entry.data.get("login_key", ""),
                "virtual_id": entry.data.get("virtual_id", ""),
                "auth_key": entry.data.get("auth_key", ""),
                "product_id": entry.data.get("product_id", ""),
                "name": entry.title,
            })
        # Update credential records: old entry_id -> MAC
        for cid, cdata in list(cred_store._data.get("credentials", {}).items()):
            if cdata.get("lock_entry_id") == entry.entry_id:
                cdata["lock_entry_id"] = mac
        for pid, pdata in list(cred_store._data.get("temp_passwords", {}).items()):
            if pdata.get("lock_entry_id") == entry.entry_id:
                pdata["lock_entry_id"] = mac
    await cred_store.async_save()

    # Convert first entry to hub format (v2)
    hub_entry = legacy[0]
    hass.config_entries.async_update_entry(
        hub_entry,
        data=cloud_creds,
        options={},
        version=2,
        unique_id=cloud_creds.get(CONF_TUYA_EMAIL, "tuya_ble_lock_hub"),
        title="Tuya BLE Locks",
    )

    # Remove remaining legacy entries
    for entry in legacy[1:]:
        await hass.config_entries.async_remove(entry.entry_id)

    _LOGGER.info(
        "Migration complete: hub entry=%s, %d devices in store",
        hub_entry.entry_id, len(device_store.devices),
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}

    # Load stores
    device_store = DeviceStore(hass)
    await device_store.async_load()

    if "credential_store" not in hass.data[DOMAIN]:
        cred_store = CredentialStore(hass)
        await cred_store.async_load()
        hass.data[DOMAIN]["credential_store"] = cred_store
    credential_store = hass.data[DOMAIN]["credential_store"]

    # Register hub device in device registry
    dev_reg = dr.async_get(hass)
    dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.entry_id)},
        name="Tuya BLE Locks",
        manufacturer="Tuya",
        model="BLE Lock Hub",
    )

    # Create coordinators for each known device
    from .ble_session import TuyaBLELockSession
    from .coordinator import TuyaBLELockCoordinator

    coordinators: dict[str, TuyaBLELockCoordinator] = {}
    profiles: dict[str, dict] = {}

    for mac, dev_data in device_store.devices.items():
        ble_device = bluetooth.async_ble_device_from_address(hass, mac, connectable=True)
        if not ble_device:
            _LOGGER.debug("BLE device %s not available at startup, skipping", mac)
            continue

        login_key = bytes.fromhex(dev_data.get("login_key", ""))
        virtual_id = bytes.fromhex(dev_data.get("virtual_id", ""))
        device_uuid = dev_data.get("uuid", "")
        product_id = dev_data.get("product_id")
        device_name = dev_data.get("name", mac)

        profile = await async_load_profile(hass, product_id)
        profiles[mac] = profile

        protocol_version = profile.get("protocol_version", 4)
        session = TuyaBLELockSession(
            hass, ble_device, login_key, virtual_id, device_uuid,
            protocol_version=protocol_version,
        )

        # Register bluetooth callback to keep BLE device reference fresh
        # This is critical for ESPHome BLE proxy support — the callback fires
        # whenever any adapter (local or proxy) sees an advertisement from this
        # device, updating the BLEDevice with the correct source/proxy routing.
        @callback
        def _async_update_ble(
            service_info: bluetooth.BluetoothServiceInfoBleak,
            change: bluetooth.BluetoothChange,
            _session=session,
        ) -> None:
            _session.set_ble_device(service_info.device)

        entry.async_on_unload(
            bluetooth.async_register_callback(
                hass,
                _async_update_ble,
                BluetoothCallbackMatcher({ADDRESS: mac}),
                bluetooth.BluetoothScanningMode.ACTIVE,
            )
        )

        coordinator = TuyaBLELockCoordinator(
            hass, entry, mac, device_name, dev_data,
            ble_device, session, profile,
        )
        coordinators[mac] = coordinator

        # One-shot status fetch in background
        entry.async_create_background_task(
            hass, coordinator.async_one_shot_status(),
            f"tuya_ble_lock_status_{mac}",
        )

    platforms = _platforms_for_devices(profiles)
    runtime_data = TuyaBLELockData(
        device_store=device_store,
        credential_store=credential_store,
        coordinators=coordinators,
        platforms=platforms,
    )
    entry.runtime_data = runtime_data
    hass.data[DOMAIN]["device_store"] = device_store

    await hass.config_entries.async_forward_entry_setups(entry, platforms)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data: TuyaBLELockData = entry.runtime_data
    for coordinator in data.coordinators.values():
        coordinator._stopping = True
        coordinator._persistent_connection = False
        if coordinator._keepalive_task and not coordinator._keepalive_task.done():
            coordinator._keepalive_task.cancel()
        if coordinator._idle_timer is not None:
            coordinator._idle_timer.cancel()
        await coordinator._session.async_disconnect()
    return await hass.config_entries.async_unload_platforms(entry, data.platforms)

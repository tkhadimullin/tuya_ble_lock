"""Lock platform for Tuya BLE lock.

Tracks actual locked/unlocked state via DP reports (motor_state transitions)
and passage mode sync (auto_lock DP).  State is persisted across restarts
via RestoreEntity.

State machine:
  - Unlock command → _is_locked=False immediately (optimistic)
  - After RELOCK_DELAY_S → scheduled callback sets _is_locked=True
    (unless passage mode keeps it unlocked)
  - DP 33 auto_lock=False (passage mode on) → _is_locked=False (overrides)
  - DP 33 auto_lock=True (passage mode off) → _is_locked=True
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .entity import TuyaBLELockEntity
from .models import TuyaBLELockData

_LOGGER = logging.getLogger(__name__)

# After an unlock command, schedule a re-lock after this many seconds.
# The motor cycle takes ~5-7s. For momentary deadbolts the bolt springs back.
# For latching locks, passage mode (auto_lock=False) will override.
RELOCK_DELAY_S = 10.0


async def async_setup_entry(hass, entry, async_add_entities):
    data: TuyaBLELockData = entry.runtime_data
    entities = []
    for mac, coordinator in data.coordinators.items():
        entities.append(TuyaBLELock(coordinator, entry))
    if entities:
        async_add_entities(entities)


class TuyaBLELock(TuyaBLELockEntity, LockEntity, RestoreEntity):
    _attr_name = None
    _attr_unique_id_suffix = "lock"

    def __init__(self, coordinator, entry) -> None:
        super().__init__(coordinator, entry)
        self._unlocking = False
        self._is_locked = True
        self._relock_unsub: Any = None  # cancel handle for scheduled re-lock

    @property
    def unique_id(self) -> str:
        return f"{self._mac}_lock"

    @property
    def icon(self) -> str:
        return "mdi:lock" if self.is_locked else "mdi:lock-open"

    @property
    def is_locked(self) -> bool:
        return self._is_locked

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"ble_connected": self.coordinator._session.is_connected}

    @property
    def is_locking(self) -> bool:
        return False

    @property
    def is_unlocking(self) -> bool:
        return self._unlocking

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last and last.state in ("locked", "unlocked"):
            self._is_locked = last.state == "locked"

    async def async_lock(self, **kwargs) -> None:
        self._cancel_relock()
        await self.coordinator.async_lock()
        self._is_locked = True
        self.async_write_ha_state()

    async def async_unlock(self, **kwargs) -> None:
        self._cancel_relock()
        self._unlocking = True
        self.async_write_ha_state()
        await self.coordinator.async_unlock()
        self._unlocking = False
        self._is_locked = False
        self.async_write_ha_state()
        # Schedule re-lock: for momentary deadbolts the bolt springs back.
        # For latching locks, passage mode (auto_lock=False) will override
        # in _delayed_relock.
        self._relock_unsub = self.hass.loop.call_later(
            RELOCK_DELAY_S, lambda: self.hass.async_create_task(self._delayed_relock()),
        )

    def _cancel_relock(self) -> None:
        if self._relock_unsub is not None:
            self._relock_unsub.cancel()
            self._relock_unsub = None

    async def _delayed_relock(self) -> None:
        """Re-lock state after delay unless passage mode keeps it unlocked."""
        self._relock_unsub = None
        auto_lock = self.coordinator.state.get("auto_lock")
        if auto_lock is False:
            # Passage mode on — lock stays unlocked
            _LOGGER.debug("Relock timer: passage mode active, staying unlocked")
            return
        if not self._is_locked:
            _LOGGER.debug("Relock timer: setting state to locked")
            self._is_locked = True
            self.async_write_ha_state()

    def _handle_coordinator_update(self) -> None:
        # Passage mode (auto_lock DP) is authoritative for latching locks:
        # auto_lock=False means passage mode on → stays unlocked.
        auto_lock = self.coordinator.state.get("auto_lock")
        if auto_lock is not None:
            if auto_lock is False and self._is_locked:
                self._cancel_relock()
                self._is_locked = False
            elif auto_lock is True and not self._is_locked:
                self._is_locked = True

        super()._handle_coordinator_update()

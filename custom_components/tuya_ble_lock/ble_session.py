"""BLE session management for Tuya BLE lock integration.

Adapted from lock_control.py LockSession + connect_and_setup().
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import struct
import time
from typing import Callable

from bleak import BleakClient
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

from . import ble_protocol
from .ble_protocol import parse_dp_report, parse_dp_report_v3, parse_frames
from .const import (
    WRITE_UUID,
    NOTIFY_UUID,
    CMD_DEVICE_INFO,
    CMD_PAIR,
    CMD_DP_WRITE_V3,
    CMD_DP_WRITE_V4,
    CMD_DEVICE_STATUS,
    CMD_TIME_V1,
    CMD_TIME_V2,
    CMD_RECV_DP,
    CMD_DP_REPORT_V4,
    SEC_NONE,
    SEC_AUTH_KEY,
    SEC_AUTH_SESSION,
    SEC_LOGIN_KEY,
    SEC_SESSION_KEY,
)

_LOGGER = logging.getLogger(__name__)


class DeviceAlreadyBoundError(Exception):
    """Raised when device is already bound and needs existing credentials or factory reset."""


class TuyaBLELockSession:
    """Manage a BLE connection and protocol state with a Tuya lock."""

    def __init__(
        self,
        hass: HomeAssistant,
        ble_device,
        login_key: bytes,
        virtual_id: bytes,
        device_uuid: str,
        auth_key: bytes | None = None,
        protocol_version: int = 4,
    ):
        self._hass = hass
        self._ble_device = ble_device
        self._login_key = login_key
        self._virtual_id = virtual_id
        self._device_uuid = device_uuid
        self._auth_key = auth_key
        self._protocol_version = protocol_version
        self._client: BleakClientWithServiceCache | None = None
        self._seq = ble_protocol.SequenceCounter()
        self._keys: dict[int, bytes] = {}
        if login_key:
            self._keys[SEC_LOGIN_KEY] = hashlib.md5(login_key).digest()
        if auth_key:
            self._keys[SEC_AUTH_KEY] = auth_key
        self._session_key: bytes | None = None
        self._notif_buf: list[bytes] = []
        self.is_connected = False
        self._lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._dp_report_callback: Callable[[list[dict]], None] | None = None
        self._write_uuid: str = WRITE_UUID
        self._notify_uuid: str = NOTIFY_UUID

    def set_ble_device(self, ble_device) -> None:
        """Update BLE device reference (called from bluetooth advertisement callback)."""
        self._ble_device = ble_device

    def _resolve_gatt_uuids(self) -> tuple[str | None, str | None]:
        """Find write and notify characteristic UUIDs from discovered services.

        Tries FD50 characteristics first, then falls back to scanning all services
        for any write-without-response + notify characteristic pair.
        Returns (write_uuid, notify_uuid) or (None, None) if not found.
        """
        if not self._client or not self._client.services:
            return None, None

        # Check if FD50 characteristics exist (get_characteristic returns None if not found)
        write_char = self._client.services.get_characteristic(WRITE_UUID)
        notify_char = self._client.services.get_characteristic(NOTIFY_UUID)
        if write_char is not None and notify_char is not None:
            self._write_uuid = WRITE_UUID
            self._notify_uuid = NOTIFY_UUID
            _LOGGER.debug("Using FD50 GATT characteristics for %s", self._ble_device.address)
            return WRITE_UUID, NOTIFY_UUID

        # Fall back: scan all services for write-without-response + notify chars
        write_uuid = None
        notify_uuid = None
        for svc in self._client.services:
            for char in svc.characteristics:
                if "write-without-response" in char.properties and not write_uuid:
                    write_uuid = char.uuid
                if "notify" in char.properties and not notify_uuid:
                    notify_uuid = char.uuid
        if write_uuid and notify_uuid:
            self._write_uuid = write_uuid
            self._notify_uuid = notify_uuid
            _LOGGER.debug(
                "Using discovered GATT characteristics for %s: write=%s notify=%s",
                self._ble_device.address, write_uuid, notify_uuid,
            )
            return write_uuid, notify_uuid

        return None, None

    def set_dp_report_callback(self, callback: Callable[[list[dict]], None]) -> None:
        """Set a callback for unsolicited DP reports (push-based updates)."""
        self._dp_report_callback = callback

    # ---------- internal helpers ----------
    def _on_disconnect(self, client):
        _LOGGER.debug("BLE disconnected")
        self.is_connected = False

    def _on_notify(self, sender, data):
        _LOGGER.debug("BLE NOTIFY received: len=%d hex=%s", len(data), bytes(data)[:40].hex())
        self._notif_buf.append(bytes(data))

    def _derive_session(self, srand: bytes) -> None:
        """Derive session keys from srand.

        keys[5] = MD5(login_key + srand) — for bound device reconnect
        keys[2] = MD5(auth_key_hex + srand) — for first activation
        """
        self._session_key = hashlib.md5(self._login_key + srand).digest()
        self._keys[SEC_SESSION_KEY] = self._session_key
        if self._auth_key:
            combined = self._auth_key.hex().encode("ascii") + srand
            self._keys[SEC_AUTH_SESSION] = hashlib.md5(combined).digest()

    async def _send_encrypted(self, cmd: int, data: bytes, sec_flag: int, ack_sn: int = 0):
        """Build encrypted fragments and write via GATT."""
        key = self._keys.get(sec_flag)
        if sec_flag != SEC_NONE and not key:
            raise RuntimeError(
                f"No key available for sec_flag={sec_flag}. "
                f"Available: {list(self._keys.keys())}. Session not established?"
            )
        if sec_flag == SEC_NONE:
            # Unencrypted: manually build frame + fragment
            frame = ble_protocol.TuyaBleFrame(
                sn=self._seq.next(), ack_sn=ack_sn, code=cmd, data=data
            )
            raw = frame.to_bytes()
            payload = bytes([SEC_NONE]) + raw
            writes = ble_protocol.fragment(payload, mtu=20, protocol_version=self._protocol_version)
        else:
            frame = ble_protocol.TuyaBleFrame(
                sn=self._seq.next(), ack_sn=ack_sn, code=cmd, data=data
            )
            raw = frame.to_bytes()
            encrypted = ble_protocol.encrypt_frame(key, sec_flag, raw)
            writes = ble_protocol.fragment(encrypted, mtu=20, protocol_version=self._protocol_version)
        _LOGGER.debug("GATT WRITE cmd=0x%04x sec=%d frags=%d", cmd, sec_flag, len(writes))
        for i, w in enumerate(writes):
            _LOGGER.debug("  frag[%d]: len=%d hex=%s", i, len(w), w.hex())
            await self._client.write_gatt_char(self._write_uuid, w, response=False)
            await asyncio.sleep(0.05)

    async def _send_recv(self, cmd: int, data: bytes, sec_flag: int, wait: float = 8.0) -> list[dict]:
        """Send command and wait for response with proper fragment reassembly."""
        async with self._lock:
            self._notif_buf.clear()
            await self._send_encrypted(cmd, data, sec_flag)
            # Wait for notifications to arrive
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                await asyncio.sleep(0.15)
                if self._notif_buf:
                    await asyncio.sleep(0.3)
                    break
                if not self._client or not self._client.is_connected:
                    _LOGGER.debug("Client disconnected while waiting for response")
                    return []
            raw = list(self._notif_buf)
            self._notif_buf.clear()
            if not raw:
                _LOGGER.debug("No BLE notifications received for cmd=0x%04x (waited %.1fs)", cmd, wait)
                return []
            _LOGGER.debug("Got %d raw notifications for cmd=0x%04x", len(raw), cmd)
            # Reassemble and decrypt all notifications at once
            frames = parse_frames(self._keys, raw)
            _LOGGER.debug("Parsed %d frames from %d notifications for cmd=0x%04x: %s",
                            len(frames), len(raw), cmd,
                            [(f["cmd"], f.get("data", b"")[:20].hex()) for f in frames])
            if not frames and raw:
                # We got data but couldn't decode — log reassembled payloads
                payloads = ble_protocol.reassemble(raw)
                for p in payloads:
                    _LOGGER.debug(
                        "Undecoded response: sec_flag=%d len=%d hex=%s",
                        p[0] if p else -1, len(p), p[:40].hex(),
                    )
            return frames

    async def _handle_time_requests(self, frames: list[dict]) -> None:
        """Respond to device time sync requests."""
        for f in frames:
            cmd = f["cmd"]
            if cmd == CMD_TIME_V1:
                ts = str(int(time.time() * 1000)).encode()
                tz = struct.pack(">h", -int(time.timezone / 36))
                await self._send_encrypted(cmd, ts + tz, SEC_SESSION_KEY, ack_sn=f["sn"])
            elif cmd == CMD_TIME_V2:
                t = time.localtime()
                tz = -int(time.timezone / 36)
                td = struct.pack(">BBBBBBBh", t.tm_year % 100, t.tm_mon, t.tm_mday,
                                 t.tm_hour, t.tm_min, t.tm_sec, t.tm_wday, tz)
                await self._send_encrypted(cmd, td, SEC_SESSION_KEY, ack_sn=f["sn"])

    async def _collect(self, timeout: float = 3.0) -> list[dict]:
        """Collect unsolicited reports (DP reports, time requests).

        Does NOT clear buffer at start — processes any pending data first.
        """
        async with self._lock:
            frames: list[dict] = []
            # Process any already-buffered notifications first
            if self._notif_buf:
                raw = list(self._notif_buf)
                self._notif_buf.clear()
                parsed = parse_frames(self._keys, raw)
                frames.extend(parsed)
                await self._handle_time_requests(parsed)
            # Then wait for more
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                await asyncio.sleep(0.2)
                if self._notif_buf:
                    await asyncio.sleep(0.3)
                    raw = list(self._notif_buf)
                    self._notif_buf.clear()
                    parsed = parse_frames(self._keys, raw)
                    frames.extend(parsed)
                    await self._handle_time_requests(parsed)
            return frames

    @staticmethod
    def _extract_dps_from_frame(f: dict) -> list[dict]:
        """Extract DPs from a single frame (V4 or V3 format)."""
        if f["cmd"] == CMD_DP_REPORT_V4:
            return parse_dp_report(f["data"])
        if f["cmd"] == CMD_RECV_DP:
            return parse_dp_report_v3(f["data"])
        return []

    def _dispatch_dp_reports(self, frames: list[dict]) -> None:
        """Extract DP reports from frames and push to coordinator callback."""
        if not self._dp_report_callback:
            return
        all_dps = []
        for f in frames:
            dps = self._extract_dps_from_frame(f)
            if dps:
                _LOGGER.debug("Extracted DPs from cmd=0x%04x: %s",
                                f["cmd"], [(d["id"], d["raw"].hex()) for d in dps])
            all_dps.extend(dps)
        if all_dps:
            self._dp_report_callback(all_dps)

    # ---------- public API ----------
    async def async_connect_single_attempt(self) -> bool:
        """One-shot connect: single attempt, no retries. For startup battery fetch."""
        async with self._connect_lock:
            return await self._async_connect_inner(max_attempts=1)

    async def async_connect(self) -> bool:
        """Connect to the lock using stored login_key (bound device reconnect).

        Retry logic mirrors the pairing flow — device may be asleep between ads.
        Uses _connect_lock to prevent concurrent connection attempts.
        """
        async with self._connect_lock:
            return await self._async_connect_inner()

    async def _async_connect_inner(self, max_attempts: int = 3) -> bool:
        if self.is_connected:
            return True

        mtu_data = struct.pack(">H", 20)
        srand = None

        for attempt in range(max_attempts):
            try:
                await self.async_disconnect()
                # BLE device is kept fresh by bluetooth callback in __init__.py
                # Log which BLE adapter/source will be used
                _details = getattr(self._ble_device, 'details', None) or {}
                _source = _details.get('source') if isinstance(_details, dict) else getattr(_details, 'source', None)
                _LOGGER.debug("Reconnect attempt %d/%d for %s (source=%s, rssi=%s): connecting...",
                              attempt + 1, max_attempts, self._ble_device.address,
                              _source, getattr(self._ble_device, 'rssi', '?'))
                self._client = await establish_connection(
                    client_class=BleakClientWithServiceCache,
                    device=self._ble_device,
                    name="tuya_ble_lock",
                    disconnected_callback=self._on_disconnect,
                    max_attempts=2,
                    use_services_cache=True,
                    ble_device_callback=lambda: self._ble_device,
                )
                # Log discovered services on first successful connection
                if self._client.services:
                    for svc in self._client.services:
                        chars = [f"{c.uuid}({','.join(c.properties)})" for c in svc.characteristics]
                        _LOGGER.debug("  GATT Service %s: %s", svc.uuid, chars)
                else:
                    _LOGGER.debug("No GATT services discovered for %s", self._ble_device.address)
                # Resolve write/notify UUIDs — try FD50 first, fall back to A201
                write_uuid, notify_uuid = self._resolve_gatt_uuids()
                if not write_uuid or not notify_uuid:
                    _LOGGER.error(
                        "No compatible GATT characteristics found for %s. "
                        "Services: %s",
                        self._ble_device.address,
                        [s.uuid for s in self._client.services] if self._client.services else "none",
                    )
                    await asyncio.sleep(2.0)
                    continue
                # Always try stop_notify first to release any stale subscription
                try:
                    await self._client.stop_notify(notify_uuid)
                    await asyncio.sleep(0.2)
                except Exception:
                    pass
                self._notif_buf.clear()
                _LOGGER.debug("Starting notify on %s for %s", notify_uuid, self._ble_device.address)
                try:
                    await self._client.start_notify(notify_uuid, self._on_notify)
                except Exception as notify_exc:
                    if "Notify acquired" in str(notify_exc):
                        # BlueZ kept stale subscription — disconnect fully and retry
                        _LOGGER.debug("Stale notify subscription, disconnecting to clear: %s", notify_exc)
                        try:
                            await self._client.disconnect()
                        except Exception:
                            pass
                        await asyncio.sleep(1.0)
                        continue
                    raise
                self.is_connected = True

                # Some devices (e.g. H8 Pro with service 1910) auto-push
                # DEVICE_INFO + PAIR + TIME + DPs after notification enable.
                # Wait for auto-push, then try explicit DEVICE_INFO if nothing arrived.
                # Note: some devices send PAIR/TIME BEFORE DEVICE_INFO, so we
                # wait the full timeout and try to parse what we have.
                deadline_auto = time.monotonic() + 5.0
                got_data = False
                while time.monotonic() < deadline_auto:
                    await asyncio.sleep(0.2)
                    if self._notif_buf:
                        got_data = True
                        # Try parsing what we have — break if we can decode DEVICE_INFO
                        raw_peek = list(self._notif_buf)
                        peek_frames = parse_frames(self._keys, raw_peek)
                        if any(f["cmd"] == CMD_DEVICE_INFO and len(f["data"]) >= 12
                               for f in peek_frames):
                            await asyncio.sleep(0.5)  # let remaining fragments arrive
                            break

                raw = list(self._notif_buf)
                self._notif_buf.clear()

                if not got_data:
                    # No auto-push: send DEVICE_INFO explicitly (FD50 devices)
                    _LOGGER.debug("No auto-push, sending device info (sec_flag=4)")
                    await self._send_encrypted(CMD_DEVICE_INFO, mtu_data, SEC_LOGIN_KEY)
                    deadline_di = time.monotonic() + 6.0
                    while time.monotonic() < deadline_di:
                        await asyncio.sleep(0.2)
                        if self._notif_buf:
                            await asyncio.sleep(0.3)
                            break
                    raw = list(self._notif_buf)
                    self._notif_buf.clear()

                if not raw:
                    _LOGGER.debug("No device info response on attempt %d", attempt + 1)
                    await asyncio.sleep(2.0)
                    continue

                _LOGGER.debug(
                    "Got %d raw notifications for device info, sizes=%s",
                    len(raw), [len(r) for r in raw[:10]],
                )
                frames = parse_frames(self._keys, raw)
                if not frames:
                    _LOGGER.debug("Could not decrypt device info response (attempt %d)", attempt + 1)
                    await asyncio.sleep(2.0)
                    continue
                # Dispatch any DP reports that arrived with device info
                self._dispatch_dp_reports(frames)

                for f in frames:
                    if f["cmd"] == CMD_DEVICE_INFO and len(f["data"]) >= 12:
                        srand = f["data"][6:12]
                        _LOGGER.debug("Device info OK, srand=%s", srand.hex())
                        break
                if srand:
                    break
            except Exception as exc:
                _LOGGER.debug("Reconnect attempt %d for %s failed: %s",
                              attempt + 1, self._ble_device.address, exc)
                await asyncio.sleep(2.0)

        if not srand:
            _LOGGER.debug("No device info response from %s after %d reconnect attempt(s)",
                         self._ble_device.address, max_attempts)
            self.is_connected = False
            return False

        self._derive_session(srand)
        await self._handle_time_requests(frames)

        # After deriving session key, collect remaining auto-pushed data
        # (PAIR + TIME_REQUEST + DPs arrive ~0.3s after DEVICE_INFO)
        post_di = await self._collect(timeout=3.5)
        _LOGGER.debug("Post-DEVICE_INFO collect: %d frames: %s",
                      len(post_di), [(f["cmd"], f.get("sec_flag")) for f in post_di])
        all_frames = frames + post_di
        self._dispatch_dp_reports(post_di)

        # Check if PAIR was already auto-pushed (e.g. H8 Pro)
        pair_already = any(f["cmd"] == CMD_PAIR for f in all_frames)
        if pair_already:
            _LOGGER.debug("PAIR already received in auto-push, skipping pair command")
        else:
            # Pair/reauth: uuid(16) + login_key(6) + virtual_id(22) padded to 44
            uuid_bytes = self._device_uuid.encode()[:16]
            pair_data = uuid_bytes + self._login_key + self._virtual_id[:22]
            pair_data = (pair_data + b"\x00" * 44)[:44]

            self._notif_buf.clear()
            await self._send_encrypted(CMD_PAIR, pair_data, SEC_SESSION_KEY)
            # Poll until pair response arrives instead of flat 3s wait
            deadline_pr = time.monotonic() + 3.0
            while time.monotonic() < deadline_pr:
                await asyncio.sleep(0.2)
                if self._notif_buf:
                    await asyncio.sleep(0.3)
                    break

            raw = list(self._notif_buf)
            self._notif_buf.clear()
            if raw:
                pair_frames = parse_frames(self._keys, raw)
                await self._handle_time_requests(pair_frames)
                self._dispatch_dp_reports(pair_frames)
            else:
                _LOGGER.debug("No pair/reauth response (may be OK)")

        # Collect extra unsolicited reports (DP reports, time requests)
        extra = await self._collect(timeout=1.5)
        self._dispatch_dp_reports(extra)

        # Note: volume safety check removed — DP 71 (ble_unlock_check) works even with mute.
        # DP 46 (manual_lock) still requires volume=normal, but we no longer use it.

        _LOGGER.info("BLE session established with %s", self._ble_device.address)
        return True

    async def async_disconnect(self) -> None:
        if self._client:
            try:
                await self._client.stop_notify(self._notify_uuid)
            except Exception:
                pass
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None
        self.is_connected = False

    def _build_dp_payload(self, dp_id: int, dp_type: int, value: bytes) -> tuple[int, bytes]:
        """Build DP write command + payload for the correct protocol version.

        V3 (service 1910): cmd=0x0002, KLV=[dp_id:1][type:1][len:1][val]
        V4 (service FD50): cmd=0x0027, KLV=[hdr:5][dp_id:1][type:1][len:2][val]
        """
        if self._protocol_version <= 3:
            return CMD_DP_WRITE_V3, ble_protocol.build_v3_dp(dp_id, dp_type, value)
        return CMD_DP_WRITE_V4, ble_protocol.build_v4_dp(dp_id, dp_type, value)

    async def async_send_dp_fire_and_forget(self, dp_id: int, dp_type: int, value: bytes) -> None:
        """Send a DP write without waiting for response. Used for lock/unlock."""
        cmd, payload = self._build_dp_payload(dp_id, dp_type, value)
        async with self._lock:
            await self._send_encrypted(cmd, payload, SEC_SESSION_KEY)
            # Brief wait to ensure BLE write completes before disconnect
            await asyncio.sleep(0.3)

    async def async_send_dp(self, dp_id: int, dp_type: int, value: bytes) -> dict | None:
        """Send a DP write and return the matching DP from the response."""
        cmd, payload = self._build_dp_payload(dp_id, dp_type, value)
        frames = await self._send_recv(cmd, payload, SEC_SESSION_KEY)
        await self._handle_time_requests(frames)
        self._dispatch_dp_reports(frames)
        for f in frames:
            for dp in self._extract_dps_from_frame(f):
                if dp["id"] == dp_id:
                    return dp
        # Also collect follow-up reports
        extra = await self._collect(timeout=1.0)
        self._dispatch_dp_reports(extra)
        for f in extra:
            for dp in self._extract_dps_from_frame(f):
                if dp["id"] == dp_id:
                    return dp
        return None

    async def async_send_dp_bool(self, dp_id: int, value: bool) -> bool:
        val = b"\x01" if value else b"\x00"
        dp = await self.async_send_dp(dp_id, 1, val)
        return dp is not None

    async def async_send_dp_raw(self, dp_id: int, payload: bytes) -> dict | None:
        return await self.async_send_dp(dp_id, 0, payload)

    async def async_query_status(self) -> list[dict]:
        """Send CMD_DEVICE_STATUS, collect all DP reports."""
        _LOGGER.debug("Sending status query (CMD=0x%04x, sec=%d)", CMD_DEVICE_STATUS, SEC_SESSION_KEY)
        frames = await self._send_recv(CMD_DEVICE_STATUS, b"", SEC_SESSION_KEY)
        await self._handle_time_requests(frames)
        results: list[dict] = []
        for f in frames:
            _LOGGER.debug("Status frame: cmd=0x%04x data=%s", f["cmd"], f.get("data", b"")[:40].hex())
            results.extend(self._extract_dps_from_frame(f))
        # Collect follow-up DP reports (5s like lock_control.py)
        extra = await self._collect(timeout=5.0)
        for f in extra:
            _LOGGER.debug("Extra frame: cmd=0x%04x data=%s", f["cmd"], f.get("data", b"")[:40].hex())
            results.extend(self._extract_dps_from_frame(f))
        self._dispatch_dp_reports(frames + extra)
        return results

    async def async_send_dp_raw_long(
        self, dp_id: int, payload: bytes, timeout: float = 60.0
    ) -> list[dict]:
        """Send a RAW DP and collect all DP reports over an extended period.

        Used for fingerprint/card enrollment where the device sends multiple
        progress reports over 30-60 seconds.
        """
        cmd, initial_payload = self._build_dp_payload(dp_id, 0, payload)
        frames = await self._send_recv(cmd, initial_payload, SEC_SESSION_KEY, wait=10.0)
        await self._handle_time_requests(frames)
        results: list[dict] = []
        for f in frames:
            results.extend(self._extract_dps_from_frame(f))

        # Wait for multi-step enrollment reports
        deadline = time.monotonic() + timeout
        done = False
        while not done and time.monotonic() < deadline:
            extra = await self._collect(timeout=5.0)
            for f in extra:
                for dp in self._extract_dps_from_frame(f):
                    results.append(dp)
                    if dp["id"] == dp_id and dp["type"] == 0 and len(dp["raw"]) >= 2:
                        stage = dp["raw"][1]
                        if stage in (0xFF, 0xFD, 0xFE):  # COMPLETE, FAILED, CANCELLED
                            done = True
        self._dispatch_dp_reports(frames)
        return results

    async def async_pair_first_activation(self, auth_key_hex: str) -> tuple[bytes, bytes]:
        """Perform first-time pairing with the lock.

        Closely follows lock_control.py connect_and_setup() first-activation path.
        Returns (login_key, virtual_id) bytes on success.
        """
        auth_key_bytes = bytes.fromhex(auth_key_hex) if auth_key_hex else b""

        # Step 1: Device info with sec_flag=0 (unencrypted), with MTU
        # Retry with fresh BLE connection each attempt (device sleeps between ads)
        mtu_data = struct.pack(">H", 20)
        srand = None
        for attempt in range(5):
            _LOGGER.info("Pair attempt %d/5: connecting...", attempt + 1)
            try:
                await self.async_disconnect()
                self._client = await establish_connection(
                    client_class=BleakClientWithServiceCache,
                    device=self._ble_device,
                    name="tuya_ble_lock",
                    disconnected_callback=self._on_disconnect,
                    max_attempts=2,
                    use_services_cache=True,
                    ble_device_callback=lambda: self._ble_device,
                )
                # Log discovered services
                if self._client.services:
                    for svc in self._client.services:
                        chars = [f"{c.uuid}({','.join(c.properties)})" for c in svc.characteristics]
                        _LOGGER.info("  Service %s: %s", svc.uuid, chars)
                write_uuid, notify_uuid = self._resolve_gatt_uuids()
                if not write_uuid or not notify_uuid:
                    _LOGGER.error(
                        "No compatible GATT characteristics for %s",
                        self._ble_device.address,
                    )
                    await asyncio.sleep(2.0)
                    continue
                try:
                    await self._client.stop_notify(notify_uuid)
                    await asyncio.sleep(0.2)
                except Exception:
                    pass
                await self._client.start_notify(notify_uuid, self._on_notify)
                self.is_connected = True

                # Send device info unencrypted — matches lock_control.py exactly
                _LOGGER.info("Connected, sending device info (sec_flag=0)")
                self._notif_buf.clear()
                await self._send_encrypted(CMD_DEVICE_INFO, mtu_data, SEC_NONE)
                await asyncio.sleep(4.0)  # flat 4s wait like lock_control.py

                raw = list(self._notif_buf)
                self._notif_buf.clear()
                if not raw:
                    _LOGGER.debug("No device info response on attempt %d", attempt + 1)
                    await asyncio.sleep(2.0)
                    continue

                _LOGGER.info("Got %d raw notifications for device info", len(raw))
                frames = parse_frames(self._keys, raw)
                if not frames:
                    # Try parsing as unencrypted manually
                    payloads = ble_protocol.reassemble(raw)
                    for p in payloads:
                        if p and p[0] == 0:
                            try:
                                f = ble_protocol.TuyaBleFrame.from_bytes(p[1:])
                                frames = [{"cmd": f.code, "sn": f.sn, "ack_sn": f.ack_sn,
                                           "data": f.data, "sec_flag": 0}]
                            except Exception:
                                pass

                for f in frames:
                    if f["cmd"] == CMD_DEVICE_INFO and len(f["data"]) >= 12:
                        srand = f["data"][6:12]
                        bound = f["data"][5]
                        _LOGGER.info("Device bound=%s, srand=%s", "YES" if bound else "NO", srand.hex())
                        break
                if srand:
                    break
            except Exception as exc:
                _LOGGER.warning("Attempt %d failed: %s", attempt + 1, exc)
            await asyncio.sleep(2.0)

        if not srand:
            raise DeviceAlreadyBoundError(
                "No device info response after 5 attempts — "
                "device may be already bound or not in pairing mode."
            )

        # Derive session keys
        if auth_key_bytes:
            self._auth_key = auth_key_bytes
            self._keys[SEC_AUTH_KEY] = auth_key_bytes
        self._derive_session(srand)

        # Step 2: Generate new login_key and virtual_id
        new_login_key = secrets.token_bytes(6)
        new_virtual_id = secrets.token_bytes(22)
        uuid_bytes = self._device_uuid.encode()[:16]
        pair_data = uuid_bytes + new_login_key + new_virtual_id
        pair_data = (pair_data + b"\x00" * 44)[:44]

        _LOGGER.info("Pair data: uuid=%s login_key=%s virtual_id=%s",
                      uuid_bytes.hex(), new_login_key.hex(), new_virtual_id.hex())

        # Build full trial key set (matches lock_control.py trial_keys)
        new_session_key = hashlib.md5(new_login_key + srand).digest()
        new_key4 = hashlib.md5(new_login_key).digest()
        self._keys[SEC_SESSION_KEY] = new_session_key
        self._keys[SEC_LOGIN_KEY] = new_key4
        # key 0 placeholder for unencrypted-response parsing (not used for AES)

        # Step 3: Try pairing — SEC_NONE first (correct for unbound/reset devices),
        # then encrypted variants as fallback
        pair_success = False
        for try_flag in [SEC_NONE, SEC_AUTH_SESSION, SEC_AUTH_KEY]:
            if try_flag != SEC_NONE and not self._keys.get(try_flag):
                _LOGGER.debug("Skipping sec_flag=%d (no key)", try_flag)
                continue

            # Reconnect if connection was lost during a previous attempt
            if not self._client or not self._client.is_connected:
                _LOGGER.info("Reconnecting before sec_flag=%d attempt...", try_flag)
                try:
                    await self.async_disconnect()
                    self._client = await establish_connection(
                        client_class=BleakClient,
                        device=self._ble_device,
                        name="tuya_ble_lock",
                        disconnected_callback=self._on_disconnect,
                        max_attempts=2,
                    )
                    write_uuid, notify_uuid = self._resolve_gatt_uuids()
                    if not write_uuid or not notify_uuid:
                        _LOGGER.warning("No compatible GATT characteristics after reconnect")
                        continue
                    try:
                        await self._client.stop_notify(notify_uuid)
                        await asyncio.sleep(0.2)
                    except Exception:
                        pass
                    await self._client.start_notify(notify_uuid, self._on_notify)
                    self.is_connected = True
                except Exception as exc:
                    _LOGGER.warning("Reconnect failed: %s", exc)
                    continue

            _LOGGER.info("Trying CMD_PAIR with sec_flag=%d", try_flag)

            if try_flag == SEC_NONE:
                # Unencrypted pair — manual send + long wait (matches lock_control.py)
                try:
                    self._notif_buf.clear()
                    await self._send_encrypted(CMD_PAIR, pair_data, SEC_NONE)
                    await asyncio.sleep(5.0)  # flat 5s wait like lock_control.py
                    raw_resp = list(self._notif_buf)
                    self._notif_buf.clear()
                except Exception as exc:
                    _LOGGER.warning("SEC_NONE pair send failed: %s", exc)
                    continue

                if not raw_resp:
                    _LOGGER.info("No response for sec_flag=0 pair")
                    continue

                _LOGGER.info("Got %d notifications for sec_flag=0 pair", len(raw_resp))
                p_msgs = ble_protocol.reassemble(raw_resp)
                _LOGGER.info("Reassembled %d messages", len(p_msgs))

                # Device may respond encrypted with new session key (sec_flag=5)
                # or unencrypted (sec_flag=0). Try all keys like lock_control.py.
                trial_keys = dict(self._keys)
                for mi, p0 in enumerate(p_msgs):
                    sec_byte = p0[0] if p0 else -1
                    _LOGGER.info("  msg[%d]: sec_flag=%d len=%d hex=%s",
                                 mi, sec_byte, len(p0), p0[:40].hex())
                    if sec_byte == 0:
                        # Unencrypted response
                        try:
                            f = ble_protocol.TuyaBleFrame.from_bytes(p0[1:])
                            _LOGGER.info("    cmd=0x%04X data=%s", f.code, f.data.hex())
                            if f.code == CMD_PAIR and f.data and f.data[0] == 0x00:
                                pair_success = True
                        except Exception as exc:
                            _LOGGER.debug("    Unencrypted parse failed: %s", exc)
                    else:
                        key = trial_keys.get(sec_byte)
                        if key:
                            try:
                                raw_dec = ble_protocol.decrypt_frame(key, p0)
                                f = ble_protocol.TuyaBleFrame.from_bytes(raw_dec)
                                _LOGGER.info("    Decrypted: cmd=0x%04X data=%s",
                                             f.code, f.data.hex() if f.data else "")
                                if f.code == CMD_PAIR and f.data and f.data[0] == 0x00:
                                    pair_success = True
                            except Exception as exc:
                                _LOGGER.debug("    Decrypt failed with key %d: %s", sec_byte, exc)
                        else:
                            _LOGGER.info("    No key for sec_flag=%d", sec_byte)
                if pair_success:
                    break
            else:
                # Encrypted pair attempt
                try:
                    pair_frames = await self._send_recv(CMD_PAIR, pair_data, try_flag, wait=8.0)
                except Exception as exc:
                    _LOGGER.warning("Pair with sec_flag=%d failed: %s", try_flag, exc)
                    continue
                if pair_frames:
                    for pf in pair_frames:
                        status = pf["data"][0] if pf.get("data") else -1
                        _LOGGER.info("  Pair response: cmd=0x%04X status=%d", pf["cmd"], status)
                        if pf["cmd"] == CMD_PAIR and status == 0x00:
                            pair_success = True
                            break
                    if pair_success:
                        await self._handle_time_requests(pair_frames)
                        break
                else:
                    _LOGGER.info("  No response for sec_flag=%d", try_flag)

        if not pair_success:
            raise Exception("Pairing failed — no successful response from device")

        _LOGGER.info("Pair SUCCESS! login_key=%s", new_login_key.hex())

        # Update keys for the new credentials
        self._login_key = new_login_key
        self._virtual_id = new_virtual_id
        self._keys[SEC_LOGIN_KEY] = hashlib.md5(new_login_key).digest()
        self._derive_session(srand)

        # Collect any extra notifications
        extra = await self._collect(timeout=2.0)
        await self._handle_time_requests(extra)
        await self.async_disconnect()

        return new_login_key, new_virtual_id

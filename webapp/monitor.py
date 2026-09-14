"""
Live Modbus monitor service for M.A.T.R.I.X Web API.

Polls target Modbus state at regular intervals (read-only) and provides
streaming updates via Server-Sent Events.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pymodbus.client import ModbusTcpClient

from attacks.validation import ModbusValidator

logger = logging.getLogger(__name__)


class MonitorSession:
    """Single active monitoring session."""

    def __init__(self, target: Dict[str, Any], window: Dict[str, int], interval: float = 1.0):
        self.target = target
        self.window = window
        self.interval = interval

        # State
        self.connected = False
        self.last_updated: Optional[str] = None
        self.last_error: Optional[str] = None
        self.coils: Dict[int, bool] = {}
        self.holding_registers: Dict[int, int] = {}

        # Control
        self.client: Optional[ModbusTcpClient] = None
        self.task: Optional[asyncio.Task] = None
        self.running = False

    def get_state(self) -> Dict[str, Any]:
        """Get current snapshot of monitored state."""
        return {
            "connected": self.connected,
            "last_updated": self.last_updated,
            "target": self.target,
            "window": self.window,
            "coils": self.coils,
            "holding_registers": self.holding_registers,
            "error": self.last_error
        }

    async def poll_once(self):
        """Execute one read cycle (read-only, never writes)."""
        host = self.target["host"]
        port = self.target["port"]
        unit_id = self.target["unit_id"]

        coil_start = self.window.get("coil_start", 0)
        coil_count = self.window.get("coil_count", 0)
        holding_start = self.window.get("holding_start", 0)
        holding_count = self.window.get("holding_count", 0)

        try:
            # Connect if needed
            if self.client is None:
                self.client = ModbusTcpClient(host, port=port)
                if not self.client.connect():
                    raise ConnectionError(f"Failed to connect to {host}:{port}")
                self.connected = True
                self.last_error = None

            # Read coils if requested
            if coil_count > 0:
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.read_coils(address=coil_start, count=coil_count, device_id=unit_id)
                )
                if result.isError():
                    raise Exception(f"Read coils error: {result}")

                # Store as dict {addr: value} - use string keys for JSON compatibility
                self.coils = {str(coil_start + i): bool(val) for i, val in enumerate(result.bits[:coil_count])}

            # Read holding registers if requested
            if holding_count > 0:
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.read_holding_registers(address=holding_start, count=holding_count, device_id=unit_id)
                )
                if result.isError():
                    raise Exception(f"Read holding registers error: {result}")

                # Store as dict {addr: value} - use string keys for JSON compatibility
                self.holding_registers = {str(holding_start + i): int(val) for i, val in enumerate(result.registers[:holding_count])}

            self.last_updated = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            self.connected = True
            self.last_error = None

        except Exception as e:
            logger.warning(f"Monitor poll failed: {e}")
            self.connected = False
            self.last_error = str(e)
            # Close client to force reconnect next time
            if self.client:
                try:
                    self.client.close()
                except:
                    pass
                self.client = None

    async def run(self):
        """Main polling loop."""
        self.running = True
        logger.info(f"Monitor session started: {self.target['host']}:{self.target['port']}")

        while self.running:
            await self.poll_once()
            await asyncio.sleep(self.interval)

    async def stop(self):
        """Stop polling and cleanup."""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        if self.client:
            try:
                self.client.close()
            except:
                pass
            self.client = None

        logger.info("Monitor session stopped")


class MonitorService:
    """
    Service managing a single active Modbus monitoring session.

    Provides read-only polling of target Modbus state.
    """

    def __init__(self):
        self.session: Optional[MonitorSession] = None

    def has_session(self) -> bool:
        """Check if there's an active session."""
        return self.session is not None

    def get_state(self) -> Dict[str, Any]:
        """Get current state snapshot."""
        if not self.session:
            return {
                "connected": False,
                "last_updated": None,
                "target": None,
                "window": None,
                "coils": {},
                "holding_registers": {},
                "error": "No active monitoring session"
            }
        return self.session.get_state()

    async def start_session(self, target: Dict[str, Any], window: Dict[str, int], interval: float = 1.0) -> Dict[str, Any]:
        """
        Start a new monitoring session (replaces any existing session).

        Args:
            target: {host, port, unit_id}
            window: {coil_start, coil_count, holding_start, holding_count}
            interval: Polling interval in seconds

        Returns:
            Initial session state
        """
        # Stop any existing session
        if self.session:
            await self.stop_session()

        # Validate window using ModbusValidator
        coil_start = window.get("coil_start", 0)
        coil_count = window.get("coil_count", 0)
        holding_start = window.get("holding_start", 0)
        holding_count = window.get("holding_count", 0)

        if coil_count > 0:
            valid, msg = ModbusValidator.validate_read_operation(
                coil_start, coil_count, target["unit_id"], "read_coils"
            )
            if not valid:
                raise ValueError(f"Coil window validation failed: {msg}")

        if holding_count > 0:
            valid, msg = ModbusValidator.validate_read_operation(
                holding_start, holding_count, target["unit_id"], "read_holding_registers"
            )
            if not valid:
                raise ValueError(f"Holding register window validation failed: {msg}")

        # Create and start new session
        self.session = MonitorSession(target, window, interval)
        self.session.task = asyncio.create_task(self.session.run())

        # Wait a moment for first poll
        await asyncio.sleep(0.1)

        return self.session.get_state()

    async def stop_session(self):
        """Stop the active monitoring session."""
        if self.session:
            await self.session.stop()
            self.session = None

    async def stream_events(self):
        """
        Async generator yielding state updates for SSE.

        Yields dicts shaped as SSE kwargs: {"data": json_string}.
        EventSourceResponse will format them as SSE frames.
        """
        import json

        if not self.session:
            # Send error event
            yield {"data": json.dumps({"error": "No active session"})}
            return

        session = self.session
        last_state = None

        try:
            while session.running:
                current_state = session.get_state()

                # Only send if state changed
                if current_state != last_state:
                    # Yield SSE-shaped dict: {"data": json_string}
                    # This produces exactly one "data:" prefix with the JSON payload
                    yield {"data": json.dumps(current_state)}
                    last_state = current_state

                await asyncio.sleep(0.5)  # Check twice per poll interval
        except asyncio.CancelledError:
            logger.info("Monitor stream cancelled")
            raise


# Global service instance
monitor_service = MonitorService()

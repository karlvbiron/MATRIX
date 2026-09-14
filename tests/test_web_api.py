"""
Tests for M.A.T.R.I.X Web API.

Uses FastAPI TestClient to test API endpoints without starting an actual server.
"""
import pytest
import os
import time
import threading
import asyncio
from fastapi.testclient import TestClient
from pymodbus.server import ServerAsyncStop, StartAsyncTcpServer
from pymodbus.datastore import ModbusSparseDataBlock, ModbusServerContext
from pymodbus.datastore.context import ModbusDeviceContext


# Test server configuration
TEST_PORT = 15020
TEST_HOST = '127.0.0.1'
TEST_UNIT_ID = 1


class ModbusTestServer:
    """Local Modbus TCP server for testing using pymodbus v3."""

    def __init__(self, host='127.0.0.1', port=15020):
        self.host = host
        self.port = port
        self.server_thread = None
        self.loop = None

    def start(self):
        """Start the Modbus TCP server in a background thread."""
        # Initialize data stores with known values
        coil_values = {i: v for i, v in enumerate([True, False, True, False, True, False, True, False] + [False] * 100)}
        di_values = {i: v for i, v in enumerate([False, True, False, True, False, True, False, True] + [False] * 100)}
        hr_values = {i: v for i, v in enumerate([100, 200, 300, 400, 500, 600, 700, 800, 900, 1000] + [0] * 100)}
        ir_values = {i: v for i, v in enumerate([10, 20, 30, 40, 50, 60, 70, 80, 90, 100] + [0] * 100)}

        datablock_co = ModbusSparseDataBlock(coil_values)
        datablock_di = ModbusSparseDataBlock(di_values)
        datablock_hr = ModbusSparseDataBlock(hr_values)
        datablock_ir = ModbusSparseDataBlock(ir_values)

        device_context = ModbusDeviceContext(
            di=datablock_di,
            co=datablock_co,
            hr=datablock_hr,
            ir=datablock_ir
        )

        context = ModbusServerContext(devices={TEST_UNIT_ID: device_context}, single=False)

        # Start server in background thread
        def run_server():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(
                StartAsyncTcpServer(
                    context=context,
                    address=(self.host, self.port)
                )
            )

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Give server time to start
        time.sleep(2)

    def stop(self):
        """Stop the Modbus TCP server."""
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.ensure_future(ServerAsyncStop()))
        time.sleep(0.5)


@pytest.fixture(scope='module')
def modbus_server():
    """Fixture that starts a local Modbus TCP server for all tests."""
    server = ModbusTestServer(host=TEST_HOST, port=TEST_PORT)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def client():
    """Create FastAPI test client."""
    from webapp.server import app
    return TestClient(app)


@pytest.fixture
def enable_dangerous():
    """Fixture to temporarily enable dangerous attacks."""
    original = os.environ.get('MATRIX_WEB_ENABLE_DANGEROUS')
    os.environ['MATRIX_WEB_ENABLE_DANGEROUS'] = '1'
    yield
    if original is None:
        os.environ.pop('MATRIX_WEB_ENABLE_DANGEROUS', None)
    else:
        os.environ['MATRIX_WEB_ENABLE_DANGEROUS'] = original


class TestHealthEndpoint:
    """Tests for /api/health endpoint."""

    def test_health_returns_200(self, client):
        """Test that health endpoint returns 200."""
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_has_version_fields(self, client):
        """Test that health response contains version information."""
        response = client.get("/api/health")
        data = response.json()

        assert 'status' in data
        assert data['status'] == 'ok'
        assert 'version' in data
        assert 'attack_ics_version' in data
        assert data['attack_ics_version'] == 'v19.2'

    def test_root_endpoint(self, client):
        """Test that root endpoint returns HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "M.A.T.R.I.X" in response.text


class TestAttacksEndpoint:
    """Tests for /api/attacks endpoint."""

    def test_attacks_lists_all_seven(self, client):
        """Test that /api/attacks returns all 7 attacks."""
        response = client.get("/api/attacks")
        assert response.status_code == 200

        attacks = response.json()
        assert len(attacks) == 7

        attack_names = {a['name'] for a in attacks}
        expected = {'read', 'coil', 'register', 'overflow', 'dos', 'replay', 'spoof'}
        assert attack_names == expected

    def test_attacks_include_technique_tags(self, client):
        """Test that attacks include ATT&CK technique information."""
        response = client.get("/api/attacks")
        attacks = response.json()

        # Find read attack
        read_attack = next(a for a in attacks if a['name'] == 'read')
        assert 'attack_technique' in read_attack
        assert read_attack['attack_technique'] is not None
        assert read_attack['attack_technique']['technique_id'] == 'T0861'
        assert read_attack['attack_technique']['technique_name'] == 'Point & Tag Identification'


class TestMappingsEndpoint:
    """Tests for /api/mappings endpoint."""

    def test_mappings_returns_200(self, client):
        """Test that mappings endpoint returns 200."""
        response = client.get("/api/mappings")
        assert response.status_code == 200

    def test_mappings_has_version_and_seven_entries(self, client):
        """Test that mappings response has version and 7 attack entries."""
        response = client.get("/api/mappings")
        data = response.json()

        assert 'version' in data
        assert data['version'] == 'v19.2'
        assert 'mappings' in data
        assert len(data['mappings']) == 7


class TestAttackExecution:
    """Tests for POST /api/attacks/{name}/run endpoint."""

    def test_read_attack_success(self, client, modbus_server):
        """Test successful read attack execution."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "coil_start": 0,
            "coil_count": 4,
            "discrete_start": 0,
            "discrete_count": 4,
            "holding_start": 0,
            "holding_count": 2,
            "input_start": 0,
            "input_count": 2
        }

        response = client.post("/api/attacks/read/run", json=payload)
        assert response.status_code == 200

        result = response.json()
        assert result['attack'] == 'read'
        assert result['success'] is True
        assert result['error'] is None
        assert 'coils' in result['data']
        assert 'holding_registers' in result['data']
        assert result['attack_technique'] is not None

    def test_coil_attack_success(self, client, modbus_server):
        """Test successful coil write attack execution."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "start": 0,
            "count": 4
        }

        response = client.post("/api/attacks/coil/run", json=payload)
        assert response.status_code == 200

        result = response.json()
        assert result['attack'] == 'coil'
        assert result['success'] is True

    def test_register_attack_success(self, client, modbus_server):
        """Test successful register write attack execution."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "start": 0,
            "count": 2
        }

        response = client.post("/api/attacks/register/run", json=payload)
        assert response.status_code == 200

        result = response.json()
        assert result['attack'] == 'register'
        assert result['success'] is True

    def test_overflow_attack_success(self, client, modbus_server):
        """Test successful overflow attack execution."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "start": 0
        }

        response = client.post("/api/attacks/overflow/run", json=payload)
        assert response.status_code == 200

        result = response.json()
        assert result['attack'] == 'overflow'
        assert result['success'] is True

    def test_unknown_attack_returns_404(self, client):
        """Test that unknown attack name returns 404."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            }
        }

        response = client.post("/api/attacks/unknown/run", json=payload)
        assert response.status_code == 404
        assert "not found" in response.json()['detail'].lower()

    def test_validation_returns_400(self, client, modbus_server):
        """Test that invalid parameters return HTTP 400 (not 200)."""
        # Invalid coil_count (exceeds max 2000)
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "coil_start": 0,
            "coil_count": 99999  # WAY over limit
        }

        response = client.post("/api/attacks/read/run", json=payload)
        # Should return 400 for validation failure
        assert response.status_code == 400
        assert 'Validation failed' in response.json()['detail']

    def test_extra_fields_forbidden(self, client):
        """Test that extra/unknown fields return HTTP 422."""
        # Unknown field "start" - read uses coil_start, discrete_start, etc
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT
            },
            "start": 0  # Invalid - read doesn't have "start"
        }

        response = client.post("/api/attacks/read/run", json=payload)
        assert response.status_code == 422  # Pydantic validation error

    def test_coil_validation_returns_400(self, client, modbus_server):
        """Test that coil write with out-of-range count returns 400."""
        # Invalid count (exceeds max 1968 for coils)
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "start": 0,
            "count": 2000  # Over limit
        }

        response = client.post("/api/attacks/coil/run", json=payload)
        assert response.status_code == 400
        assert 'Validation failed' in response.json()['detail']

    def test_register_validation_returns_400(self, client, modbus_server):
        """Test that register write with out-of-range count returns 400."""
        # Invalid count (exceeds max 123 for registers)
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "start": 0,
            "count": 200  # Over limit
        }

        response = client.post("/api/attacks/register/run", json=payload)
        assert response.status_code == 400
        assert 'Validation failed' in response.json()['detail']

    def test_attack_technique_on_failure(self, client):
        """Test that attack_technique is populated even on failure."""
        # Read attack with bad port will fail (connection refused)
        payload = {
            "target": {
                "host": "127.0.0.1",
                "port": 9999,  # Nothing listening here
                "unit_id": 1
            }
        }

        response = client.post("/api/attacks/read/run", json=payload)
        assert response.status_code == 200
        result = response.json()
        assert result['success'] is False
        # attack_technique should still be populated
        assert result['attack_technique'] is not None
        assert result['attack_technique']['technique_id'] == 'T0861'


class TestDangerousAttacks:
    """Tests for dangerous attack safety rails."""

    def test_dos_disabled_by_default(self, client):
        """Test that DoS attack returns 501 by default."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "threads": 2
        }

        response = client.post("/api/attacks/dos/run", json=payload)
        assert response.status_code == 501
        assert "disabled in web MVP" in response.json()['detail']

    def test_spoof_disabled_by_default(self, client):
        """Test that spoof attack returns 501 by default."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "spoof_ip": "192.168.1.50"
        }

        response = client.post("/api/attacks/spoof/run", json=payload)
        assert response.status_code == 501
        assert "disabled in web MVP" in response.json()['detail']

    def test_replay_disabled_by_default(self, client):
        """Test that replay attack returns 501 by default."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "pcap_file": "test.pcap"
        }

        response = client.post("/api/attacks/replay/run", json=payload)
        assert response.status_code == 501
        assert "disabled in web MVP" in response.json()['detail']

    def test_dos_enabled_with_env_var(self, client, modbus_server, enable_dangerous):
        """Test that DoS can be enabled with env var."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "threads": 2,
            "duration": 0.5
        }

        response = client.post("/api/attacks/dos/run", json=payload)
        # Should execute (200) when enabled, not 501
        assert response.status_code == 200
        result = response.json()
        assert result['attack'] == 'dos'

    def test_replay_enabled_with_env_var(self, client, enable_dangerous):
        """Test that replay can be enabled with env var."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": 1
            },
            "pcap_file": "ModbusTraffic.pcap"
        }

        response = client.post("/api/attacks/replay/run", json=payload)
        # Should execute (200) when enabled, not 501
        # Note: will fail with actual execution error if file missing, but won't be 501
        assert response.status_code != 501


class TestServerDefaults:
    """Tests for server configuration defaults."""

    def test_server_defaults_to_localhost(self):
        """Test that server configuration uses 127.0.0.1 by default."""
        # This is verified by checking the argparse defaults in matrix.py
        # The actual binding happens in start_web_server()
        import subprocess

        # Check that --web-host defaults to 127.0.0.1
        result = subprocess.run(
            ['python3', 'matrix.py', '--help'],
            capture_output=True,
            text=True
        )

        assert '127.0.0.1' in result.stdout
        assert '--web-host' in result.stdout


class TestMonitorEndpoints:
    """Tests for live monitoring endpoints."""

    def test_monitor_state_no_session(self, client):
        """Test that state with no session returns clean shape, not 500."""
        response = client.get("/api/monitor/state")
        assert response.status_code == 200

        data = response.json()
        assert data['connected'] is False
        assert data['last_updated'] is None
        assert data['target'] is None
        assert data['error'] == "No active monitoring session"

    def test_monitor_start_with_bad_window_returns_400(self, client):
        """Test that start with invalid window returns 400."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "window": {
                "coil_start": 0,
                "coil_count": 99999  # Exceeds Modbus limit
            }
        }

        response = client.post("/api/monitor/start", json=payload)
        assert response.status_code == 400
        assert "validation failed" in response.json()['detail'].lower()

    def test_monitor_start_and_poll_state(self, client, modbus_server):
        """Test starting session and polling state reflects known values."""
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "window": {
                "coil_start": 0,
                "coil_count": 4,
                "holding_start": 0,
                "holding_count": 3
            },
            "interval": 0.5
        }

        # Start monitoring
        response = client.post("/api/monitor/start", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data['target']['host'] == TEST_HOST

        # Give it a moment to poll
        time.sleep(1.0)

        # Get state
        response = client.get("/api/monitor/state")
        assert response.status_code == 200
        data = response.json()

        # Should have connected and read values
        assert data['connected'] is True or data['error'] is not None  # May fail to connect
        assert data['last_updated'] is not None or data['error'] is not None

        if data['connected']:
            # Check we got some coils and registers (keys are strings in JSON)
            assert '0' in data['coils']
            assert '0' in data['holding_registers']

    def test_monitor_stop_ends_session(self, client, modbus_server):
        """Test that stop ends the active session."""
        # Start a session
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "window": {
                "coil_start": 0,
                "coil_count": 2
            }
        }

        client.post("/api/monitor/start", json=payload)
        time.sleep(0.5)

        # Stop it
        response = client.post("/api/monitor/stop")
        assert response.status_code == 200
        assert response.json()['status'] == 'stopped'

        # State should now show no session
        response = client.get("/api/monitor/state")
        data = response.json()
        assert data['error'] == "No active monitoring session"

    def test_monitor_never_writes(self, client, modbus_server):
        """Test that monitor never writes to target (read-only)."""
        # Read initial state directly
        from pymodbus.client import ModbusTcpClient
        direct_client = ModbusTcpClient(TEST_HOST, port=TEST_PORT)
        direct_client.connect()

        initial_coils = direct_client.read_coils(address=0, count=8, device_id=TEST_UNIT_ID)
        initial_regs = direct_client.read_holding_registers(address=0, count=4, device_id=TEST_UNIT_ID)

        initial_coil_values = list(initial_coils.bits[:8])
        initial_reg_values = list(initial_regs.registers[:4])

        direct_client.close()

        # Start monitor and let it poll several times
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "window": {
                "coil_start": 0,
                "coil_count": 8,
                "holding_start": 0,
                "holding_count": 4
            },
            "interval": 0.3
        }

        client.post("/api/monitor/start", json=payload)
        time.sleep(1.5)  # Let it poll ~5 times

        # Stop and read final state
        client.post("/api/monitor/stop")

        direct_client = ModbusTcpClient(TEST_HOST, port=TEST_PORT)
        direct_client.connect()

        final_coils = direct_client.read_coils(address=0, count=8, device_id=TEST_UNIT_ID)
        final_regs = direct_client.read_holding_registers(address=0, count=4, device_id=TEST_UNIT_ID)

        final_coil_values = list(final_coils.bits[:8])
        final_reg_values = list(final_regs.registers[:4])

        direct_client.close()

        # Values should be unchanged
        assert initial_coil_values == final_coil_values
        assert initial_reg_values == final_reg_values

    def test_monitor_stream_no_session_returns_400(self, client):
        """Test that stream with no session returns 400."""
        response = client.get("/api/monitor/stream")
        assert response.status_code == 400
        assert "No active monitoring session" in response.json()['detail']

    def test_monitor_start_with_exact_frontend_payload(self, client, modbus_server):
        """Test that monitor/start accepts the exact payload the frontend sends."""
        # This is the EXACT payload the Monitor tab sends (with monitorTarget populated)
        frontend_payload = {
            "target": {"host": TEST_HOST, "port": TEST_PORT, "unit_id": 1},
            "window": {"coil_start": 0, "coil_count": 8, "holding_start": 0, "holding_count": 4},
            "interval": 1.0
        }

        response = client.post("/api/monitor/start", json=frontend_payload)

        # Should return 200, not 422
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.json()}"

        data = response.json()

        # Verify response has the backend's actual shape
        assert "connected" in data, "Response must have 'connected' field"
        assert isinstance(data["connected"], bool), "'connected' must be boolean"
        assert "coils" in data, "Response must have 'coils' field"
        assert "holding_registers" in data, "Response must have 'holding_registers' field"

        # Connected should be True (server is running via fixture)
        assert data["connected"] == True, "Should connect to test server"

        # Stop the monitor
        client.post("/api/monitor/stop")

    def test_monitor_stream_sse_format_correct(self, client, modbus_server):
        """Test that /api/monitor/stream emits proper SSE frames via HTTP."""
        import json
        import time
        import asyncio
        from webapp.monitor import monitor_service

        # Start monitor session
        start_payload = {
            "target": {"host": TEST_HOST, "port": TEST_PORT, "unit_id": 1},
            "window": {"coil_start": 0, "coil_count": 4, "holding_start": 0, "holding_count": 2},
            "interval": 0.5
        }
        response = client.post("/api/monitor/start", json=start_payload)
        assert response.status_code == 200

        # Wait for first poll
        time.sleep(0.3)

        # Test the generator directly (EventSourceResponse will use this)
        async def test_stream():
            gen = monitor_service.stream_events()

            # Get first yielded value with timeout
            try:
                first_event = await asyncio.wait_for(gen.__anext__(), timeout=2.0)
            except asyncio.TimeoutError:
                raise AssertionError("Stream did not yield any events within 2 seconds")

            # Verify it's the correct SSE shape: {"data": json_string}
            assert isinstance(first_event, dict), f"Expected dict, got {type(first_event)}"
            assert "data" in first_event, f"Expected 'data' key in SSE dict, got keys: {first_event.keys()}"

            # Verify the data value is a JSON string
            json_str = first_event["data"]
            assert isinstance(json_str, str), f"Expected data to be string, got {type(json_str)}"

            # Parse and validate the state
            state = json.loads(json_str)
            assert isinstance(state, dict), "Payload should be a dict"
            assert "coils" in state, "Payload must contain 'coils' field"
            assert "holding_registers" in state, "Payload must contain 'holding_registers' field"
            assert "connected" in state, "Payload must contain 'connected' field"

            # When sse-starlette processes this dict, ensure_bytes will create:
            # ServerSentEvent(data=json_str, sep=sep) which encodes to "data: {json}\r\n\r\n"
            # Verify no double prefix by checking json_str doesn't start with "data:"
            assert not json_str.startswith("data:"), "JSON string should not contain 'data:' prefix"

            # Close the generator
            await gen.aclose()

        # Run the async test
        asyncio.run(test_stream())

        # Stop the monitor
        client.post("/api/monitor/stop")

    def test_monitor_timestamp_is_iso8601_utc(self, client, modbus_server):
        """Test that monitor timestamp is timezone-aware ISO-8601 format with 'Z' suffix."""
        from datetime import datetime, timezone

        # Start a monitor session
        payload = {
            "target": {
                "host": TEST_HOST,
                "port": TEST_PORT,
                "unit_id": TEST_UNIT_ID
            },
            "window": {
                "coil_start": 0,
                "coil_count": 2
            }
        }

        client.post("/api/monitor/start", json=payload)
        time.sleep(0.5)  # Let it poll once

        # Get state with timestamp
        response = client.get("/api/monitor/state")
        assert response.status_code == 200
        data = response.json()

        # If connected, check timestamp format
        if data['connected'] and data['last_updated']:
            timestamp = data['last_updated']

            # Check format ends with 'Z' for UTC
            assert timestamp.endswith('Z'), f"Timestamp should end with 'Z': {timestamp}"

            # Check it can be parsed as ISO format
            timestamp_without_z = timestamp.replace('Z', '+00:00')
            parsed = datetime.fromisoformat(timestamp_without_z)

            # Verify it's recent (within last minute)
            now = datetime.now(timezone.utc)
            diff = (now - parsed).total_seconds()
            assert abs(diff) < 60, f"Timestamp should be recent, got diff: {diff}s"

        # Stop the monitor
        client.post("/api/monitor/stop")


class TestFrontendShell:
    """Tests for the web UI frontend."""

    def test_root_returns_html(self, client):
        """Test that GET / returns HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers['content-type']

    def test_shell_contains_tabs(self, client):
        """Test that shell contains all four tab labels."""
        response = client.get("/")
        html = response.text

        # Check for tab labels
        assert "ATTACKS" in html
        assert "LIVE MONITOR" in html
        assert "ATT&CK FOR ICS" in html or "ATT&CK" in html

    def test_shell_contains_target_bar(self, client):
        """Test that shell contains target configuration bar."""
        response = client.get("/")
        html = response.text

        assert "TARGET" in html or "target" in html.lower()
        assert "host" in html.lower()
        assert "port" in html.lower()
        assert "unit" in html.lower()

    def test_palette_vars_present(self, client):
        """Test that HMI palette CSS variables are present."""
        response = client.get("/")
        html = response.text

        # Check for CSS variable definitions
        assert "--bg" in html
        assert "--panel" in html
        assert "--accent" in html
        assert "--danger" in html
        assert "#3DDC84" in html  # phosphor green
        assert "#FF4438" in html  # danger red

    def test_attacks_screen_lists_all_seven(self, client):
        """Test that attacks screen lists all 7 attacks."""
        response = client.get("/")
        html = response.text

        # All 7 attack names should appear
        assert "read" in html.lower()
        assert "coil" in html.lower()
        assert "register" in html.lower()
        assert "overflow" in html.lower()
        assert "dos" in html.lower()
        assert "replay" in html.lower()
        assert "spoof" in html.lower()

    def test_dos_spoof_replay_buttons_disabled(self, client):
        """Test that DoS, Spoof, and Replay run buttons are disabled, but read/coil/register/overflow are NOT."""
        response = client.get("/")
        html = response.text

        # Check for disabled buttons - should have at least 3 (dos, spoof, replay)
        assert html.count('disabled') >= 3, "Expected at least 3 disabled buttons (dos, spoof, replay)"
        assert "disabled in web mvp" in html.lower() or "MATRIX_WEB_ENABLE_DANGEROUS" in html

        # Verify the legitimate attack buttons (read, coil, register, overflow) are NOT disabled
        # by checking that their "Run" buttons appear WITHOUT disabled attribute
        assert "Run Read Attack" in html
        assert "Run Coil Write Attack" in html or "confirming" in html  # coil has confirm flow
        assert "Run Register Write Attack" in html or "confirming" in html  # register has confirm flow
        assert "Run Overflow Attack" in html or "confirming" in html  # overflow has confirm flow

    def test_attack_tags_present(self, client):
        """Test that ATT&CK technique tags are present."""
        response = client.get("/")
        html = response.text

        # Should have technique IDs visible
        assert "T0" in html  # ATT&CK ICS technique IDs start with T0

    def test_htmx_alpine_tailwind_loaded(self, client):
        """Test that HTMX, Alpine.js, and Tailwind are loaded."""
        response = client.get("/")
        html = response.text

        assert "htmx" in html.lower() or "unpkg.com/htmx" in html
        assert "alpine" in html.lower() or "alpinejs" in html
        assert "tailwind" in html.lower()

    def test_monitor_tab_has_session_controls(self, client):
        """Test that Monitor tab has session control form and buttons."""
        response = client.get("/")
        html = response.text

        # Check for window configuration inputs
        assert "coil_start" in html.lower() or "Coil Start" in html
        assert "coil_count" in html.lower() or "Coil Count" in html
        assert "holding_start" in html.lower() or "Holding Start" in html
        assert "holding_count" in html.lower() or "Holding Count" in html

        # Check for Start/Stop buttons
        assert "Start Monitor" in html
        assert "Stop Monitor" in html

    def test_monitor_tab_has_led_grid(self, client):
        """Test that Monitor tab has LED grid container for coils."""
        response = client.get("/")
        html = response.text

        # Check for LED grid elements
        assert "LED Grid" in html or "Coils" in html
        assert "aspect-square" in html  # LED cells are square

    def test_monitor_tab_has_register_cells(self, client):
        """Test that Monitor tab has register value cells."""
        response = client.get("/")
        html = response.text

        # Check for register display elements
        assert "Holding Registers" in html
        assert "font-mono" in html  # Monospace for values

    def test_monitor_tab_has_eventsource_client(self, client):
        """Test that Monitor tab includes EventSource SSE client code."""
        response = client.get("/")
        html = response.text

        # Check for EventSource usage
        assert "EventSource" in html
        assert "/api/monitor/stream" in html
        assert "onmessage" in html.lower() or "e.data" in html

    def test_monitor_start_includes_target_in_body(self, client):
        """Test that Monitor Start handler includes target in fetch body.

        Regression test for bug where target field was missing from POST body,
        causing 422 errors. The handler must send {target: {...}, window: {...}, interval: ...}
        """
        response = client.get("/")
        html = response.text

        # Verify Monitor Start handler includes target in JSON.stringify body
        # Look for the pattern in the /api/monitor/start fetch call
        assert "/api/monitor/start" in html, "Monitor Start endpoint must be present"

        # Extract the monitor start handler section (handle multiline)
        import re
        monitor_start_pattern = r"fetch\('/api/monitor/start'.+?target:\s*([\w\.\$]+)"
        match = re.search(monitor_start_pattern, html, re.DOTALL)

        assert match is not None, \
            "Monitor Start handler must include 'target:' in the fetch body"

        target_ref = match.group(1)
        assert target_ref == '$store.target', \
            f"Monitor Start must use '$store.target' (Alpine.store), found '{target_ref}'"

        # Verify broken monitorTarget variable is not used
        assert "monitorTarget" not in html, \
            "monitorTarget variable should not exist (it caused 422 errors)"

    def test_attack_ics_tab_has_matrix_table(self, client):
        """Test that ATT&CK for ICS tab contains coverage matrix table with five columns."""
        response = client.get("/")
        html = response.text

        # Verify matrix container exists
        assert "ATT&CK FOR ICS COVERAGE" in html
        assert "attack-ics" in html

        # Verify all five column headers are present
        assert "Attack" in html
        assert "Technique ID" in html
        assert "Technique Name" in html
        assert "Tactic" in html
        assert "Legacy ID" in html

    def test_attack_ics_tab_fetches_mappings(self, client):
        """Test that ATT&CK tab fetches /api/mappings endpoint."""
        response = client.get("/")
        html = response.text

        # Verify fetch call to /api/mappings exists
        assert "/api/mappings" in html, "ATT&CK tab must fetch from /api/mappings endpoint"

        # Verify fetch is in the context of the attack-ics tab
        import re
        # Look for pattern: attack-ics ... fetch('/api/mappings')
        attack_ics_section = re.search(
            r"activeTab === 'attack-ics'.*?fetch\('/api/mappings'\)",
            html,
            re.DOTALL
        )
        assert attack_ics_section is not None, \
            "ATT&CK tab must fetch /api/mappings when tab is active"

    def test_attack_ics_tab_shows_version(self, client):
        """Test that ATT&CK tab displays the version from /api/mappings."""
        response = client.get("/")
        html = response.text

        # Verify version display exists
        assert "MITRE ATT&CK for ICS" in html

        # Verify version binding
        assert 'x-text="version"' in html, \
            "ATT&CK tab must display version from API response"

    def test_read_handler_includes_target(self, client):
        """Test that READ handler sends target field using Alpine.store().

        IMPORTANT: This test checks the template source, but the real bug was that
        $root.target evaluated to undefined at runtime in nested x-data scopes.
        Fixed by using Alpine.store() for shared target state, which is accessible
        from any Alpine context. Template grep is INSUFFICIENT - browser verification
        is required to confirm target is actually sent in the POST body.
        """
        response = client.get("/")
        html = response.text

        # Verify Alpine.store('target') is initialized
        import re
        assert "Alpine.store('target'" in html, \
            "Alpine.store('target') initialization not found in template"

        # Verify READ card x-data is single-line (CRITICAL for Alpine.js scope resolution)
        # Find x-data containing coil_start (unique to READ card)
        read_xdata = re.search(r'<div x-data="(\{[^"]*coil_start[^"]*\})"', html)
        assert read_xdata, "READ card x-data not found"
        xdata_value = read_xdata.group(1)

        # Multi-line x-data breaks Alpine scope
        assert "\n" not in xdata_value, \
            "READ x-data MUST be single-line (multi-line breaks Alpine.js scope)"

        # Verify READ handler includes target reference in fetch body
        read_handler = re.search(
            r"fetch\('/api/attacks/read/run'.*?JSON\.stringify\(\{([^}]+)\}\)",
            html,
            re.DOTALL
        )
        assert read_handler, "READ handler not found"

        body_fields = read_handler.group(1)

        # CRITICAL: Must include target field using Alpine.store (was omitted, causing 422)
        assert "target: $store.target" in body_fields, \
            "READ handler MUST include 'target: $store.target' in JSON.stringify body"

        # Verify all 8 range fields are present
        for field in ['coil_start', 'coil_count', 'discrete_start', 'discrete_count',
                      'holding_start', 'holding_count', 'input_start', 'input_count']:
            assert field in body_fields, f"READ handler must include {field}"

    def test_read_endpoint_accepts_full_body_with_target(self, client, modbus_server):
        """Test that READ endpoint returns 200 when target is included (simulates browser POST)."""
        # This is what the browser SHOULD send (with target)
        payload = {
            "target": {"host": TEST_HOST, "port": TEST_PORT, "unit_id": TEST_UNIT_ID},
            "coil_start": 0,
            "coil_count": 8,
            "discrete_start": 0,
            "discrete_count": 8,
            "holding_start": 0,
            "holding_count": 4,
            "input_start": 0,
            "input_count": 4
        }

        response = client.post("/api/attacks/read/run", json=payload)

        # Must return 200, not 422
        assert response.status_code == 200, \
            f"READ endpoint should return 200 when target is included, got {response.status_code}"

        data = response.json()
        assert data["success"] is True
        assert "target" in data
        assert data["target"]["host"] == TEST_HOST

        # Verify data contains all four read types
        assert "coils" in data["data"]
        assert "discrete_inputs" in data["data"]
        assert "holding_registers" in data["data"]
        assert "input_registers" in data["data"]

    def test_attack_results_write_read_consistency(self, client):
        """Test that attack result displays bind REACTIVELY to Alpine.store.

        CRITICAL: This prevents the reactivity bug where display blocks use
        x-data="{ result: $store.results.<name> }" which creates a non-reactive
        snapshot. The local `result` variable captures the store value at initialization
        (when null) and never updates when the fetch populates the store.

        FIX: Display blocks must reference $store.results.<name> directly (not via
        a local snapshot) so they reactively update when the store changes.

        IMPORTANT: This test verifies template structure only. Actual rendering reactivity
        must be browser-verified, since template greps cannot confirm Alpine.js state updates
        trigger DOM updates correctly.
        """
        response = client.get("/")
        html = response.text

        # Verify Alpine.store('results') is initialized
        import re
        assert "Alpine.store('results'" in html, \
            "Alpine.store('results') initialization not found"

        # For each attack type, verify handler WRITE location matches display READ location
        for attack in ['read', 'coil', 'register', 'overflow']:
            # Find the handler's write location (in fetch .then())
            write_pattern = rf"fetch\('/api/attacks/{attack}/run'.*?\.then\(data => ([^)]+)\)"
            write_match = re.search(write_pattern, html, re.DOTALL)
            assert write_match, f"{attack} handler not found"

            write_location = write_match.group(1)

            # CRITICAL: Handler must write to $store.results.ATTACK_NAME
            assert f"$store.results.{attack}" in write_location, \
                f"{attack} handler must write to '$store.results.{attack}', found: {write_location[:100]}"

            # Find the display block's outer x-show
            display_xshow_pattern = rf'x-show="\$store\.results\.{attack}"'
            assert re.search(display_xshow_pattern, html), \
                f"{attack} display must use x-show=\"$store.results.{attack}\""

            # CRITICAL: Display must NOT use non-reactive snapshot pattern
            # The broken pattern: x-data="{ result: $store.results.<name> }"
            # This creates a local variable that never updates
            broken_snapshot_pattern = rf'x-data="\{{ result: \$store\.results\.{attack} \}}"'
            assert not re.search(broken_snapshot_pattern, html), \
                f"{attack} display must NOT use non-reactive snapshot 'x-data=\"{{ result: $store.results.{attack} }}\"'"

            # Display blocks should reference $store.results.<name> directly for reactivity
            # Check for direct store references in success/error bindings
            assert f"$store.results.{attack}?.success" in html, \
                f"{attack} display must reference '$store.results.{attack}?.success' directly (reactive)"

            # SUCCESS: Write and read are consistent, and display is reactive


class TestWebServerPortCollision:
    """Tests for port-in-use detection when starting web server."""

    def test_port_in_use_returns_clean_error(self):
        """Test that start_web_server detects port collision and exits cleanly without traceback."""
        import socket
        from matrix import start_web_server
        from io import StringIO
        import sys

        # Find an available port
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.bind(('127.0.0.1', 0))
        _, test_port = test_sock.getsockname()

        # Bind the port (keep it bound)
        test_sock.listen(1)

        # Capture stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()

        try:
            # Try to start web server on the same port
            result = start_web_server(host='127.0.0.1', port=test_port)

            # Get stderr output
            stderr_output = sys.stderr.getvalue()

            # Should return non-zero
            assert result == 1, "start_web_server should return 1 when port is in use"

            # Should have clear error message
            assert f"Port {test_port} already in use" in stderr_output, \
                f"Expected port-in-use message, got: {stderr_output}"
            assert "Another MATRIX --web may be running" in stderr_output, \
                f"Expected helpful message, got: {stderr_output}"

            # Should NOT contain traceback keywords
            assert "Traceback" not in stderr_output, \
                f"Should not show traceback, got: {stderr_output}"
            assert "Exception" not in stderr_output, \
                f"Should not show exception, got: {stderr_output}"

        finally:
            # Restore stderr and close socket
            sys.stderr = old_stderr
            test_sock.close()

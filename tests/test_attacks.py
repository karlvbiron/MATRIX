"""
Comprehensive test suite for M.A.T.R.I.X attack modules.

Tests all attack modules against a local Modbus TCP server running on a
non-privileged port, ensuring no root or Docker required.
"""
import pytest
import time
import threading
import sys
import asyncio
from pymodbus.server import ServerAsyncStop, StartAsyncTcpServer
from pymodbus.datastore import ModbusSparseDataBlock, ModbusServerContext
from pymodbus.datastore.context import ModbusDeviceContext


# Import attack modules
from attacks.modbus_unauthorized_read import ModbusUnauthorizedReader
from attacks.modbus_coil_write_attack import ModbusUnauthorizedCoilWriter
from attacks.modbus_holding_registers_write_attack import ModbusUnauthorizedHoldingRegisterWriter
from attacks.modbus_overflow_attack import ModbusOverflowAttacker
from attacks.attack_result import AttackResult


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
        # Initialize data stores with known values using sparse datablocks
        # Coils (0x): 0-7 = [True, False, True, False, True, False, True, False]
        # Discrete Inputs (1x): 0-7 = [False, True, False, True, False, True, False, True]
        # Holding Registers (4x): 0-9 = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
        # Input Registers (3x): 0-9 = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

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


class TestUnauthorizedRead:
    """Tests for unauthorized read attack module."""

    def test_read_returns_known_values(self, modbus_server):
        """Test that read attack returns the known preloaded values."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = reader.execute(
            coil_start=0, coil_count=8,
            discrete_start=0, discrete_count=8,
            holding_start=0, holding_count=4,
            input_start=0, input_count=4
        )

        assert result.success is True
        assert result.error is None
        assert 'coils' in result.data
        assert 'discrete_inputs' in result.data
        assert 'holding_registers' in result.data
        assert 'input_registers' in result.data

        # Verify known values
        assert result.data['coils'][0] is True
        assert result.data['coils'][1] is False
        assert result.data['discrete_inputs'][0] is False
        assert result.data['discrete_inputs'][1] is True
        assert result.data['holding_registers'][0] == 100
        assert result.data['holding_registers'][1] == 200
        assert result.data['input_registers'][0] == 10
        assert result.data['input_registers'][1] == 20

    def test_read_with_custom_start_count(self, modbus_server):
        """Test read attack with custom --start and --count parameters."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = reader.execute(
            holding_start=2, holding_count=3,
            coil_start=0, coil_count=8,
            discrete_start=0, discrete_count=8,
            input_start=0, input_count=4
        )

        assert result.success is True
        assert 'holding_registers' in result.data
        assert len(result.data['holding_registers']) == 3
        assert result.data['holding_registers'][2] == 300
        assert result.data['holding_registers'][3] == 400
        assert result.data['holding_registers'][4] == 500

    def test_read_validation_errors(self, modbus_server):
        """Test that validation errors are properly caught."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Test address out of range
        result = reader.execute(coil_start=65536, coil_count=8)
        assert result.success is False
        assert result.error is not None
        assert 'Validation failed' in result.error

        # Test count exceeds limit
        result = reader.execute(coil_start=0, coil_count=2001)
        assert result.success is False
        assert result.error is not None
        assert 'Validation failed' in result.error

    def test_backward_compatibility(self, modbus_server):
        """Test that default invocation targets original hardcoded values."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = reader.execute()  # All defaults

        assert result.success is True
        # Verify defaults match original hardcoded values
        assert len(result.data['coils']) == 8
        assert len(result.data['discrete_inputs']) == 8
        assert len(result.data['holding_registers']) == 4
        assert len(result.data['input_registers']) == 4

    def test_returns_attack_result(self, modbus_server):
        """Test that execute() returns a well-formed AttackResult."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = reader.execute()

        assert isinstance(result, AttackResult)
        assert result.attack == 'read'
        assert result.target['host'] == TEST_HOST
        assert result.target['port'] == TEST_PORT
        assert result.target['unit_id'] == TEST_UNIT_ID
        assert isinstance(result.params, dict)
        assert isinstance(result.success, bool)
        assert isinstance(result.timestamp, str)
        assert isinstance(result.data, dict)


class TestCoilWrite:
    """Tests for coil write attack module."""

    def test_coil_write_and_readback(self, modbus_server):
        """Test that coil write successfully flips coils and readback confirms."""
        writer = ModbusUnauthorizedCoilWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Write pattern: [True]*4 + [False]*4
        result = writer.execute(start=0, count=8)

        assert result.success is True
        assert result.data.get('write_success') is True
        assert 'coils' in result.data

        # Verify the written pattern
        assert result.data['coils'][0] is True
        assert result.data['coils'][1] is True
        assert result.data['coils'][2] is True
        assert result.data['coils'][3] is True
        assert result.data['coils'][4] is False
        assert result.data['coils'][5] is False
        assert result.data['coils'][6] is False
        assert result.data['coils'][7] is False

    def test_coil_write_specific_window(self, modbus_server):
        """Test coil write with specific start and count."""
        writer = ModbusUnauthorizedCoilWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Write to coils 10-13
        values = [True, True, False, False]
        result = writer.execute(start=10, count=4, values=values)

        assert result.success is True
        assert 'coils' in result.data
        assert len(result.data['coils']) == 4

    def test_coil_write_validation(self, modbus_server):
        """Test validation for coil write parameters."""
        writer = ModbusUnauthorizedCoilWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Test count exceeds limit (max 1968 coils)
        result = writer.execute(start=0, count=1969)
        assert result.success is False
        assert 'Validation failed' in result.error


class TestRegisterWrite:
    """Tests for holding register write attack module."""

    def test_register_write_and_readback(self, modbus_server):
        """Test that register write sets values and readback confirms."""
        writer = ModbusUnauthorizedHoldingRegisterWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        result = writer.execute(start=0, count=4)

        assert result.success is True
        assert result.data.get('write_success') is True
        assert 'registers' in result.data

        # Verify default pattern: [0x0000]*2 + [0xFFFF]*2
        assert result.data['registers'][0] == 0x0000
        assert result.data['registers'][1] == 0x0000
        assert result.data['registers'][2] == 0xFFFF
        assert result.data['registers'][3] == 0xFFFF

    def test_register_write_specific_window(self, modbus_server):
        """Test register write with specific start and count."""
        writer = ModbusUnauthorizedHoldingRegisterWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        values = [1111, 2222, 3333]
        result = writer.execute(start=5, count=3, values=values)

        assert result.success is True
        assert 'registers' in result.data
        assert result.data['registers'][5] == 1111
        assert result.data['registers'][6] == 2222
        assert result.data['registers'][7] == 3333

    def test_register_write_validation(self, modbus_server):
        """Test validation for register write parameters."""
        writer = ModbusUnauthorizedHoldingRegisterWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Test count exceeds limit (max 123 registers)
        result = writer.execute(start=0, count=124)
        assert result.success is False
        assert 'Validation failed' in result.error


class TestOverflowAttack:
    """Tests for overflow attack module."""

    def test_overflow_rejects_out_of_range(self, modbus_server):
        """Test that overflow gracefully handles out-of-range values."""
        attacker = ModbusOverflowAttacker(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Test with values 65536 and -1
        result = attacker.execute(start=0, test_values=[65536, -1])

        assert result.success is True
        assert 'tests' in result.data
        assert len(result.data['tests']) == 2

        # The values should be handled (wrapped or rejected by pymodbus)
        # We just verify the attack doesn't crash
        for test in result.data['tests']:
            assert 'value' in test
            assert 'address' in test

    def test_overflow_validation(self, modbus_server):
        """Test validation for overflow attack parameters."""
        attacker = ModbusOverflowAttacker(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Test invalid address
        result = attacker.execute(start=65536)
        assert result.success is False
        assert 'Validation failed' in result.error


class TestValidation:
    """Tests for parameter validation."""

    def test_unit_id_validation(self, modbus_server):
        """Test that invalid unit IDs are rejected."""
        # Unit ID out of range (0-255)
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=256)
        result = reader.execute()

        assert result.success is False
        assert 'Validation failed' in result.error

    def test_address_range_validation(self, modbus_server):
        """Test that address range validation works."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)

        # Address + count exceeds max address
        result = reader.execute(holding_start=65535, holding_count=2)
        assert result.success is False
        assert 'Validation failed' in result.error


class TestDoSAttack:
    """Tests for DoS attack module."""

    def test_dos_attack_returns_result(self, modbus_server):
        """Test that DoS attack returns well-formed AttackResult with tiny bounds."""
        from attacks.modbus_dos_attack import ModbusDoSAttacker

        # Use minimal threads and short duration for smoke test
        attacker = ModbusDoSAttacker(host=TEST_HOST, port=TEST_PORT, thread_count=2)
        result = attacker.execute(duration=1.0)

        assert isinstance(result, AttackResult)
        assert result.attack == 'dos'
        assert result.target['host'] == TEST_HOST
        assert result.target['port'] == TEST_PORT
        assert result.success is True
        assert 'thread_count' in result.data
        assert 'duration_seconds' in result.data
        assert 'total_requests' in result.data
        assert result.data['thread_count'] == 2


class TestReplayAttack:
    """Tests for replay attack module."""

    @pytest.fixture
    def synthetic_pcap(self, tmp_path):
        """Generate a small synthetic PCAP with Modbus packets."""
        from scapy.all import wrpcap, Ether, IP, TCP, Raw
        import struct

        pcap_file = tmp_path / "test_modbus.pcap"

        # Create a simple Modbus request packet (read holding registers)
        # Modbus TCP header: transaction_id=1, protocol=0, length=6, unit_id=1
        # Modbus PDU: function_code=3 (read holding), start_addr=0, count=4
        modbus_request = struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, 0, 4)

        packet = (
            Ether() /
            IP(src='192.168.1.100', dst=TEST_HOST) /
            TCP(sport=50000, dport=TEST_PORT) /
            Raw(load=modbus_request)
        )

        wrpcap(str(pcap_file), [packet, packet])  # Write 2 packets
        return str(pcap_file)

    def test_replay_attack_returns_result(self, modbus_server, synthetic_pcap):
        """Test that replay attack returns well-formed AttackResult."""
        from attacks.modbus_replay_attack import ModbusReplyAttacker

        attacker = ModbusReplyAttacker(target_ip=TEST_HOST, target_port=TEST_PORT)
        result = attacker.execute(pcap_file=synthetic_pcap)

        assert isinstance(result, AttackResult)
        assert result.attack == 'replay'
        assert result.target['host'] == TEST_HOST
        assert result.target['port'] == TEST_PORT
        assert result.success is True
        assert 'pcap_file' in result.data
        assert 'total_packets_in_pcap' in result.data
        assert 'packets_replayed' in result.data
        assert result.data['pcap_file'] == synthetic_pcap

    def test_replay_missing_pcap(self, modbus_server):
        """Test that replay handles missing PCAP file gracefully."""
        from attacks.modbus_replay_attack import ModbusReplyAttacker

        attacker = ModbusReplyAttacker(target_ip=TEST_HOST, target_port=TEST_PORT)
        result = attacker.execute(pcap_file="/nonexistent/file.pcap")

        assert result.success is False
        assert 'not found' in result.error.lower()


class TestSpoofAttack:
    """Tests for spoof attack module."""

    def test_spoof_no_privileges(self):
        """Test that spoof returns error without root privileges."""
        from attacks.modbus_spoof_response import ModbusResponseSpoofer
        import os

        # Only run if not root
        try:
            if os.geteuid() == 0:
                pytest.skip("Running as root, cannot test no-privilege path")
        except AttributeError:
            pytest.skip("os.geteuid() not available on this platform")

        spoofer = ModbusResponseSpoofer(
            target_ip=TEST_HOST,
            target_port=TEST_PORT,
            spoof_ip='192.168.1.50'
        )
        result = spoofer.execute()

        assert isinstance(result, AttackResult)
        assert result.attack == 'spoof'
        assert result.success is False
        assert 'root' in result.error.lower() or 'privilege' in result.error.lower()

    def test_spoof_object_construction(self):
        """Test that spoof attack object can be constructed."""
        from attacks.modbus_spoof_response import ModbusResponseSpoofer

        spoofer = ModbusResponseSpoofer(
            target_ip=TEST_HOST,
            target_port=TEST_PORT,
            spoof_ip='192.168.1.50'
        )

        assert spoofer.target_ip == TEST_HOST
        assert spoofer.target_port == TEST_PORT
        assert spoofer.spoof_ip == '192.168.1.50'
        assert spoofer.interface == 'docker0'


class TestTimestampFormat:
    """Tests for timezone-aware timestamp format."""

    def test_timestamp_is_iso8601_utc(self):
        """Test that AttackResult timestamp is timezone-aware and ISO-8601 format."""
        from attacks.attack_result import AttackResult
        from datetime import datetime

        result = AttackResult.create('test', 'localhost', 502)

        # Check format ends with 'Z' for UTC
        assert result.timestamp.endswith('Z')

        # Check it can be parsed as ISO format
        timestamp_without_z = result.timestamp.replace('Z', '+00:00')
        parsed = datetime.fromisoformat(timestamp_without_z)

        # Verify it's recent (within last minute)
        from datetime import timezone
        now = datetime.now(timezone.utc)
        diff = (now - parsed).total_seconds()
        assert abs(diff) < 60  # Within 1 minute


class TestMITREATTACKMappings:
    """Tests for MITRE ATT&CK for ICS mapping coverage."""

    def test_all_attacks_have_mappings(self):
        """Test that all seven attacks have mapping entries."""
        from attacks.attack_mapping import ATTACK_TECHNIQUE_MAPPING

        expected_attacks = ['read', 'coil', 'register', 'overflow', 'dos', 'replay', 'spoof']

        for attack in expected_attacks:
            assert attack in ATTACK_TECHNIQUE_MAPPING, f"Attack '{attack}' missing from mapping"
            assert len(ATTACK_TECHNIQUE_MAPPING[attack]) > 0, f"Attack '{attack}' has empty mapping"

    def test_mapping_fields_are_valid(self):
        """Test that each mapping contains non-empty technique_id, technique_name, tactic."""
        from attacks.attack_mapping import ATTACK_TECHNIQUE_MAPPING

        for attack_name, techniques in ATTACK_TECHNIQUE_MAPPING.items():
            for technique in techniques:
                assert 'technique_id' in technique, f"Missing technique_id for {attack_name}"
                assert 'technique_name' in technique, f"Missing technique_name for {attack_name}"
                assert 'tactic' in technique, f"Missing tactic for {attack_name}"

                assert technique['technique_id'], f"Empty technique_id for {attack_name}"
                assert technique['technique_name'], f"Empty technique_name for {attack_name}"
                assert technique['tactic'], f"Empty tactic for {attack_name}"

                # Verify technique_id format (should start with T followed by digits)
                assert technique['technique_id'].startswith('T'), f"Invalid technique_id format for {attack_name}"

    def test_attack_ics_version_present(self):
        """Test that ATTACK_ICS_VERSION is present and non-empty."""
        from attacks.attack_mapping import ATTACK_ICS_VERSION

        assert ATTACK_ICS_VERSION is not None
        assert isinstance(ATTACK_ICS_VERSION, str)
        assert len(ATTACK_ICS_VERSION) > 0
        assert ATTACK_ICS_VERSION == 'v19.2'

    def test_read_attack_has_technique(self, modbus_server):
        """Test that read attack result carries the expected attack_technique."""
        reader = ModbusUnauthorizedReader(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = reader.execute()

        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T0861'
        assert result.attack_technique['technique_name'] == 'Point & Tag Identification'

    def test_coil_attack_has_technique(self, modbus_server):
        """Test that coil write attack result carries the expected attack_technique."""
        writer = ModbusUnauthorizedCoilWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = writer.execute(start=0, count=8)

        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T1692.001'
        assert result.attack_technique['technique_name'] == 'Command Message'

    def test_register_attack_has_technique(self, modbus_server):
        """Test that register write attack result carries the expected attack_technique."""
        writer = ModbusUnauthorizedHoldingRegisterWriter(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = writer.execute(start=0, count=4)

        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T0836'
        assert result.attack_technique['technique_name'] == 'Modify Parameter'

    def test_overflow_attack_has_technique(self, modbus_server):
        """Test that overflow attack result carries the expected attack_technique."""
        attacker = ModbusOverflowAttacker(host=TEST_HOST, port=TEST_PORT, unit_id=TEST_UNIT_ID)
        result = attacker.execute(start=0)

        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T0814'
        assert result.attack_technique['technique_name'] == 'Denial of Service'

    def test_dos_attack_has_technique(self, modbus_server):
        """Test that DoS attack result carries the expected attack_technique."""
        from attacks.modbus_dos_attack import ModbusDoSAttacker

        attacker = ModbusDoSAttacker(host=TEST_HOST, port=TEST_PORT, thread_count=2)
        result = attacker.execute(duration=0.5)

        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T0814'
        assert result.attack_technique['technique_name'] == 'Denial of Service'

    def test_replay_attack_has_technique(self, modbus_server):
        """Test that replay attack result carries the expected attack_technique."""
        from attacks.modbus_replay_attack import ModbusReplyAttacker

        attacker = ModbusReplyAttacker(target_ip=TEST_HOST, target_port=TEST_PORT)
        result = attacker.execute(pcap_file="/nonexistent/file.pcap")

        # Even failed attacks should have technique populated
        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T1692.001'

    def test_spoof_attack_has_technique(self):
        """Test that spoof attack result carries the expected attack_technique."""
        from attacks.modbus_spoof_response import ModbusResponseSpoofer

        spoofer = ModbusResponseSpoofer(
            target_ip=TEST_HOST,
            target_port=TEST_PORT,
            spoof_ip='192.168.1.50'
        )
        result = spoofer.execute()

        # Even failed attacks should have technique populated
        assert result.attack_technique is not None
        assert 'technique_id' in result.attack_technique
        assert result.attack_technique['technique_id'] == 'T1692.002'
        assert result.attack_technique['technique_name'] == 'Reporting Message'


class TestListMappingsCLI:
    """Tests for --list-mappings CLI command."""

    def test_list_mappings_exits_0(self):
        """Test that --list-mappings exits with code 0."""
        import subprocess

        result = subprocess.run(
            ['python3', 'matrix.py', '--list-mappings'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0

    def test_list_mappings_contains_all_attacks(self):
        """Test that --list-mappings output contains all seven attack names."""
        import subprocess

        result = subprocess.run(
            ['python3', 'matrix.py', '--list-mappings'],
            capture_output=True,
            text=True
        )

        expected_attacks = ['read', 'coil', 'register', 'overflow', 'dos', 'replay', 'spoof']

        for attack in expected_attacks:
            assert attack in result.stdout, f"Attack '{attack}' not found in --list-mappings output"

    def test_list_mappings_json_format(self):
        """Test that --list-mappings --output json produces valid, clean JSON on stdout."""
        import subprocess
        import json

        result = subprocess.run(
            ['python3', 'matrix.py', '--list-mappings', '--output', 'json'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0

        # Parse JSON directly from stdout - must be clean with no banner/logging
        data = json.loads(result.stdout)

        # Verify structure
        assert 'version' in data, "Missing 'version' field in JSON output"
        assert data['version'] == 'v19.2'
        assert 'mappings' in data
        assert len(data['mappings']) == 7

        # Verify all attacks present
        attack_names = {m['attack'] for m in data['mappings']}
        expected = {'read', 'coil', 'register', 'overflow', 'dos', 'replay', 'spoof'}
        assert attack_names == expected

        # Verify all required fields present in each mapping
        for mapping in data['mappings']:
            assert 'attack' in mapping
            assert 'technique_id' in mapping
            assert 'technique_name' in mapping
            assert 'tactic' in mapping
            assert 'legacy_id' in mapping

    def test_list_mappings_json_pipes_through_python(self):
        """Test that JSON output can be piped through python json.load."""
        import subprocess

        # This is the actual command from the requirements
        cmd = 'python3 matrix.py --list-mappings --output json | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[\\"version\\"])"'

        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert result.stdout.strip() == 'v19.2', f"Expected 'v19.2', got: {result.stdout.strip()}"

    def test_legacy_id_values(self):
        """Test that legacy_id values are correct: only coil, replay, spoof have them."""
        from attacks.attack_mapping import ATTACK_TECHNIQUE_MAPPING

        # Attacks that should have legacy_id = None
        no_legacy = ['read', 'register', 'overflow', 'dos']
        for attack in no_legacy:
            techniques = ATTACK_TECHNIQUE_MAPPING[attack]
            for tech in techniques:
                assert tech['legacy_id'] is None, f"{attack} should have legacy_id=None, got {tech['legacy_id']}"

        # Attacks that should have specific legacy IDs
        assert ATTACK_TECHNIQUE_MAPPING['coil'][0]['legacy_id'] == 'T0855'
        assert ATTACK_TECHNIQUE_MAPPING['replay'][0]['legacy_id'] == 'T0855'
        assert ATTACK_TECHNIQUE_MAPPING['spoof'][0]['legacy_id'] == 'T0856'

    def test_list_mappings_no_network_activity(self):
        """Test that --list-mappings runs without target host required."""
        import subprocess

        # Should work without -H or -p flags
        result = subprocess.run(
            ['python3', 'matrix.py', '--list-mappings'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        # Should not contain error about missing target
        assert 'required' not in result.stderr.lower()

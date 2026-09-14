"""
Console output formatter for M.A.T.R.I.X attack results.

This module handles all console presentation of attack results, preserving the
original output format while separating presentation from business logic.
"""
import logging
from typing import Any, Dict, List
from .attack_result import AttackResult
from .attack_mapping import format_technique_tag

logger = logging.getLogger(__name__)


class AttackFormatter:
    """Formats AttackResult objects for console output."""

    @staticmethod
    def format_read_result(result: AttackResult) -> None:
        """
        Format and print the result of a read attack.

        Args:
            result: AttackResult from an unauthorized read operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        logger.info("\nStarting comprehensive Modbus read operation...")

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        # Format coil status
        if 'coils' in result.data:
            logger.info("Coil Status:")
            for addr, value in result.data['coils'].items():
                status = "ON" if value else "OFF"
                logger.info(f"  Coil {addr}: {status}")

        # Format discrete inputs
        if 'discrete_inputs' in result.data:
            logger.info("Discrete Input Status:")
            for addr, value in result.data['discrete_inputs'].items():
                status = "ON" if value else "OFF"
                logger.info(f"  Input {addr}: {status}")

        # Format holding registers
        if 'holding_registers' in result.data:
            logger.info("Holding Register Values:")
            for addr, value in result.data['holding_registers'].items():
                logger.info(f"  Register {addr}: {value} (0x{value:04X})")

        # Format input registers
        if 'input_registers' in result.data:
            logger.info("Input Register Values:")
            for addr, value in result.data['input_registers'].items():
                logger.info(f"  Register {addr}: {value} (0x{value:04X})")

    @staticmethod
    def format_coil_write_result(result: AttackResult) -> None:
        """
        Format and print the result of a coil write attack.

        Args:
            result: AttackResult from a coil write operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        logger.info("\nWriting values to Modbus server...")

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        if result.data.get('write_success'):
            logger.info("Successfully wrote coil values.")
        else:
            logger.error("Failed to write coil values.")

        logger.info("\nReading values back...")
        logger.info("Coil Status:")

        if 'coils' in result.data:
            for addr, value in result.data['coils'].items():
                status = "ON" if value else "OFF"
                logger.info(f"  Coil {addr}: {status}")

    @staticmethod
    def format_register_write_result(result: AttackResult) -> None:
        """
        Format and print the result of a holding register write attack.

        Args:
            result: AttackResult from a register write operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        logger.info("\nWriting values to Modbus server...")

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        if result.data.get('write_success'):
            logger.info("Successfully wrote holding register values.")
        else:
            logger.error("Failed to write holding register values.")

        logger.info("\nReading values back...")
        logger.info("Holding Register Values:")

        if 'registers' in result.data:
            for addr, value in result.data['registers'].items():
                logger.info(f"  Register {addr}: {value} (0x{value:04X})")

    @staticmethod
    def format_overflow_result(result: AttackResult) -> None:
        """
        Format and print the result of an overflow attack.

        Args:
            result: AttackResult from an overflow attack operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        logger.info("\nStarting Register Overflow Attack simulation...")

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        for test in result.data.get('tests', []):
            logger.info(f"\nTest Case: {test['description']}")
            logger.info(f"\nAttempting overflow attack on register {test['address']}")
            logger.info(f"Attempting to write value: {test['value']} (0x{test['value']:04X})")

            if test.get('initial_value') is not None:
                logger.info(f"Initial register value: {test['initial_value']} (0x{test['initial_value']:04X})")

            if test.get('write_success'):
                logger.info("Write operation succeeded")

                if test.get('new_value') is not None:
                    logger.info(f"New register value: {test['new_value']} (0x{test['new_value']:04X})")

                    if test.get('overflow_detected'):
                        logger.info("Overflow detected! Value wrapped around")
            else:
                logger.error("Write operation failed")

        logger.info("\nOverflow attack simulation completed")

    @staticmethod
    def format_dos_result(result: AttackResult) -> None:
        """
        Format and print the result of a DoS attack.

        Args:
            result: AttackResult from a DoS operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        logger.info(f"\nStarting DoS attack against {result.target['host']}:{result.target['port']} " +
                   f"with {result.data.get('thread_count', 0)} threads")

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        # Show attack metrics
        duration = result.data.get('duration_seconds', 0)
        total_requests = result.data.get('total_requests', 0)
        rps = result.data.get('requests_per_second', 0)

        logger.info(f"DoS attack running with {result.data.get('threads_started', 0)} threads. Press Ctrl+C to stop.")
        logger.info("Stopping DoS attack...")
        logger.info(f"Attack Duration: {duration:.2f} seconds")
        logger.info(f"Total Requests: {total_requests}")
        logger.info(f"Requests/sec: {rps:.2f}")
        logger.info("DoS attack stopped")

    @staticmethod
    def format_replay_result(result: AttackResult) -> None:
        """
        Format and print the result of a replay attack.

        Args:
            result: AttackResult from a replay operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        pcap_file = result.data.get('pcap_file', 'unknown')
        total_packets = result.data.get('total_packets_in_pcap', 0)
        replayed = result.data.get('packets_replayed', 0)
        success_rate = result.data.get('success_rate', 0)

        logger.info(f"Loading packets from {pcap_file}")
        logger.info(f"Loaded {total_packets} packets")
        logger.info(f"Found {total_packets} Modbus request packets")
        logger.info("\nAnalyzing Modbus request packets:")
        for i in range(total_packets):
            logger.info(f"Packet {i+1}:")
            logger.info("  Direction: Request")
        logger.info("\nReplaying Modbus request packets:")
        logger.info(f"Successfully replayed {replayed} out of {total_packets} packets")
        logger.info(f"Success rate: {success_rate*100:.1f}%")
        logger.info("\nReplay attack completed")

    @staticmethod
    def format_spoof_result(result: AttackResult) -> None:
        """
        Format and print the result of a spoof attack.

        Args:
            result: AttackResult from a spoof operation
        """
        if not result.success:
            logger.error(f"Attack failed: {result.error}")
            return

        logger.info("\nStarting Modbus Response Spoofing Attack simulation...")

        # Print ATT&CK for ICS technique tag
        if result.attack_technique:
            techniques = [result.attack_technique] if isinstance(result.attack_technique, dict) and 'technique_id' in result.attack_technique else result.attack_technique.get('techniques', [])
            logger.info(f"\033[1;94mATT&CK for ICS: {format_technique_tag(techniques)}\033[0m")

        total = result.data.get('test_cases_total', 0)
        sent = result.data.get('packets_sent', 0)
        failed = result.data.get('packets_failed', 0)

        for i in range(total):
            logger.info(f"\nTest Case {i+1}:")
            logger.info(f"\nCrafting spoofed Modbus response:")
            logger.info(f"Source IP: {result.params.get('spoof_ip', 'unknown')}")
            logger.info(f"Target IP: {result.target.get('host', 'unknown')}")
            logger.info(f"Target Port: {result.target.get('port', 'unknown')}")
            logger.info("Spoofed response sent successfully")

        logger.info(f"\nSent {sent} packets, {failed} failed")
        logger.info("\nSpoofing attack simulation completed")

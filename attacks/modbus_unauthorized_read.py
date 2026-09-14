from pymodbus.client import ModbusTcpClient
import time
import logging
from .attack_result import AttackResult
from .validation import ModbusValidator
from .attack_mapping import get_attack_techniques

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

class ModbusUnauthorizedReader:
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

    def read_coils(self, start_addr=0, count=8, log_output=True):
        """Read coil status (binary outputs)"""
        try:
            result = self.client.read_coils(address=start_addr, count=count, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info(f"Coil Status:")
                    for i, value in enumerate(result.bits[:count]):
                        status = "ON" if value else "OFF"
                        logger.info(f"  Coil {start_addr + i}: {status}")
                return result.bits[:count]
            return None
        except Exception as e:
            logger.error(f"Failed to read coils: {e}")
            return None

    def read_discrete_inputs(self, start_addr=0, count=8, log_output=True):
        """Read discrete input status (binary inputs)"""
        try:
            result = self.client.read_discrete_inputs(address=start_addr, count=count, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info(f"Discrete Input Status:")
                    for i, value in enumerate(result.bits[:count]):
                        status = "ON" if value else "OFF"
                        logger.info(f"  Input {start_addr + i}: {status}")
                return result.bits[:count]
            return None
        except Exception as e:
            logger.error(f"Failed to read discrete inputs: {e}")
            return None

    def read_holding_registers(self, start_addr=0, count=4, log_output=True):
        """Read holding registers (analog outputs)"""
        try:
            result = self.client.read_holding_registers(address=start_addr, count=count, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info(f"Holding Register Values:")
                    for i, value in enumerate(result.registers):
                        logger.info(f"  Register {start_addr + i}: {value} (0x{value:04X})")
                return result.registers
            return None
        except Exception as e:
            logger.error(f"Failed to read holding registers: {e}")
            return None

    def read_input_registers(self, start_addr=0, count=4, log_output=True):
        """Read input registers (analog inputs)"""
        try:
            result = self.client.read_input_registers(address=start_addr, count=count, device_id=self.unit_id)
            if not result.isError():
                if log_output:
                    logger.info(f"Input Register Values:")
                    for i, value in enumerate(result.registers):
                        logger.info(f"  Register {start_addr + i}: {value} (0x{value:04X})")
                return result.registers
            return None
        except Exception as e:
            logger.error(f"Failed to read input registers: {e}")
            return None

    def execute(self, coil_start=0, coil_count=8, discrete_start=0, discrete_count=8,
                holding_start=0, holding_count=4, input_start=0, input_count=4):
        """
        Execute unauthorized read attack and return structured result.

        Args:
            coil_start: Starting address for coil read (default: 0)
            coil_count: Number of coils to read (default: 8)
            discrete_start: Starting address for discrete input read (default: 0)
            discrete_count: Number of discrete inputs to read (default: 8)
            holding_start: Starting address for holding register read (default: 0)
            holding_count: Number of holding registers to read (default: 4)
            input_start: Starting address for input register read (default: 0)
            input_count: Number of input registers to read (default: 4)

        Returns:
            AttackResult with read data or error information
        """
        # Validate all parameters
        validations = [
            ModbusValidator.validate_read_operation(coil_start, coil_count, self.unit_id, 'read_coils'),
            ModbusValidator.validate_read_operation(discrete_start, discrete_count, self.unit_id, 'read_discrete_inputs'),
            ModbusValidator.validate_read_operation(holding_start, holding_count, self.unit_id, 'read_holding_registers'),
            ModbusValidator.validate_read_operation(input_start, input_count, self.unit_id, 'read_input_registers'),
        ]

        for valid, msg in validations:
            if not valid:
                return AttackResult(
                    attack='read',
                    target={'host': self.host, 'port': self.port, 'unit_id': self.unit_id},
                    params={
                        'coil_start': coil_start, 'coil_count': coil_count,
                        'discrete_start': discrete_start, 'discrete_count': discrete_count,
                        'holding_start': holding_start, 'holding_count': holding_count,
                        'input_start': input_start, 'input_count': input_count
                    },
                    success=False,
                    timestamp=AttackResult.create('read', self.host, self.port, self.unit_id).timestamp,
                    error=f"Validation failed: {msg}"
                )

        result = AttackResult.create(
            'read', self.host, self.port, self.unit_id,
            params={
                'coil_start': coil_start, 'coil_count': coil_count,
                'discrete_start': discrete_start, 'discrete_count': discrete_count,
                'holding_start': holding_start, 'holding_count': holding_count,
                'input_start': input_start, 'input_count': input_count
            }
        )

        try:
            if not self.connect():
                result.error = "Failed to connect to Modbus server"
                return result

            # Read coils
            coils = self.read_coils(coil_start, coil_count, log_output=False)
            if coils is not None:
                result.data['coils'] = {coil_start + i: val for i, val in enumerate(coils)}
            time.sleep(0.5)

            # Read discrete inputs
            discrete = self.read_discrete_inputs(discrete_start, discrete_count, log_output=False)
            if discrete is not None:
                result.data['discrete_inputs'] = {discrete_start + i: val for i, val in enumerate(discrete)}
            time.sleep(0.5)

            # Read holding registers
            holding = self.read_holding_registers(holding_start, holding_count, log_output=False)
            if holding is not None:
                result.data['holding_registers'] = {holding_start + i: val for i, val in enumerate(holding)}
            time.sleep(0.5)

            # Read input registers
            inputs = self.read_input_registers(input_start, input_count, log_output=False)
            if inputs is not None:
                result.data['input_registers'] = {input_start + i: val for i, val in enumerate(inputs)}

            self.client.close()
            result.success = True

        except Exception as e:
            result.error = str(e)
            if self.client:
                self.client.close()

        # Populate ATT&CK for ICS technique mapping
        techniques = get_attack_techniques('read')
        if techniques:
            result.attack_technique = techniques[0] if len(techniques) == 1 else {'techniques': techniques}

        return result

    def run_comprehensive_scan(self):
        """Run a comprehensive scan of all register types (backward compatibility)"""
        if self.connect():
            logger.info("\nStarting comprehensive Modbus read operation...")
            self.read_coils()
            time.sleep(0.5)  # Prevent overwhelming the server
            self.read_discrete_inputs()
            time.sleep(0.5)
            self.read_holding_registers()
            time.sleep(0.5)
            self.read_input_registers()
            self.client.close()
        else:
            logger.error("Failed to connect to Modbus server")

if __name__ == "__main__":
    reader = ModbusUnauthorizedReader()
    reader.run_comprehensive_scan()

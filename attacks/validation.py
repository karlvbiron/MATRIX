"""
Modbus protocol validation utilities for M.A.T.R.I.X.

Provides validation functions to ensure parameters comply with Modbus TCP
specifications before sending requests.
"""
from typing import Tuple


class ModbusValidator:
    """Validates Modbus protocol parameters and constraints."""

    # Modbus address and unit ID ranges
    MIN_ADDRESS = 0
    MAX_ADDRESS = 65535
    MIN_UNIT_ID = 0
    MAX_UNIT_ID = 255

    # Modbus per-request limits (from specification)
    MAX_READ_COILS = 2000
    MAX_READ_DISCRETE_INPUTS = 2000
    MAX_READ_HOLDING_REGISTERS = 125
    MAX_READ_INPUT_REGISTERS = 125
    MAX_WRITE_COILS = 1968
    MAX_WRITE_REGISTERS = 123

    @classmethod
    def validate_address(cls, address: int) -> Tuple[bool, str]:
        """
        Validate a Modbus address.

        Args:
            address: Address to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(address, int):
            return False, f"Address must be an integer, got {type(address).__name__}"

        if address < cls.MIN_ADDRESS or address > cls.MAX_ADDRESS:
            return False, f"Address {address} out of range (must be {cls.MIN_ADDRESS}-{cls.MAX_ADDRESS})"

        return True, ""

    @classmethod
    def validate_unit_id(cls, unit_id: int) -> Tuple[bool, str]:
        """
        Validate a Modbus unit ID.

        Args:
            unit_id: Unit ID to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(unit_id, int):
            return False, f"Unit ID must be an integer, got {type(unit_id).__name__}"

        if unit_id < cls.MIN_UNIT_ID or unit_id > cls.MAX_UNIT_ID:
            return False, f"Unit ID {unit_id} out of range (must be {cls.MIN_UNIT_ID}-{cls.MAX_UNIT_ID})"

        return True, ""

    @classmethod
    def validate_count(cls, count: int, operation: str) -> Tuple[bool, str]:
        """
        Validate count parameter for a Modbus operation.

        Args:
            count: Number of registers/coils to read/write
            operation: Operation type (e.g., 'read_coils', 'write_registers')

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(count, int):
            return False, f"Count must be an integer, got {type(count).__name__}"

        if count < 1:
            return False, f"Count must be at least 1, got {count}"

        # Check operation-specific limits
        limits = {
            'read_coils': cls.MAX_READ_COILS,
            'read_discrete_inputs': cls.MAX_READ_DISCRETE_INPUTS,
            'read_holding_registers': cls.MAX_READ_HOLDING_REGISTERS,
            'read_input_registers': cls.MAX_READ_INPUT_REGISTERS,
            'write_coils': cls.MAX_WRITE_COILS,
            'write_registers': cls.MAX_WRITE_REGISTERS,
        }

        max_count = limits.get(operation)
        if max_count is None:
            return False, f"Unknown operation type: {operation}"

        if count > max_count:
            return False, f"Count {count} exceeds Modbus limit for {operation} (max {max_count})"

        return True, ""

    @classmethod
    def validate_read_operation(cls, start: int, count: int, unit_id: int,
                               operation: str) -> Tuple[bool, str]:
        """
        Validate parameters for a read operation.

        Args:
            start: Starting address
            count: Number of items to read
            unit_id: Modbus unit ID
            operation: Operation type (e.g., 'read_coils')

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Validate start address
        valid, msg = cls.validate_address(start)
        if not valid:
            return False, msg

        # Validate count
        valid, msg = cls.validate_count(count, operation)
        if not valid:
            return False, msg

        # Validate unit ID
        valid, msg = cls.validate_unit_id(unit_id)
        if not valid:
            return False, msg

        # Check that the range doesn't exceed address space
        if start + count - 1 > cls.MAX_ADDRESS:
            return False, f"Address range {start} to {start + count - 1} exceeds maximum address {cls.MAX_ADDRESS}"

        return True, ""

    @classmethod
    def validate_write_operation(cls, start: int, count: int, unit_id: int,
                                operation: str) -> Tuple[bool, str]:
        """
        Validate parameters for a write operation.

        Args:
            start: Starting address
            count: Number of items to write
            unit_id: Modbus unit ID
            operation: Operation type (e.g., 'write_coils')

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Same validation as read operations
        return cls.validate_read_operation(start, count, unit_id, operation)

    @classmethod
    def validate_register_value(cls, value: int) -> Tuple[bool, str]:
        """
        Validate a register value (16-bit unsigned).

        Args:
            value: Register value to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(value, int):
            return False, f"Register value must be an integer, got {type(value).__name__}"

        # Note: Python's pymodbus will handle wrapping, but we validate the input
        # Negative values and values > 65535 will be rejected for clarity
        if value < -32768 or value > 65535:
            return False, f"Register value {value} out of valid range (-32768 to 65535)"

        return True, ""

"""
Shared result contract for M.A.T.R.I.X attack modules.

This module defines the standard result structure returned by all attack modules,
enabling programmatic use and separation of business logic from presentation.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional


@dataclass
class AttackResult:
    """
    Structured result returned by attack module execution.

    Attributes:
        attack: Name of the attack module (e.g., 'read', 'coil', 'register', 'overflow')
        target: Dictionary containing host, port, and unit_id (or other relevant keys)
        params: Dictionary of attack-specific parameters used
        success: Boolean indicating if the attack executed successfully
        timestamp: ISO format timestamp of when the attack was executed
        data: Dictionary containing attack-specific result data
        error: Optional error message if the attack failed
        attack_technique: Optional MITRE ATT&CK for ICS technique mapping
    """
    attack: str
    target: Dict[str, Any]
    params: Dict[str, Any]
    success: bool
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    attack_technique: Optional[Dict[str, Any]] = None

    @staticmethod
    def create(attack: str, host: str, port: int, unit_id: int = 1,
               params: Optional[Dict[str, Any]] = None) -> 'AttackResult':
        """
        Factory method to create an AttackResult with common defaults.

        Args:
            attack: Attack module name
            host: Target host IP/hostname
            port: Target port number
            unit_id: Modbus unit ID (default: 1)
            params: Optional attack-specific parameters

        Returns:
            New AttackResult instance with timestamp and empty data dict
        """
        return AttackResult(
            attack=attack,
            target={'host': host, 'port': port, 'unit_id': unit_id},
            params=params or {},
            success=False,
            timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            data={},
            error=None,
            attack_technique=None
        )

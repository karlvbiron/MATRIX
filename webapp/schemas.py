"""
Pydantic schemas for M.A.T.R.I.X Web API request/response models.
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    attack_ics_version: str


class AttackTechniqueInfo(BaseModel):
    """ATT&CK for ICS technique information."""
    technique_id: str
    technique_name: str
    tactic: str
    legacy_id: Optional[str] = None


class AttackInfo(BaseModel):
    """Information about an available attack."""
    name: str
    description: str
    attack_technique: Optional[AttackTechniqueInfo] = None


class MappingsResponse(BaseModel):
    """Coverage matrix response."""
    version: str
    mappings: List[Dict[str, Any]]


class AttackTarget(BaseModel):
    """Target configuration for an attack."""
    model_config = ConfigDict(extra='forbid')

    host: str = Field(default="localhost", description="Target Modbus server IP/hostname")
    port: int = Field(default=502, ge=1, le=65535, description="Target Modbus server port")
    unit_id: int = Field(default=1, ge=0, le=255, description="Modbus unit ID (0-255)")


class ReadAttackRequest(BaseModel):
    """Request for read attack with four independent ranges."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    coil_start: int = Field(default=0, ge=0, le=65535)
    coil_count: int = Field(default=8, ge=1, le=100000)
    discrete_start: int = Field(default=0, ge=0, le=65535)
    discrete_count: int = Field(default=8, ge=1, le=100000)
    holding_start: int = Field(default=0, ge=0, le=65535)
    holding_count: int = Field(default=4, ge=1, le=10000)
    input_start: int = Field(default=0, ge=0, le=65535)
    input_count: int = Field(default=4, ge=1, le=10000)


class CoilAttackRequest(BaseModel):
    """Request for coil write attack."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    start: int = Field(default=0, ge=0, le=65535)
    count: int = Field(default=8, ge=1, le=100000)
    values: Optional[List[bool]] = None


class RegisterAttackRequest(BaseModel):
    """Request for holding register write attack."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    start: int = Field(default=0, ge=0, le=65535)
    count: int = Field(default=4, ge=1, le=10000)
    values: Optional[List[int]] = None


class OverflowAttackRequest(BaseModel):
    """Request for overflow attack."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    start: int = Field(default=0, ge=0, le=65535)
    test_values: Optional[List[int]] = None


class DoSAttackRequest(BaseModel):
    """Request for DoS attack."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    threads: int = Field(default=100, ge=1, le=1000)
    duration: Optional[float] = Field(default=None, ge=0.1, le=300)
    max_requests: Optional[int] = Field(default=None, ge=1)


class ReplayAttackRequest(BaseModel):
    """Request for replay attack."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    pcap_file: str = Field(default="ModbusTraffic.pcap")


class SpoofAttackRequest(BaseModel):
    """Request for spoof attack."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    spoof_ip: str = Field(default="192.168.1.50")
    interface: str = Field(default="docker0")


class AttackResultResponse(BaseModel):
    """Attack execution result."""
    attack: str
    target: Dict[str, Any]
    params: Dict[str, Any]
    success: bool
    timestamp: str
    data: Dict[str, Any]
    error: Optional[str] = None
    attack_technique: Optional[Dict[str, Any]] = None


class MonitorWindow(BaseModel):
    """Window configuration for monitoring."""
    model_config = ConfigDict(extra='forbid')

    coil_start: int = Field(default=0, ge=0, le=65535)
    coil_count: int = Field(default=0, ge=0, le=100000)
    holding_start: int = Field(default=0, ge=0, le=65535)
    holding_count: int = Field(default=0, ge=0, le=10000)


class MonitorStartRequest(BaseModel):
    """Request to start monitoring session."""
    model_config = ConfigDict(extra='forbid')

    target: AttackTarget
    window: MonitorWindow
    interval: float = Field(default=1.0, ge=0.1, le=60.0)


class MonitorStateResponse(BaseModel):
    """Current monitor state snapshot."""
    connected: bool
    last_updated: Optional[str] = None
    target: Optional[Dict[str, Any]] = None
    window: Optional[Dict[str, Any]] = None
    coils: Dict[str, bool] = {}
    holding_registers: Dict[str, int] = {}
    error: Optional[str] = None

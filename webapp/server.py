"""
FastAPI server for M.A.T.R.I.X Web API.

Orchestrates attack execution by calling attack classes' execute() methods in-process.
"""
import os
import logging
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from attacks.attack_mapping import ATTACK_TECHNIQUE_MAPPING, ATTACK_ICS_VERSION, get_attack_techniques
from attacks.validation import ModbusValidator
from attacks.modbus_unauthorized_read import ModbusUnauthorizedReader
from attacks.modbus_coil_write_attack import ModbusUnauthorizedCoilWriter
from attacks.modbus_holding_registers_write_attack import ModbusUnauthorizedHoldingRegisterWriter
from attacks.modbus_overflow_attack import ModbusOverflowAttacker
from attacks.modbus_dos_attack import ModbusDoSAttacker
from attacks.modbus_replay_attack import ModbusReplyAttacker
from attacks.modbus_spoof_response import ModbusResponseSpoofer

from .schemas import (
    HealthResponse, AttackInfo, AttackTechniqueInfo, MappingsResponse,
    AttackResultResponse, ReadAttackRequest, CoilAttackRequest, RegisterAttackRequest,
    OverflowAttackRequest, DoSAttackRequest, ReplayAttackRequest, SpoofAttackRequest,
    MonitorStartRequest, MonitorStateResponse
)
from .monitor import monitor_service

logger = logging.getLogger(__name__)

# App version
APP_VERSION = "0.1.0"

# Available attacks
AVAILABLE_ATTACKS = {
    "read": "Unauthorized read of Modbus registers and coils",
    "coil": "Unauthorized write to coils",
    "register": "Unauthorized write to holding registers",
    "overflow": "Register overflow attack",
    "dos": "Denial of Service attack",
    "replay": "Modbus traffic replay attack",
    "spoof": "Response spoofing attack"
}

# Dangerous attacks that require explicit enablement
DANGEROUS_ATTACKS = {"dos", "spoof", "replay"}

# Create FastAPI app
app = FastAPI(
    title="M.A.T.R.I.X API",
    description="Modbus Attack Tool for Remote Industrial Exploitation - Web API",
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Setup templates and static files
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Mount static files
try:
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
except RuntimeError:
    # Static directory might not exist yet or be empty
    pass


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Main web UI."""
    # Get attacks list for the template
    attacks = []
    for name, description in AVAILABLE_ATTACKS.items():
        techniques = get_attack_techniques(name)
        attack_technique = None
        if techniques:
            tech = techniques[0]
            attack_technique = {
                'technique_id': tech['technique_id'],
                'technique_name': tech['technique_name'],
                'tactic': tech['tactic'],
                'legacy_id': tech.get('legacy_id')
            }
        attacks.append({
            'name': name,
            'description': description,
            'attack_technique': attack_technique
        })

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"attacks": attacks}
    )


@app.get("/api/health", response_model=HealthResponse)
async def health():
    """Health check endpoint with version information."""
    return HealthResponse(
        status="ok",
        version=APP_VERSION,
        attack_ics_version=ATTACK_ICS_VERSION
    )


@app.get("/api/attacks", response_model=list[AttackInfo])
async def list_attacks():
    """List all available attacks with their ATT&CK for ICS technique mappings."""
    attacks = []

    for name, description in AVAILABLE_ATTACKS.items():
        # Get technique from mapping
        techniques = get_attack_techniques(name)
        attack_technique = None

        if techniques:
            tech = techniques[0]  # Use first technique
            attack_technique = AttackTechniqueInfo(
                technique_id=tech['technique_id'],
                technique_name=tech['technique_name'],
                tactic=tech['tactic'],
                legacy_id=tech.get('legacy_id')
            )

        attacks.append(AttackInfo(
            name=name,
            description=description,
            attack_technique=attack_technique
        ))

    return attacks


@app.get("/api/mappings", response_model=MappingsResponse)
async def get_mappings():
    """Get the complete ATT&CK for ICS coverage matrix."""
    mappings = []

    for attack_name, techniques in ATTACK_TECHNIQUE_MAPPING.items():
        for technique in techniques:
            mappings.append({
                'attack': attack_name,
                'technique_id': technique['technique_id'],
                'technique_name': technique['technique_name'],
                'tactic': technique['tactic'],
                'legacy_id': technique.get('legacy_id')
            })

    return MappingsResponse(
        version=ATTACK_ICS_VERSION,
        mappings=mappings
    )


def get_attack_technique_dict(attack_name: str):
    """Get attack technique as dict for consistent response format."""
    techniques = get_attack_techniques(attack_name)
    if techniques:
        return techniques[0] if len(techniques) == 1 else {'techniques': techniques}
    return None


@app.post("/api/attacks/read/run", response_model=AttackResultResponse)
async def run_read_attack(request: ReadAttackRequest):
    """Execute unauthorized read attack."""
    # Validate all four ranges
    for operation, start, count in [
        ('read_coils', request.coil_start, request.coil_count),
        ('read_discrete_inputs', request.discrete_start, request.discrete_count),
        ('read_holding_registers', request.holding_start, request.holding_count),
        ('read_input_registers', request.input_start, request.input_count)
    ]:
        valid, msg = ModbusValidator.validate_read_operation(start, count, request.target.unit_id, operation)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Validation failed: {msg}")

    attacker = ModbusUnauthorizedReader(
        host=request.target.host,
        port=request.target.port,
        unit_id=request.target.unit_id
    )
    result = attacker.execute(
        coil_start=request.coil_start,
        coil_count=request.coil_count,
        discrete_start=request.discrete_start,
        discrete_count=request.discrete_count,
        holding_start=request.holding_start,
        holding_count=request.holding_count,
        input_start=request.input_start,
        input_count=request.input_count
    )

    # Ensure attack_technique is populated even on failure
    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('read')

    return AttackResultResponse(**result.__dict__)


@app.post("/api/attacks/coil/run", response_model=AttackResultResponse)
async def run_coil_attack(request: CoilAttackRequest):
    """Execute coil write attack."""
    # Validate with attacks/validation.py
    valid, msg = ModbusValidator.validate_write_operation(
        request.start, request.count, request.target.unit_id, 'write_coils'
    )
    if not valid:
        raise HTTPException(status_code=400, detail=f"Validation failed: {msg}")

    attacker = ModbusUnauthorizedCoilWriter(
        host=request.target.host,
        port=request.target.port,
        unit_id=request.target.unit_id
    )
    result = attacker.execute(start=request.start, count=request.count, values=request.values)

    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('coil')

    return AttackResultResponse(**result.__dict__)


@app.post("/api/attacks/register/run", response_model=AttackResultResponse)
async def run_register_attack(request: RegisterAttackRequest):
    """Execute holding register write attack."""
    # Validate with attacks/validation.py
    valid, msg = ModbusValidator.validate_write_operation(
        request.start, request.count, request.target.unit_id, 'write_registers'
    )
    if not valid:
        raise HTTPException(status_code=400, detail=f"Validation failed: {msg}")

    attacker = ModbusUnauthorizedHoldingRegisterWriter(
        host=request.target.host,
        port=request.target.port,
        unit_id=request.target.unit_id
    )
    result = attacker.execute(start=request.start, count=request.count, values=request.values)

    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('register')

    return AttackResultResponse(**result.__dict__)


@app.post("/api/attacks/overflow/run", response_model=AttackResultResponse)
async def run_overflow_attack(request: OverflowAttackRequest):
    """Execute overflow attack."""
    # Validate address and unit_id
    valid, msg = ModbusValidator.validate_address(request.start)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Validation failed: {msg}")

    valid, msg = ModbusValidator.validate_unit_id(request.target.unit_id)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Validation failed: {msg}")

    attacker = ModbusOverflowAttacker(
        host=request.target.host,
        port=request.target.port,
        unit_id=request.target.unit_id
    )
    result = attacker.execute(start=request.start, test_values=request.test_values)

    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('overflow')

    return AttackResultResponse(**result.__dict__)


@app.post("/api/attacks/dos/run", response_model=AttackResultResponse)
async def run_dos_attack(request: DoSAttackRequest):
    """Execute DoS attack (requires MATRIX_WEB_ENABLE_DANGEROUS=1)."""
    dangerous_enabled = os.environ.get("MATRIX_WEB_ENABLE_DANGEROUS", "0") == "1"
    if not dangerous_enabled:
        raise HTTPException(
            status_code=501,
            detail="Attack 'dos' disabled in web MVP. Set MATRIX_WEB_ENABLE_DANGEROUS=1 to enable."
        )

    attacker = ModbusDoSAttacker(
        host=request.target.host,
        port=request.target.port,
        thread_count=request.threads
    )
    result = attacker.execute(duration=request.duration, max_requests=request.max_requests)

    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('dos')

    return AttackResultResponse(**result.__dict__)


@app.post("/api/attacks/replay/run", response_model=AttackResultResponse)
async def run_replay_attack(request: ReplayAttackRequest):
    """Execute replay attack (requires MATRIX_WEB_ENABLE_DANGEROUS=1)."""
    dangerous_enabled = os.environ.get("MATRIX_WEB_ENABLE_DANGEROUS", "0") == "1"
    if not dangerous_enabled:
        raise HTTPException(
            status_code=501,
            detail="Attack 'replay' disabled in web MVP. Set MATRIX_WEB_ENABLE_DANGEROUS=1 to enable."
        )

    attacker = ModbusReplyAttacker(
        target_ip=request.target.host,
        target_port=request.target.port
    )
    result = attacker.execute(pcap_file=request.pcap_file)

    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('replay')

    return AttackResultResponse(**result.__dict__)


@app.post("/api/attacks/spoof/run", response_model=AttackResultResponse)
async def run_spoof_attack(request: SpoofAttackRequest):
    """Execute spoof attack (requires MATRIX_WEB_ENABLE_DANGEROUS=1)."""
    dangerous_enabled = os.environ.get("MATRIX_WEB_ENABLE_DANGEROUS", "0") == "1"
    if not dangerous_enabled:
        raise HTTPException(
            status_code=501,
            detail="Attack 'spoof' disabled in web MVP. Set MATRIX_WEB_ENABLE_DANGEROUS=1 to enable."
        )

    attacker = ModbusResponseSpoofer(
        target_ip=request.target.host,
        target_port=request.target.port,
        spoof_ip=request.spoof_ip
    )
    attacker.interface = request.interface
    result = attacker.execute()

    if result.attack_technique is None:
        result.attack_technique = get_attack_technique_dict('spoof')

    return AttackResultResponse(**result.__dict__)


# === Monitor Endpoints ===

@app.post("/api/monitor/start", response_model=MonitorStateResponse)
async def start_monitor(request: MonitorStartRequest):
    """
    Start live monitoring session (replaces any existing session).

    Polls target Modbus state at specified interval (read-only).
    """
    try:
        state = await monitor_service.start_session(
            target={
                "host": request.target.host,
                "port": request.target.port,
                "unit_id": request.target.unit_id
            },
            window={
                "coil_start": request.window.coil_start,
                "coil_count": request.window.coil_count,
                "holding_start": request.window.holding_start,
                "holding_count": request.window.holding_count
            },
            interval=request.interval
        )
        return MonitorStateResponse(**state)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/monitor/stop")
async def stop_monitor():
    """Stop the active monitoring session."""
    await monitor_service.stop_session()
    return {"status": "stopped"}


@app.get("/api/monitor/state", response_model=MonitorStateResponse)
async def get_monitor_state():
    """Get current monitor state snapshot."""
    state = monitor_service.get_state()
    return MonitorStateResponse(**state)


@app.get("/api/monitor/stream")
async def monitor_stream():
    """
    Server-Sent Events stream of live monitor state.

    Pushes state updates as they occur. Client should use EventSource API.
    """
    from sse_starlette.sse import EventSourceResponse

    if not monitor_service.has_session():
        raise HTTPException(status_code=400, detail="No active monitoring session")

    return EventSourceResponse(monitor_service.stream_events())

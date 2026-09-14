"""
MITRE ATT&CK for ICS technique mapping for M.A.T.R.I.X attack modules.

This module is the single source of truth for ATT&CK for ICS technique mappings.
All attack modules reference this central registry.

Version: MITRE ATT&CK for ICS v19.2 (current as of 2026)
"""
from typing import Dict, List, Any

# MITRE ATT&CK for ICS framework version
ATTACK_ICS_VERSION = "v19.2"

# Central mapping: attack name -> list of ATT&CK for ICS technique(s)
# Each technique entry contains:
#   - technique_id: MITRE ATT&CK for ICS technique ID (e.g., "T0861")
#   - technique_name: Human-readable name of the technique
#   - tactic: Primary tactic category
#   - legacy_id: Optional pre-v19 technique ID for recognition
ATTACK_TECHNIQUE_MAPPING: Dict[str, List[Dict[str, Any]]] = {
    "read": [
        {
            "technique_id": "T0861",
            "technique_name": "Point & Tag Identification",
            "tactic": "Collection",
            "legacy_id": None
        }
    ],
    "coil": [
        {
            "technique_id": "T1692.001",
            "technique_name": "Command Message",
            "tactic": "Impair Process Control",
            "legacy_id": "T0855"
        }
    ],
    "register": [
        {
            "technique_id": "T0836",
            "technique_name": "Modify Parameter",
            "tactic": "Impair Process Control",
            "legacy_id": None
        }
    ],
    "overflow": [
        {
            "technique_id": "T0814",
            "technique_name": "Denial of Service",
            "tactic": "Inhibit Response Function",
            "legacy_id": None
        }
    ],
    "dos": [
        {
            "technique_id": "T0814",
            "technique_name": "Denial of Service",
            "tactic": "Inhibit Response Function",
            "legacy_id": None
        }
    ],
    "replay": [
        {
            "technique_id": "T1692.001",
            "technique_name": "Command Message",
            "tactic": "Impair Process Control",
            "legacy_id": "T0855"
        }
    ],
    "spoof": [
        {
            "technique_id": "T1692.002",
            "technique_name": "Reporting Message",
            "tactic": "Evasion / Impair Process Control",
            "legacy_id": "T0856"
        }
    ]
}


def get_attack_techniques(attack_name: str) -> List[Dict[str, Any]]:
    """
    Get ATT&CK for ICS technique(s) for a given attack.

    Args:
        attack_name: Name of the attack (e.g., 'read', 'coil', 'register')

    Returns:
        List of technique dictionaries, or empty list if not mapped
    """
    return ATTACK_TECHNIQUE_MAPPING.get(attack_name, [])


def get_all_mappings() -> Dict[str, List[Dict[str, Any]]]:
    """
    Get the complete attack-to-technique mapping.

    Returns:
        Dictionary mapping attack names to their technique list
    """
    return ATTACK_TECHNIQUE_MAPPING.copy()


def format_technique_tag(techniques: List[Dict[str, Any]]) -> str:
    """
    Format technique(s) as a single-line tag for display.

    Args:
        techniques: List of technique dictionaries

    Returns:
        Formatted string (e.g., "T1692.001 Command Message (Impair Process Control)")
    """
    if not techniques:
        return "No mapping"

    # For single technique, format as: ID Name (Tactic)
    if len(techniques) == 1:
        tech = techniques[0]
        return f"{tech['technique_id']} {tech['technique_name']} ({tech['tactic']})"

    # For multiple techniques, list them separated by semicolons
    parts = []
    for tech in techniques:
        parts.append(f"{tech['technique_id']} {tech['technique_name']} ({tech['tactic']})")
    return "; ".join(parts)

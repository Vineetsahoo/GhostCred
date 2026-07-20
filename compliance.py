from typing import List

COMPLIANCE_MAPPINGS = {
    "code": [
        "SOC 2 CC6.1 (Logical Access)",
        "ISO 27001 A.9.2.3 (Management of Secret Authentication Information)",
        "PCI-DSS Req 8.2 (Identify users and authenticate access)"
    ],
    "env": [
        "SOC 2 CC6.1 (Logical Access)",
        "ISO 27001 A.9.2.3 (Management of Secret Authentication Information)",
        "PCI-DSS Req 8.2 (Identify users and authenticate access)"
    ],
    "mcp_config": [
        "SOC 2 CC6.6 (Endpoint Security)",
        "ISO 27001 A.14.2.1 (Secure Development Policy)"
    ],
    "ide_config": [
        "SOC 2 CC6.6 (Endpoint Security)",
        "ISO 27001 A.14.2.1 (Secure Development Policy)"
    ],
    "shell_history": [
        "SOC 2 CC6.1 (Logical Access)",
        "ISO 27001 A.9.2.3 (Management of Secret Authentication Information)"
    ],
}

def map_finding_to_compliance(source_kind: str) -> List[str]:
    """
    Returns a list of compliance standard violations based on the finding's source_kind.
    """
    return COMPLIANCE_MAPPINGS.get(source_kind, [])

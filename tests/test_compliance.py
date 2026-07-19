from ghostcred.compliance import map_finding_to_compliance

def test_map_finding_to_compliance():
    violations = map_finding_to_compliance("code")
    assert "SOC 2 CC6.1 (Logical Access)" in violations
    
    violations_mcp = map_finding_to_compliance("mcp_config")
    assert "SOC 2 CC6.6 (Endpoint Security)" in violations_mcp
    
    violations_unknown = map_finding_to_compliance("unknown_kind")
    assert violations_unknown == []

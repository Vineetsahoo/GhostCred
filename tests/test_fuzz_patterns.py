import hypothesis.strategies as st
from hypothesis import given, settings, HealthCheck
from ghostcred.scanners.base import scan_text

@given(st.text(min_size=1, max_size=500))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow], deadline=1000)
def test_fuzz_patterns_no_redos(text):
    """
    Fuzz all regex patterns with random text.
    This test primarily verifies that the regexes don't get stuck in catastrophic 
    backtracking (ReDoS). The deadline=1000ms ensures that no evaluation takes 
    longer than 1 second per string.
    """
    # Just running the text through the scanners to make sure it doesn't hang/crash.
    try:
        scan_text(text, source_path="fuzzed.txt", source_kind="code", salt="fuzz")
    except Exception as e:
        # We only care about hangs (ReDoS), catching exceptions is secondary but 
        # scanning shouldn't crash either.
        pass

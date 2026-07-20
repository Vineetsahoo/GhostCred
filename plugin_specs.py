import pluggy
from typing import List, Type, Dict, TYPE_CHECKING
if TYPE_CHECKING:
    from ghostcred.scanners.patterns import SecretPattern
    from ghostcred.revocation.base import Revoker

hookspec = pluggy.HookspecMarker("ghostcred")
hookimpl = pluggy.HookimplMarker("ghostcred")

@hookspec
def ghostcred_register_patterns() -> List['SecretPattern']:
    """Register custom secret scanning patterns."""

@hookspec
def ghostcred_register_revokers() -> Dict[str, Type['Revoker']]:
    """Register custom revokers. Return a dict mapping provider name to revoker class."""

from ghostcred.revocation.base import RevocationResult, Revoker
from ghostcred.revocation.github_revoker import GitHubRevoker
from ghostcred.revocation.openai_revoker import OpenAIRevoker
from ghostcred.revocation.anthropic_revoker import AnthropicRevoker

from ghostcred.plugin_manager import pm, load_plugins

def get_revoker_registry() -> dict[str, Revoker]:
    load_plugins()
    registry: dict[str, Revoker] = {}
    for revoker_dict in pm.hook.ghostcred_register_revokers():
        registry.update(revoker_dict)
    return registry

__all__ = ["get_revoker_registry", "RevocationResult", "Revoker"]

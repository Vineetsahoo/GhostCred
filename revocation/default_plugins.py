from ghostcred.plugin_specs import hookimpl
from ghostcred.revocation.github_revoker import GitHubRevoker
from ghostcred.revocation.openai_revoker import OpenAIRevoker
from ghostcred.revocation.anthropic_revoker import AnthropicRevoker

@hookimpl
def ghostcred_register_revokers():
    return {
        "github_pat": GitHubRevoker(),
        "github_fine_grained_pat": GitHubRevoker(),
        "openai_api_key": OpenAIRevoker(),
        "anthropic_api_key": AnthropicRevoker(),
    }

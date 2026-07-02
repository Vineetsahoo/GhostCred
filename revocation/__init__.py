from ghostcred.revocation.base import RevocationResult, Revoker
from ghostcred.revocation.github_revoker import GitHubRevoker
from ghostcred.revocation.openai_revoker import OpenAIRevoker
from ghostcred.revocation.anthropic_revoker import AnthropicRevoker

# AWS revocation is not active yet — will be wired in when deploying to an AWS account.
# from ghostcred.revocation.aws_revoker import AWSRevoker

REVOKER_REGISTRY: dict[str, Revoker] = {
    "github_pat": GitHubRevoker(),
    "github_fine_grained_pat": GitHubRevoker(),
    "openai_api_key": OpenAIRevoker(),
    "anthropic_api_key": AnthropicRevoker(),
}

__all__ = ["REVOKER_REGISTRY", "RevocationResult", "Revoker"]

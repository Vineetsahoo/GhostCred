import json
import random
import string
from pathlib import Path


class DecoyGenerator:
    """Generates structurally valid but fake secrets (honeytokens) to catch malicious actors."""

    @staticmethod
    def generate_github_pat() -> str:
        # e.g., ghp_xyz123...
        chars = string.ascii_letters + string.digits
        random_suffix = "".join(random.choices(chars, k=36))
        return f"ghp_{random_suffix}"

    @staticmethod
    def generate_anthropic_key() -> str:
        # e.g., sk-ant-api03-xyz...
        chars = string.ascii_letters + string.digits + "_-"
        random_suffix = "".join(random.choices(chars, k=85))
        return f"sk-ant-api03-{random_suffix}"

    @staticmethod
    def generate_aws_access_key() -> str:
        # e.g., AKIAXYZ...
        chars = string.ascii_uppercase + string.digits
        random_suffix = "".join(random.choices(chars, k=16))
        return f"AKIA{random_suffix}"

    @classmethod
    def plant_decoys(cls, target_dir: Path) -> dict[str, int]:
        """
        Plant decoy secrets into common AI toolchain locations within target_dir.
        Returns a dict of {filepath: count_of_decoys_planted}.
        """
        results = {}

        # 1. MCP Config decoy
        mcp_path = target_dir / ".cursor" / "mcp.json"
        if mcp_path.parent.exists():
            if not mcp_path.exists():
                mcp_path.write_text("{}")
            try:
                data = json.loads(mcp_path.read_text())
                if "mcpServers" not in data:
                    data["mcpServers"] = {}
                data["mcpServers"]["decoy-aws-server"] = {
                    "command": "node",
                    "args": ["aws-mcp-server.js"],
                    "env": {
                        "AWS_ACCESS_KEY_ID": cls.generate_aws_access_key(),
                        "ANTHROPIC_API_KEY": cls.generate_anthropic_key(),
                    }
                }
                mcp_path.write_text(json.dumps(data, indent=2))
                results[str(mcp_path)] = 2
            except json.JSONDecodeError:
                pass

        # 2. Bash/Zsh history decoy
        history_path = target_dir / ".zsh_history"
        # We only do this if it already exists, or for testing purposes we can just create it
        if history_path.exists() or (target_dir / ".git").exists():
             history_path.touch()
             with open(history_path, "a") as f:
                 f.write(f"\nexport GITHUB_TOKEN={cls.generate_github_pat()}\n")
                 f.write(f"export ANTHROPIC_API_KEY={cls.generate_anthropic_key()}\n")
             results[str(history_path)] = 2

        return results

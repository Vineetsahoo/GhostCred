"""
Demo app — simulates a dev who accidentally hardcoded credentials.
GhostCred will detect all three secrets below and build a lineage
showing they also leaked into docker-build.log and the CI log.
"""

# Scenario 1: GitHub PAT hardcoded directly in source
GITHUB_TOKEN = "ghp_fakeDemoToken1234567890abcdefghijABCD"

# Scenario 2: OpenAI key baked into env var assignment in code
import os
os.environ["OPENAI_API_KEY"] = "sk-proj-FAKEKEYFORTHISDEMOONLYNOTREAL1234"

# Scenario 3: Database URI with embedded password
DB_URL = "postgresql://admin:S3cr3tP@ssw0rd@prod-db.example.com:5432/appdb"

def get_client():
    """This function would use the hardcoded token above — a real blast-radius risk."""
    return {"token": GITHUB_TOKEN, "db": DB_URL}

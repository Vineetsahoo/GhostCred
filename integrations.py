import json
import logging
import urllib.request
import urllib.error
import copy
from typing import Dict, Any

logger = logging.getLogger(__name__)

def send_webhook_report(report: Dict[str, Any], url: str) -> bool:
    """
    Sends the GhostCred JSON report to the provided webhook/SIEM URL.
    Explicitly redacts raw_secret from the payload before transmission to satisfy enterprise logging rules.
    """
    # Create a deep copy to avoid modifying the original report object which might be written to disk
    payload = copy.deepcopy(report)
    
    # Redact raw secrets
    for finding in payload.get("findings", []):
        if "raw_secret" in finding:
            finding["raw_secret"] = "[REDACTED_FOR_SIEM_INGEST]"

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, 
            data=data, 
            headers={"Content-Type": "application/json", "User-Agent": "GhostCred-Webhook/1.0"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status >= 200 and response.status < 300:
                return True
            else:
                logger.error(f"Webhook failed with status {response.status}")
                return False
    except Exception as e:
        logger.error(f"Failed to send webhook to {url}: {e}")
        return False

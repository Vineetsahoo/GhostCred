import json
from unittest.mock import patch, MagicMock
from ghostcred.integrations import send_webhook_report

def test_send_webhook_report_success():
    report = {
        "findings": [{"raw_secret": "secret123", "provider": "aws"}],
        "revocations": []
    }
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        success = send_webhook_report(report, "http://example.com/webhook")
        
        assert success is True
        # Verify the raw_secret is redacted in the payload
        request = mock_urlopen.call_args[0][0]
        sent_data = json.loads(request.data.decode("utf-8"))
        assert sent_data["findings"][0]["raw_secret"] == "[REDACTED_FOR_SIEM_INGEST]"

def test_send_webhook_report_failure():
    report = {"findings": []}
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        success = send_webhook_report(report, "http://example.com/webhook")
        assert success is False

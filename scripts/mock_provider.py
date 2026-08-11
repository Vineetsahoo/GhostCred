"""
Mock Provider Server
====================
Simulates GitHub, OpenAI, and Anthropic provider endpoints locally
so GhostCred's liveness checks and revocation calls work without
real credentials or hitting real APIs.

Usage:
    pip install flask
    python scripts/mock_provider.py

Endpoints:
    GET  /user                   -> GitHub PAT liveness check
    DELETE /installation/token   -> GitHub PAT revocation
    GET  /openai/check           -> OpenAI key liveness check
    DELETE /openai/revoke        -> OpenAI key revocation
    GET  /anthropic/check        -> Anthropic key liveness check
    DELETE /anthropic/revoke     -> Anthropic key revocation

The demo tokens here match demo-repo/.env and demo-repo/app.py exactly.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Token state — starts as "live", revocation flips it to False ──────────────
tokens: dict[str, bool] = {
    # GitHub PAT — matches demo-repo/app.py and demo-repo/.cursor/mcp.json
    "ghp_fakeDemoToken1234567890abcdefghijABCD": True,
    # OpenAI key — matches demo-repo/.env
    "sk-proj-FAKEKEYFORTHISDEMOONLYNOTREAL1234": True,
    # Anthropic key — matches demo-repo/.env (truncated for check purposes)
    "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01": True,
}

# ── GitHub endpoints ───────────────────────────────────────────────────────────

@app.get("/user")
def github_check():
    token = _extract_token()
    if tokens.get(token):
        return jsonify({"login": "demo-user", "provider": "github"}), 200
    return jsonify({"message": "Bad credentials"}), 401

@app.delete("/installation/token")
def github_revoke():
    token = _extract_token()
    tokens[token] = False
    print(f"[mock] GitHub token REVOKED: {token[:20]}...")
    return "", 204

# ── OpenAI endpoints ───────────────────────────────────────────────────────────

@app.get("/openai/check")
def openai_check():
    token = _extract_bearer()
    if tokens.get(token):
        return jsonify({"object": "model", "provider": "openai"}), 200
    return jsonify({"error": {"code": "invalid_api_key"}}), 401

@app.delete("/openai/revoke")
def openai_revoke():
    token = _extract_bearer()
    tokens[token] = False
    print(f"[mock] OpenAI key REVOKED: {token[:20]}...")
    return jsonify({"deleted": True}), 200

# ── Anthropic endpoints ────────────────────────────────────────────────────────

@app.get("/anthropic/check")
def anthropic_check():
    key = request.headers.get("x-api-key", "")
    if tokens.get(key):
        return jsonify({"type": "ping_event", "provider": "anthropic"}), 200
    return jsonify({"error": {"type": "authentication_error"}}), 401

@app.delete("/anthropic/revoke")
def anthropic_revoke():
    key = request.headers.get("x-api-key", "")
    tokens[key] = False
    print(f"[mock] Anthropic key REVOKED: {key[:20]}...")
    return jsonify({"deleted": True}), 200

# ── Status endpoint — shows all current token states ──────────────────────────

@app.get("/status")
def status():
    return jsonify({
        k[:20] + "...": ("LIVE" if v else "REVOKED")
        for k, v in tokens.items()
    })

# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_token() -> str:
    auth = request.headers.get("Authorization", "")
    return auth.replace("token ", "").replace("Bearer ", "").strip()

def _extract_bearer() -> str:
    auth = request.headers.get("Authorization", "")
    return auth.replace("Bearer ", "").strip()


if __name__ == "__main__":
    print("\n  GhostCred Mock Provider running at http://localhost:5001")
    print("  GET  /status  — check current token liveness state")
    print("  GET  /user    — GitHub PAT check  (Authorization: token <tok>)")
    print("  DELETE /installation/token  — GitHub PAT revoke")
    print("  Press Ctrl+C to stop.\n")
    app.run(port=5001, debug=False)

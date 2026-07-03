from flask import Flask, jsonify, request

app = Flask(__name__)

tokens = {"ghp_fakeDemoToken1234567890abcdefghij": True}

@app.get("/user")
def check_token():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("token ", "")
    if tokens.get(token):
        return jsonify({"login": "demo-user"}), 200
    return jsonify({"message": "Bad credentials"}), 401

@app.delete("/installation/token")
def revoke_token():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("token ", "")
    tokens[token] = False  # actually kills it
    return "", 204

if __name__ == "__main__":
    app.run(port=5001)

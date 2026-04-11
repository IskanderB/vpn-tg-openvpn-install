import os
import subprocess
from bottle import Bottle, request, response, static_file, abort

app = Bottle()

API_KEY      = os.environ.get("API_KEY", "changeme")
SCRIPTS_DIR  = "/var/openvpn/openvpn-install"
CERTS_DIR    = "/var/openvpn/certs"
ROOT_DIR     = "/root"


def check_auth():
    token = request.headers.get("Authorization", "")
    if token != f"Bearer {API_KEY}":
        abort(401, "Unauthorized")


def run_script(script: str, client_name: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [script, client_name],
        capture_output=True,
        text=True,
        timeout=120,
    )


# POST /users  — добавить пользователя и вернуть .ovpn файл
@app.post("/users")
def add_user():
    check_auth()

    data = request.json
    if not data or not data.get("name"):
        abort(400, "Field 'name' is required")

    name = data["name"].strip()
    if not name.isalnum():
        abort(400, "Name must be alphanumeric")

    cert_path = os.path.join(CERTS_DIR, f"{name}.ovpn")
    if os.path.exists(cert_path):
        abort(409, f"User '{name}' already exists")

    result = run_script(f"{SCRIPTS_DIR}/add-client.expect", name)
    if result.returncode != 0:
        abort(500, f"Script error: {result.stderr}")

    root_cert = os.path.join(ROOT_DIR, f"{name}.ovpn")
    if not os.path.exists(root_cert):
        abort(500, "Certificate was not generated")

    return static_file(
        f"{name}.ovpn",
        root=ROOT_DIR,
        download=f"{name}.ovpn",
        mimetype="application/octet-stream",
    )


# GET /users/{name}/cert  — скачать .ovpn файл существующего пользователя
@app.get("/users/<name>/cert")
def get_cert(name):
    check_auth()

    cert_path = os.path.join(CERTS_DIR, f"{name}.ovpn")
    if not os.path.exists(cert_path):
        abort(404, f"Certificate for '{name}' not found")

    return static_file(
        f"{name}.ovpn",
        root=CERTS_DIR,
        download=f"{name}.ovpn",
        mimetype="application/octet-stream",
    )


# DELETE /users/{name}  — отозвать сертификат и удалить пользователя
@app.delete("/users/<name>")
def delete_user(name):
    check_auth()

    result = run_script(f"{SCRIPTS_DIR}/revoke-client.expect", name)
    if result.returncode != 0:
        abort(500, f"Script error: {result.stderr}")

    cert_path = os.path.join(CERTS_DIR, f"{name}.ovpn")
    if os.path.exists(cert_path):
        os.remove(cert_path)

    response.status = 204
    return ""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)

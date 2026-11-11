import io

from flask import Flask, jsonify, render_template, request, send_file
from urllib.parse import quote

import engine

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = engine.MAX_ENCRYPTED_BYTES


def _uploaded_file():
    if "file" not in request.files:
        raise ValueError("No se recibió ningún archivo.")
    uploaded = request.files["file"]
    if not uploaded.filename:
        raise ValueError("No se recibió ningún archivo.")
    return uploaded


def _api_error(handler):
    try:
        return handler()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Error inesperado al procesar el archivo."}), 500


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/inspect")
def inspect():
    def handler():
        data = _uploaded_file().read()
        info = engine.inspect_blob(data)
        if info["version"] == 0:
            raise ValueError("Archivo inválido o no cifrado con CryptoVault.")
        return jsonify(info)
    return _api_error(handler)


@app.post("/api/encrypt")
def encrypt():
    def handler():
        uploaded = _uploaded_file()
        data = uploaded.read()
        blob = engine.encrypt_selfcontained(data, uploaded.filename)
        name = engine.encrypted_filename()
        response = send_file(
            io.BytesIO(blob),
            as_attachment=True,
            download_name=name,
            mimetype="application/octet-stream",
        )
        response.headers["X-Filename"] = quote(name)
        return response
    return _api_error(handler)


@app.post("/api/decrypt")
def decrypt():
    def handler():
        uploaded = _uploaded_file()
        data = uploaded.read()
        plaintext, filename = engine.decrypt_file(data)
        response = send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream",
        )
        response.headers["X-Filename"] = quote(filename)
        return response
    return _api_error(handler)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, threaded=True)

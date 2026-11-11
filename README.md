# CryptoVault Web

Versión web de CryptoVault pensada para el mínimo manejo del usuario:
**cifrar, descifrar y cargar el archivo**, nada más.

- **Cifrar**: carga un archivo → pulsa el botón → descarga un único
  archivo `.cvault` autocontenido con la master key de 69 caracteres
  embebida dentro.
- **Descifrar**: carga el `.cvault` → pulsa el botón → descarga el
  archivo original con su nombre. Sin escribir claves.

## Cómo correrlo

Servidor **local** (no expone nada a la red):

```bash
python3 -m venv --without-pip .venv      # si tu sistema no trae ensurepip
.venv/bin/python get-pip.py              # bootstrap de pip
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Abre http://127.0.0.1:5000 en el navegador.

## Formato v5 autocontenido

```
CVLT\x05\x00 | modo | sección de key | salt(32) | HMAC(64) | capa3
```

- **Sin contraseña** (modo 0): la master key va embebida ofuscada dentro
  del archivo. El archivo se descifra solo al cargarlo: máximo comodidad,
  pero quien obtenga el archivo podrá descifrarlo.
- **Con contraseña** (modo 1, opcional): la master key embebida viaja
  cifrada con AES-256-GCM usando una clave derivada de la contraseña
  (scrypt + HKDF). Sin la contraseña el archivo no se puede abrir.

El cuerpo usa el mismo triple cifrado autenticado del desktop:
AES-256-GCM → AES-256-OCB3 → ChaCha20-Poly1305, con cabecera como AAD en
las tres capas y HMAC-SHA512 exterior (Encrypt-then-MAC) verificado
antes de descifrar. KDF: scrypt (`n=2^16, r=8, p=1`) + HKDF-SHA512 con
separación de dominio.

## Compatibilidad

| Archivo | CryptoVault Web | CryptoVault Desktop 3.0.0 |
|---|---|---|
| v5 autocontenido | cifra y descifra | no lo reconoce |
| v4 (desktop, con master key) | descifra pegando la key | cifra y descifra |
| v3 / v2 (legacy) | descifra pegando la key | descifra |

Al cargar un archivo para descifrar, la web lo analiza y muestra
únicamente los campos que necesita.

## Seguridad

- El servidor corre solo en `127.0.0.1`; ningún dato sale de tu equipo.
- Límite de 256 MB por archivo.
- La ofuscación de la key embebida **no es cifrado**: evita que se lea a
  simple vista, pero no protege contra quien tenga el archivo. Para
  protección real usa la contraseña opcional.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

import hashlib
import hmac
import os
import secrets
import string
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESOCB3, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MASTER_KEY_LENGTH = 69
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
HMAC_SIZE = 64
KEY_SIZE = 32
SEED_SIZE = 64
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1
PBKDF2_ITERATIONS = 310_000

MAGIC_V5 = b"CVLT\x05\x00"
MAGIC = b"CVLT\x04\x00"
MAGIC_V3 = b"CVLT\x03\x00"
MAGIC_V2 = b"CVLT\x02\x00"
FILE_FORMAT_VERSION = 5

MODE_EMBEDDED = 0x00
MODE_WRAPPED = 0x01
EMBEDDED_SECTION_SIZE = MASTER_KEY_LENGTH
WRAPPED_SECTION_SIZE = SALT_SIZE + NONCE_SIZE + MASTER_KEY_LENGTH + TAG_SIZE
V5_PREFIX_SIZE = len(MAGIC_V5) + 1
V5_HEADER_SIZE = V5_PREFIX_SIZE + EMBEDDED_SECTION_SIZE + SALT_SIZE
V5_WRAPPED_HEADER_SIZE = V5_PREFIX_SIZE + WRAPPED_SECTION_SIZE + SALT_SIZE

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ENCRYPTED_BYTES = MAX_FILE_BYTES + (2 * 1024 * 1024)

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_INVALID_FILENAME_CHARS = set('<>:"/\\|?*')

_OBFUSCATION_PAD = hashlib.sha256(
    b"cryptovault-web/v5/embedded-key-obfuscation"
).digest()


def generate_master_key() -> str:
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    raw = "".join(secrets.choice(charset) for _ in range(60))
    parts = [raw[i:i + 5] for i in range(0, 60, 5)]
    return "-".join(parts)[:MASTER_KEY_LENGTH]


def _derive_seed(master_key: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=SEED_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(master_key.encode("utf-8"))


def _derive_key(seed: bytes, info: bytes, length: int) -> bytes:
    kdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return kdf.derive(seed)


def _derive_keys_v4(master_key: str, salt: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    seed = _derive_seed(master_key, salt)
    k1 = _derive_key(seed, b"cryptovault/v4/aes-256-gcm", KEY_SIZE)
    k2 = _derive_key(seed, b"cryptovault/v4/aes-256-ocb3", KEY_SIZE)
    k3 = _derive_key(seed, b"cryptovault/v4/chacha20-poly1305", KEY_SIZE)
    kmac = _derive_key(seed, b"cryptovault/v4/hmac-sha512", HMAC_SIZE)
    return k1, k2, k3, kmac


def _derive_keys(master_key: str, salt1: bytes, salt2: bytes) -> tuple[bytes, bytes]:
    master_bytes = master_key.encode("utf-8")
    kdf1 = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt1,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    kdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt2,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    key1 = kdf1.derive(master_bytes)
    key2 = kdf2.derive(master_bytes + b"\x01")
    return key1, key2


def _encrypt_gcm(data: bytes, key: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _decrypt_gcm(data: bytes, key: bytes, aad: bytes) -> bytes:
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Datos GCM truncados.")
    return AESGCM(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], aad)


def _encrypt_ocb3(data: bytes, key: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESOCB3(key).encrypt(nonce, data, aad)


def _decrypt_ocb3(data: bytes, key: bytes, aad: bytes) -> bytes:
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Datos OCB truncados.")
    return AESOCB3(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], aad)


def _encrypt_chacha(data: bytes, key: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, data, aad)


def _decrypt_chacha(data: bytes, key: bytes, aad: bytes) -> bytes:
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Datos ChaCha20 truncados.")
    return ChaCha20Poly1305(key).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], aad)


def _encrypt_cbc(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def _decrypt_cbc(data: bytes, key: bytes) -> bytes:
    if len(data) < 16 + 16 or (len(data) - 16) % 16 != 0:
        raise ValueError("Datos CBC inválidos.")
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _compute_hmac(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def _compute_legacy_mac(data: bytes, key: bytes) -> bytes:
    h = hashlib.new("sha512")
    h.update(key)
    h.update(data)
    return h.digest()


def _obfuscate_key(master_key: bytes) -> bytes:
    pad = (_OBFUSCATION_PAD * 3)[:len(master_key)]
    return bytes(a ^ b for a, b in zip(master_key, pad))


def _wrap_master_key(master_key: str, password: str) -> bytes:
    wrap_salt = os.urandom(SALT_SIZE)
    seed = _derive_seed(password, wrap_salt)
    wrap_key = _derive_key(seed, b"cryptovault/v5/wrap-aes-256-gcm", KEY_SIZE)
    aad = MAGIC_V5 + bytes([MODE_WRAPPED])
    nonce = os.urandom(NONCE_SIZE)
    wrapped = AESGCM(wrap_key).encrypt(
        nonce, master_key.encode("utf-8"), aad
    )
    return wrap_salt + nonce + wrapped


def _unwrap_master_key(section: bytes, password: str) -> str:
    if len(section) != WRAPPED_SECTION_SIZE:
        raise ValueError("Archivo v5 inválido o truncado.")
    wrap_salt = section[:SALT_SIZE]
    nonce = section[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    wrapped = section[SALT_SIZE + NONCE_SIZE:]
    seed = _derive_seed(password, wrap_salt)
    wrap_key = _derive_key(seed, b"cryptovault/v5/wrap-aes-256-gcm", KEY_SIZE)
    aad = MAGIC_V5 + bytes([MODE_WRAPPED])
    try:
        master_key = AESGCM(wrap_key).decrypt(nonce, wrapped, aad)
    except Exception:
        raise ValueError("Contraseña incorrecta o archivo corrupto.") from None
    return master_key.decode("utf-8")


def _safe_filename(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("El nombre de archivo debe ser texto.")
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    cleaned = []
    for ch in name:
        code = ord(ch)
        if code < 32 or code == 127 or ch in _INVALID_FILENAME_CHARS:
            cleaned.append("_")
        else:
            cleaned.append(ch)
    name = "".join(cleaned).rstrip(" .")
    if not name:
        name = "archivo_recuperado"
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        name = f"_{name}"
    if len(name.encode("utf-8")) > 0xFFFF:
        raise ValueError("El nombre de archivo es demasiado largo.")
    return name


def encrypted_filename(name: str) -> str:
    return _safe_filename(name) + ".cvault"


def _build_payload(plaintext: bytes, filename: str) -> bytes:
    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 0xFFFF:
        raise ValueError("El nombre de archivo es demasiado largo.")
    return struct.pack(">H", len(fname_bytes)) + fname_bytes + plaintext


def _parse_payload(payload: bytes) -> tuple[bytes, str]:
    if len(payload) < 2:
        raise ValueError("Contenido interno inválido.")
    fname_len = int.from_bytes(payload[:2], "big")
    if 2 + fname_len > len(payload):
        raise ValueError("Contenido interno inválido.")
    try:
        filename = payload[2:2 + fname_len].decode("utf-8")
    except UnicodeDecodeError:
        filename = "archivo_recuperado"
    return payload[2 + fname_len:], _safe_filename(filename)


def encrypt_selfcontained(
    plaintext: bytes,
    original_filename: str,
    password: str | None = None,
    progress_callback=None,
) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("El contenido debe ser bytes.")
    if len(plaintext) > MAX_FILE_BYTES:
        raise ValueError("El archivo supera el límite permitido.")

    if password is not None and not password:
        raise ValueError("La contraseña no puede estar vacía.")

    master_key = generate_master_key()
    safe_name = _safe_filename(original_filename)
    if progress_callback:
        progress_callback(10)

    if password is None:
        mode = MODE_EMBEDDED
        key_section = _obfuscate_key(master_key.encode("utf-8"))
    else:
        mode = MODE_WRAPPED
        key_section = _wrap_master_key(master_key, password)
    if progress_callback:
        progress_callback(25)

    salt = os.urandom(SALT_SIZE)
    header = MAGIC_V5 + bytes([mode]) + key_section + salt
    if progress_callback:
        progress_callback(40)

    k1, k2, k3, kmac = _derive_keys_v4(master_key, salt)
    if progress_callback:
        progress_callback(55)

    payload = _build_payload(bytes(plaintext), safe_name)
    if progress_callback:
        progress_callback(70)

    layer1 = _encrypt_gcm(payload, k1, header)
    layer2 = _encrypt_ocb3(layer1, k2, header)
    layer3 = _encrypt_chacha(layer2, k3, header)
    mac = _compute_hmac(header + layer3, kmac)
    blob = header + mac + layer3

    if progress_callback:
        progress_callback(100)
    return blob


def _decrypt_v5(blob: bytes, password: str | None, progress_callback=None) -> tuple[bytes, str]:
    mode = blob[len(MAGIC_V5)]
    if mode == MODE_EMBEDDED:
        header_size = V5_HEADER_SIZE
        section_size = EMBEDDED_SECTION_SIZE
    elif mode == MODE_WRAPPED:
        header_size = V5_WRAPPED_HEADER_SIZE
        section_size = WRAPPED_SECTION_SIZE
    else:
        raise ValueError("Archivo v5 con modo desconocido.")

    min_size = header_size + HMAC_SIZE + NONCE_SIZE + TAG_SIZE
    if len(blob) < min_size:
        raise ValueError("Archivo inválido o corrupto.")

    key_section = blob[V5_PREFIX_SIZE:V5_PREFIX_SIZE + section_size]
    if mode == MODE_EMBEDDED:
        master_key = _obfuscate_key(key_section).decode("utf-8")
    else:
        if not password:
            raise ValueError("Este archivo se cifró con contraseña.")
        master_key = _unwrap_master_key(key_section, password)

    if progress_callback:
        progress_callback(45)

    header = blob[:header_size]
    salt = blob[header_size - SALT_SIZE:header_size]
    mac_stored = blob[header_size:header_size + HMAC_SIZE]
    layer3 = blob[header_size + HMAC_SIZE:]

    k1, k2, k3, kmac = _derive_keys_v4(master_key, salt)
    if progress_callback:
        progress_callback(60)

    mac_computed = _compute_hmac(header + layer3, kmac)
    if not secrets.compare_digest(mac_stored, mac_computed):
        raise ValueError("Archivo corrupto o alterado.")

    if progress_callback:
        progress_callback(80)

    try:
        layer2 = _decrypt_chacha(layer3, k3, header)
        layer1 = _decrypt_ocb3(layer2, k2, header)
        payload = _decrypt_gcm(layer1, k1, header)
        plaintext, filename = _parse_payload(payload)
    except Exception:
        raise ValueError("Archivo corrupto o alterado.") from None

    if progress_callback:
        progress_callback(100)
    return plaintext, filename


def encrypt_file(
    plaintext: bytes,
    master_key: str,
    original_filename: str,
    progress_callback=None,
) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("El contenido debe ser bytes.")
    if len(plaintext) > MAX_FILE_BYTES:
        raise ValueError("El archivo supera el límite permitido.")

    safe_name = _safe_filename(original_filename)
    if progress_callback:
        progress_callback(5)

    salt = os.urandom(SALT_SIZE)
    header = MAGIC + salt
    if progress_callback:
        progress_callback(15)

    k1, k2, k3, kmac = _derive_keys_v4(master_key, salt)
    if progress_callback:
        progress_callback(30)

    payload = _build_payload(bytes(plaintext), safe_name)
    if progress_callback:
        progress_callback(45)

    layer1 = _encrypt_gcm(payload, k1, header)
    if progress_callback:
        progress_callback(65)

    layer2 = _encrypt_ocb3(layer1, k2, header)
    if progress_callback:
        progress_callback(80)

    layer3 = _encrypt_chacha(layer2, k3, header)
    mac = _compute_hmac(header + layer3, kmac)
    blob = header + mac + layer3

    if progress_callback:
        progress_callback(100)
    return blob


def _decrypt_v4(blob: bytes, master_key: str, progress_callback=None) -> tuple[bytes, str]:
    header_size = len(MAGIC) + SALT_SIZE
    min_size = header_size + HMAC_SIZE + NONCE_SIZE + TAG_SIZE
    if len(blob) < min_size:
        raise ValueError("Archivo inválido o corrupto.")

    header = blob[:header_size]
    salt = blob[len(MAGIC):header_size]
    mac_stored = blob[header_size:header_size + HMAC_SIZE]
    layer3 = blob[header_size + HMAC_SIZE:]

    if progress_callback:
        progress_callback(25)

    k1, k2, k3, kmac = _derive_keys_v4(master_key, salt)
    if progress_callback:
        progress_callback(45)

    mac_computed = _compute_hmac(header + layer3, kmac)
    if not secrets.compare_digest(mac_stored, mac_computed):
        raise ValueError("Clave incorrecta o archivo corrupto.")

    if progress_callback:
        progress_callback(60)

    try:
        layer2 = _decrypt_chacha(layer3, k3, header)
        layer1 = _decrypt_ocb3(layer2, k2, header)
        payload = _decrypt_gcm(layer1, k1, header)
        plaintext, filename = _parse_payload(payload)
    except Exception:
        raise ValueError("Clave incorrecta o archivo corrupto.") from None

    if progress_callback:
        progress_callback(100)
    return plaintext, filename


def _decrypt_v3(blob: bytes, master_key: str, progress_callback=None) -> tuple[bytes, str]:
    header_size = len(MAGIC_V3) + SALT_SIZE * 2
    min_size = header_size + HMAC_SIZE + 16 + 16
    if len(blob) < min_size:
        raise ValueError("Archivo inválido o corrupto.")

    header = blob[:header_size]
    salt1 = blob[len(MAGIC_V3):len(MAGIC_V3) + SALT_SIZE]
    salt2 = blob[len(MAGIC_V3) + SALT_SIZE:header_size]
    mac_stored = blob[header_size:header_size + HMAC_SIZE]
    layer2 = blob[header_size + HMAC_SIZE:]

    if progress_callback:
        progress_callback(25)

    key1, key2 = _derive_keys(master_key, salt1, salt2)
    if progress_callback:
        progress_callback(45)

    integrity_key = bytes(a ^ b for a, b in zip(key1, key2))
    mac_computed = _compute_hmac(header + layer2, integrity_key)
    if not secrets.compare_digest(mac_stored, mac_computed):
        raise ValueError("Clave incorrecta o archivo corrupto.")

    if progress_callback:
        progress_callback(60)

    try:
        layer1 = _decrypt_cbc(layer2, key2)
        payload = _decrypt_gcm(layer1, key1, header)
        plaintext, filename = _parse_payload(payload)
    except Exception:
        raise ValueError("Clave incorrecta o archivo corrupto.") from None

    if progress_callback:
        progress_callback(100)
    return plaintext, filename


def _decrypt_v2(blob: bytes, master_key: str, progress_callback=None) -> tuple[bytes, str]:
    header_size = len(MAGIC_V2) + SALT_SIZE * 2
    if len(blob) < header_size + 2 + HMAC_SIZE:
        raise ValueError("Archivo v2 inválido o truncado.")

    salt1 = blob[len(MAGIC_V2):len(MAGIC_V2) + SALT_SIZE]
    salt2 = blob[len(MAGIC_V2) + SALT_SIZE:header_size]
    fname_len = int.from_bytes(blob[header_size:header_size + 2], "big")
    mac_start = header_size + 2 + fname_len
    if mac_start + HMAC_SIZE > len(blob):
        raise ValueError("Archivo v2 inválido o truncado.")

    mac_stored = blob[mac_start:mac_start + HMAC_SIZE]
    layer2 = blob[mac_start + HMAC_SIZE:]

    if progress_callback:
        progress_callback(25)

    key1, key2 = _derive_keys(master_key, salt1, salt2)
    if progress_callback:
        progress_callback(45)

    integrity_key = bytes(a ^ b for a, b in zip(key1, key2))
    mac_computed = _compute_legacy_mac(layer2, integrity_key)
    if not secrets.compare_digest(mac_stored, mac_computed):
        raise ValueError("Clave incorrecta o archivo corrupto.")

    if progress_callback:
        progress_callback(60)

    try:
        layer1 = _decrypt_cbc(layer2, key2)
        payload = _decrypt_gcm(layer1, key1, None)
        plaintext, filename = _parse_payload(payload)
    except Exception:
        raise ValueError("Clave incorrecta o archivo corrupto.") from None

    if progress_callback:
        progress_callback(100)
    return plaintext, filename


def inspect_blob(blob: bytes) -> dict:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("El contenido debe ser bytes.")
    if blob.startswith(MAGIC_V5):
        mode = blob[len(MAGIC_V5)]
        if mode not in (MODE_EMBEDDED, MODE_WRAPPED):
            raise ValueError("Archivo v5 con modo desconocido.")
        return {
            "version": 5,
            "has_embedded_key": True,
            "needs_password": mode == MODE_WRAPPED,
            "needs_master_key": False,
        }
    if blob.startswith(MAGIC):
        return {
            "version": 4,
            "has_embedded_key": False,
            "needs_password": False,
            "needs_master_key": True,
        }
    if blob.startswith(MAGIC_V3):
        return {
            "version": 3,
            "has_embedded_key": False,
            "needs_password": False,
            "needs_master_key": True,
        }
    if blob.startswith(MAGIC_V2):
        return {
            "version": 2,
            "has_embedded_key": False,
            "needs_password": False,
            "needs_master_key": True,
        }
    return {
        "version": 0,
        "has_embedded_key": False,
        "needs_password": False,
        "needs_master_key": False,
    }


def decrypt_file(
    blob: bytes,
    master_key: str | None = None,
    password: str | None = None,
    progress_callback=None,
) -> tuple[bytes, str]:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("El contenido debe ser bytes.")
    if len(blob) > MAX_ENCRYPTED_BYTES:
        raise ValueError("El archivo supera el límite permitido.")

    if blob.startswith(MAGIC_V5):
        return _decrypt_v5(blob, password, progress_callback)
    if blob.startswith(MAGIC):
        if not master_key:
            raise ValueError(
                "Este archivo se cifró con el CryptoVault de escritorio: "
                "necesita la master key."
            )
        return _decrypt_v4(blob, master_key, progress_callback)
    if blob.startswith(MAGIC_V3):
        if not master_key:
            raise ValueError(
                "Este archivo se cifró con el CryptoVault de escritorio: "
                "necesita la master key."
            )
        return _decrypt_v3(blob, master_key, progress_callback)
    if blob.startswith(MAGIC_V2):
        if not master_key:
            raise ValueError(
                "Este archivo se cifró con el CryptoVault de escritorio: "
                "necesita la master key."
            )
        return _decrypt_v2(blob, master_key, progress_callback)
    raise ValueError("Archivo inválido o no cifrado con CryptoVault.")

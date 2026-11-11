import os
import struct
import unittest
from unittest import mock

import engine as ce


class SelfContainedV5Tests(unittest.TestCase):
    def setUp(self):
        self.plaintext = b"contenido secreto del usuario" * 40
        self.name = "documento.pdf"

    def test_roundtrip_without_password(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name)
        self.assertTrue(blob.startswith(ce.MAGIC_V5))
        plain, filename = ce.decrypt_file(blob)
        self.assertEqual(plain, self.plaintext)
        self.assertEqual(filename, self.name)

    def test_roundtrip_with_password(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name, "clave-s3creta")
        plain, filename = ce.decrypt_file(blob, password="clave-s3creta")
        self.assertEqual(plain, self.plaintext)
        self.assertEqual(filename, self.name)

    def test_master_key_is_69_chars(self):
        key = ce.generate_master_key()
        self.assertEqual(len(key), ce.MASTER_KEY_LENGTH)

    def test_embedded_key_is_not_plainly_visible(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name)
        self.assertNotIn(b"CVLT", blob[len(ce.MAGIC_V5):len(ce.MAGIC_V5) + 2])

    def test_wrapped_file_requires_password(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name, "clave-s3creta")
        with self.assertRaises(ValueError):
            ce.decrypt_file(blob)

    def test_wrong_password_is_rejected(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name, "clave-s3creta")
        with self.assertRaises(ValueError):
            ce.decrypt_file(blob, password="otra-clave")

    def test_tampered_key_section_is_rejected(self):
        blob = bytearray(ce.encrypt_selfcontained(self.plaintext, self.name))
        blob[ce.V5_PREFIX_SIZE] ^= 0x01
        with self.assertRaises(ValueError):
            ce.decrypt_file(bytes(blob))

    def test_tampered_hmac_is_rejected(self):
        blob = bytearray(ce.encrypt_selfcontained(self.plaintext, self.name))
        blob[ce.V5_HEADER_SIZE + 5] ^= 0x01
        with self.assertRaises(ValueError):
            ce.decrypt_file(bytes(blob))

    def test_tampered_ciphertext_is_rejected(self):
        blob = bytearray(ce.encrypt_selfcontained(self.plaintext, self.name))
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            ce.decrypt_file(bytes(blob))

    def test_truncated_file_is_rejected(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name)
        with self.assertRaises(ValueError):
            ce.decrypt_file(blob[: ce.V5_HEADER_SIZE + 10])

    def test_oversized_plaintext_is_rejected(self):
        with mock.patch.object(ce, "MAX_FILE_BYTES", 10):
            with self.assertRaises(ValueError):
                ce.encrypt_selfcontained(b"x" * 11, "a.txt")

    def test_empty_password_is_rejected(self):
        with self.assertRaises(ValueError):
            ce.encrypt_selfcontained(self.plaintext, self.name, "")

    def test_inspect_v5_without_password(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name)
        info = ce.inspect_blob(blob)
        self.assertEqual(info["version"], 5)
        self.assertTrue(info["has_embedded_key"])
        self.assertFalse(info["needs_password"])
        self.assertFalse(info["needs_master_key"])

    def test_inspect_v5_with_password(self):
        blob = ce.encrypt_selfcontained(self.plaintext, self.name, "clave-s3creta")
        info = ce.inspect_blob(blob)
        self.assertEqual(info["version"], 5)
        self.assertTrue(info["needs_password"])

    def test_inspect_unknown_blob(self):
        self.assertEqual(ce.inspect_blob(b"DATOS-ALEATORIOS")["version"], 0)


class DesktopCompatTests(unittest.TestCase):
    def setUp(self):
        self.master_key = ce.generate_master_key()
        self.plaintext = b"archivo cifrado con el desktop"

    def test_desktop_v4_blob_decrypts_with_master_key(self):
        blob = ce.encrypt_file(self.plaintext, self.master_key, "informe.docx")
        info = ce.inspect_blob(blob)
        self.assertEqual(info["version"], 4)
        self.assertTrue(info["needs_master_key"])
        plain, filename = ce.decrypt_file(blob, master_key=self.master_key)
        self.assertEqual(plain, self.plaintext)
        self.assertEqual(filename, "informe.docx")

    def test_desktop_v4_blob_without_key_is_rejected(self):
        blob = ce.encrypt_file(self.plaintext, self.master_key, "informe.docx")
        with self.assertRaises(ValueError):
            ce.decrypt_file(blob)

    def test_encrypted_filename_suffix(self):
        self.assertEqual(
            ce.encrypted_filename("../../notas.txt"), "notas.txt.cvault"
        )


class LegacyV3Tests(unittest.TestCase):
    def setUp(self):
        self.key = ce.generate_master_key()
        self.plaintext = b"legacy v3 payload"

    def _build_v3(self, inner_name):
        salt1 = os.urandom(ce.SALT_SIZE)
        salt2 = os.urandom(ce.SALT_SIZE)
        key1, key2 = ce._derive_keys(self.key, salt1, salt2)
        payload = (
            struct.pack(">H", len(inner_name.encode("utf-8")))
            + inner_name.encode("utf-8")
            + self.plaintext
        )
        header = ce.MAGIC_V3 + salt1 + salt2
        layer1 = ce._encrypt_gcm(payload, key1, header)
        layer2 = ce._encrypt_cbc(layer1, key2)
        integrity_key = bytes(a ^ b for a, b in zip(key1, key2))
        mac = ce._compute_hmac(header + layer2, integrity_key)
        return header + mac + layer2

    def test_legacy_v3_decrypt(self):
        blob = self._build_v3("original.txt")
        plain, name = ce.decrypt_file(blob, master_key=self.key)
        self.assertEqual(plain, self.plaintext)
        self.assertEqual(name, "original.txt")

    def test_legacy_v3_wrong_key_is_rejected(self):
        blob = self._build_v3("a.txt")
        with self.assertRaises(ValueError):
            ce.decrypt_file(blob, master_key=ce.generate_master_key())


class LegacyV2Tests(unittest.TestCase):
    def setUp(self):
        self.key = ce.generate_master_key()
        self.plaintext = b"legacy payload"

    def test_legacy_v2_decrypt(self):
        salt1 = os.urandom(ce.SALT_SIZE)
        salt2 = os.urandom(ce.SALT_SIZE)
        key1, key2 = ce._derive_keys(self.key, salt1, salt2)
        inner_name = "original.txt"
        outer_name = b"a.txt"
        payload = (
            struct.pack(">H", len(inner_name.encode("utf-8")))
            + inner_name.encode("utf-8")
            + self.plaintext
        )
        layer1 = ce._encrypt_gcm(payload, key1, None)
        layer2 = ce._encrypt_cbc(layer1, key2)
        integrity_key = bytes(a ^ b for a, b in zip(key1, key2))
        mac = ce._compute_legacy_mac(layer2, integrity_key)
        blob = (
            ce.MAGIC_V2
            + salt1
            + salt2
            + struct.pack(">H", len(outer_name))
            + outer_name
            + mac
            + layer2
        )
        plain, name = ce.decrypt_file(blob, master_key=self.key)
        self.assertEqual(plain, self.plaintext)
        self.assertEqual(name, inner_name)


if __name__ == "__main__":
    unittest.main()

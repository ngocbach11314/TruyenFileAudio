import os
import hashlib
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_key_pair(self):
        """Tạo cặp khóa RSA 2048-bit"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def serialize_public_key(self, public_key):
        """Chuyển public key thành bytes"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_public_key(self, key_bytes):
        """Chuyển bytes thành public key"""
        return serialization.load_pem_public_key(key_bytes, backend=self.backend)
    
    def serialize_private_key(self, private_key):
        """Chuyển private key thành bytes"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def deserialize_private_key(self, key_bytes):
        """Chuyển bytes thành private key"""
        return serialization.load_pem_private_key(key_bytes, backend=self.backend)
    
    def generate_session_key(self):
        """Tạo SessionKey cho Triple DES (24 bytes)"""
        return os.urandom(24)
    
    def encrypt_triple_des(self, data, key, iv=None):
        """Mã hóa Triple DES"""
        if iv is None:
            iv = os.urandom(8)  # IV cho DES
        
        # Đảm bảo key có đúng 24 bytes cho Triple DES
        if len(key) != 24:
            key = key[:24].ljust(24, b'\x00')
        
        cipher = Cipher(
            algorithms.TripleDES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Padding dữ liệu
        padded_data = self._pad_data(data)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt_triple_des(self, ciphertext, key, iv):
        """Giải mã Triple DES"""
        cipher = Cipher(
            algorithms.TripleDES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return self._unpad_data(padded_data)
    
    def _pad_data(self, data):
        """Padding dữ liệu theo PKCS7"""
        block_size = 8  # DES block size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data):
        """Unpadding dữ liệu theo PKCS7"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def hash_sha512(self, data):
        """Tạo hash SHA-512"""
        return hashlib.sha512(data).digest()
    
    def sign_rsa(self, data, private_key):
        """Ký số RSA"""
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_rsa(self, data, signature, public_key):
        """Xác thực chữ ký RSA"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def encrypt_rsa(self, data, public_key):
        """Mã hóa RSA"""
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt_rsa(self, ciphertext, private_key):
        """Giải mã RSA"""
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def encode_packet(self, data):
        """Mã hóa packet để gửi qua socket"""
        return base64.b64encode(data)
    
    def decode_packet(self, encoded_data):
        """Giải mã packet nhận từ socket"""
        return base64.b64decode(encoded_data) 
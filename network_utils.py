import socket
import json
import struct
import time
from crypto_utils import CryptoUtils

class NetworkUtils:
    def __init__(self):
        self.crypto = CryptoUtils()
        self.buffer_size = 4096
    
    def send_message(self, sock, message, encoding='utf-8'):
        """Gửi message qua socket"""
        if isinstance(message, str):
            message = message.encode(encoding)
        
        # Gửi độ dài message trước
        length = len(message)
        sock.send(struct.pack('!I', length))
        
        # Gửi message
        sock.send(message)
    
    def receive_message(self, sock, encoding='utf-8'):
        """Nhận message từ socket"""
        # Nhận độ dài message
        length_data = sock.recv(4)
        if not length_data:
            return None
        
        length = struct.unpack('!I', length_data)[0]
        
        # Nhận message
        message = b''
        while len(message) < length:
            chunk = sock.recv(min(self.buffer_size, length - len(message)))
            if not chunk:
                break
            message += chunk
        
        if encoding:
            return message.decode(encoding)
        return message
    
    def send_data_packet(self, sock, data):
        """Gửi packet dữ liệu được mã hóa base64"""
        encoded_data = self.crypto.encode_packet(data)
        self.send_message(sock, encoded_data, encoding=None)
    
    def receive_data_packet(self, sock):
        """Nhận packet dữ liệu và giải mã base64"""
        encoded_data = self.receive_message(sock, encoding=None)
        if encoded_data:
            return self.crypto.decode_packet(encoded_data)
        return None
    
    def send_json(self, sock, data):
        """Gửi dữ liệu JSON"""
        json_str = json.dumps(data, ensure_ascii=False)
        self.send_message(sock, json_str)
    
    def receive_json(self, sock):
        """Nhận dữ liệu JSON"""
        json_str = self.receive_message(sock)
        if json_str:
            return json.loads(json_str)
        return None
    
    def handshake_client(self, sock):
        """Handshake từ phía client"""
        print("🔄 Bắt đầu handshake...")
        
        # Gửi "Hello!"
        self.send_message(sock, "Hello!")
        print("📤 Gửi: Hello!")
        
        # Nhận "Ready!"
        response = self.receive_message(sock)
        if response == "Ready!":
            print("📥 Nhận: Ready!")
            print("✅ Handshake thành công!")
            return True
        else:
            print(f"❌ Handshake thất bại! Nhận: {response}")
            return False
    
    def handshake_server(self, sock):
        """Handshake từ phía server"""
        print("🔄 Chờ handshake từ client...")
        
        # Nhận "Hello!"
        message = self.receive_message(sock)
        if message == "Hello!":
            print("📥 Nhận: Hello!")
            
            # Gửi "Ready!"
            self.send_message(sock, "Ready!")
            print("📤 Gửi: Ready!")
            print("✅ Handshake thành công!")
            return True
        else:
            print(f"❌ Handshake thất bại! Nhận: {message}")
            return False
    
    def send_metadata(self, sock, metadata, signature):
        """Gửi metadata và chữ ký số"""
        print("📤 Gửi metadata và chữ ký số...")
        
        # Gửi metadata
        self.send_json(sock, metadata)
        
        # Gửi chữ ký số
        self.send_data_packet(sock, signature)
        
        print("✅ Đã gửi metadata và chữ ký số")
    
    def receive_metadata(self, sock):
        """Nhận metadata và chữ ký số"""
        print("📥 Nhận metadata và chữ ký số...")
        
        # Nhận metadata
        metadata = self.receive_json(sock)
        
        # Nhận chữ ký số
        signature = self.receive_data_packet(sock)
        
        print("✅ Đã nhận metadata và chữ ký số")
        return metadata, signature
    
    def send_session_key(self, sock, session_key, server_public_key):
        """Gửi SessionKey được mã hóa RSA"""
        print("📤 Gửi SessionKey được mã hóa...")
        
        # Mã hóa SessionKey bằng RSA
        encrypted_session_key = self.crypto.encrypt_rsa(session_key, server_public_key)
        
        # Gửi SessionKey đã mã hóa
        self.send_data_packet(sock, encrypted_session_key)
        
        print("✅ Đã gửi SessionKey")
    
    def receive_session_key(self, sock, private_key):
        """Nhận và giải mã SessionKey"""
        print("📥 Nhận SessionKey...")
        
        # Nhận SessionKey đã mã hóa
        encrypted_session_key = self.receive_data_packet(sock)
        
        # Giải mã SessionKey
        session_key = self.crypto.decrypt_rsa(encrypted_session_key, private_key)
        
        print("✅ Đã nhận và giải mã SessionKey")
        return session_key
    
    def send_chunk(self, sock, chunk_data, session_key, private_key):
        """Gửi một chunk với mã hóa và chữ ký"""
        # Mã hóa chunk bằng Triple DES
        iv, ciphertext = self.crypto.encrypt_triple_des(chunk_data, session_key)
        
        # Tạo hash SHA-512
        chunk_hash = self.crypto.hash_sha512(chunk_data)
        
        # Ký số hash
        signature = self.crypto.sign_rsa(chunk_hash, private_key)
        
        # Gửi IV, ciphertext, hash, signature
        self.send_data_packet(sock, iv)
        self.send_data_packet(sock, ciphertext)
        self.send_data_packet(sock, chunk_hash)
        self.send_data_packet(sock, signature)
    
    def receive_chunk(self, sock, session_key, sender_public_key):
        """Nhận và xử lý một chunk"""
        # Nhận IV, ciphertext, hash, signature
        iv = self.receive_data_packet(sock)
        ciphertext = self.receive_data_packet(sock)
        chunk_hash = self.receive_data_packet(sock)
        signature = self.receive_data_packet(sock)
        
        # Xác thực chữ ký
        if not self.crypto.verify_rsa(chunk_hash, signature, sender_public_key):
            print("❌ Chữ ký không hợp lệ!")
            return None, chunk_hash, signature
        
        # Giải mã chunk
        chunk_data = self.crypto.decrypt_triple_des(ciphertext, session_key, iv)
        
        # Kiểm tra hash
        calculated_hash = self.crypto.hash_sha512(chunk_data)
        if calculated_hash != chunk_hash:
            print("❌ Hash không khớp!")
            return None, chunk_hash, signature
        
        return chunk_data, chunk_hash, signature
    
    def send_ack(self, sock):
        """Gửi ACK"""
        self.send_message(sock, "ACK")
        print("📤 Gửi: ACK")
    
    def send_nack(self, sock):
        """Gửi NACK"""
        self.send_message(sock, "NACK")
        print("📤 Gửi: NACK")
    
    def receive_response(self, sock):
        """Nhận ACK/NACK"""
        response = self.receive_message(sock)
        if response == "ACK":
            print("📥 Nhận: ACK")
            return True
        elif response == "NACK":
            print("📥 Nhận: NACK")
            return False
        else:
            print(f"❌ Phản hồi không hợp lệ: {response}")
            return False
    
    def create_server_socket(self, host='localhost', port=12345):
        """Tạo server socket"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"🚀 Server đang lắng nghe tại {host}:{port}")
        return server_socket
    
    def create_client_socket(self, host='localhost', port=12345):
        """Tạo client socket"""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        print(f"🔗 Đã kết nối đến server {host}:{port}")
        return client_socket 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
from crypto_utils import CryptoUtils
from file_utils import FileUtils
from network_utils import NetworkUtils

class SecureAudioClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.crypto = CryptoUtils()
        self.file_utils = FileUtils()
        self.network = NetworkUtils()
        
        # Tạo cặp khóa RSA cho client
        print("🔑 Tạo cặp khóa RSA cho client...")
        self.private_key, self.public_key = self.crypto.generate_rsa_key_pair()
        print("✅ Đã tạo cặp khóa RSA 2048-bit")
    
    def send_file(self, file_path):
        """Gửi file âm thanh an toàn"""
        print("🎵 === CLIENT GỬI FILE ÂM THANH AN TOÀN ===")
        
        # Kiểm tra file
        if not os.path.exists(file_path):
            print(f"❌ File {file_path} không tồn tại!")
            return False
        
        if not self.file_utils.is_audio_file(file_path):
            print(f"⚠️  Cảnh báo: {file_path} có thể không phải file âm thanh")
        
        try:
            # Kết nối đến server
            print(f"🔗 Kết nối đến server {self.host}:{self.port}...")
            client_socket = self.network.create_client_socket(self.host, self.port)
            
            try:
                # 1. Handshake
                if not self.network.handshake_client(client_socket):
                    print("❌ Handshake thất bại!")
                    return False
                
                # Sau handshake, gửi public key của client cho server
                client_public_key_bytes = self.crypto.serialize_public_key(self.public_key)
                self.network.send_data_packet(client_socket, client_public_key_bytes)
                
                # 2. Chuẩn bị file
                print(f"\n📁 Chuẩn bị file: {file_path}")
                file_info = self.file_utils.get_file_info(file_path)
                print(f"   Kích thước: {self.file_utils.format_file_size(file_info['size'])}")
                
                # Chia file thành 3 chunk
                print("✂️  Chia file thành 3 chunk...")
                chunks = self.file_utils.split_file(file_path, 3)
                for i, chunk in enumerate(chunks):
                    print(f"   Chunk {i+1}: {self.file_utils.format_file_size(len(chunk))}")
                
                # 3. Tạo metadata và chữ ký số
                print("\n📋 Tạo metadata...")
                metadata = self.file_utils.create_metadata(file_path)
                metadata_bytes = str(metadata).encode('utf-8')
                metadata_signature = self.crypto.sign_rsa(metadata_bytes, self.private_key)
                
                # Gửi metadata (JSON)
                self.network.send_json(client_socket, metadata)
                # Gửi chữ ký số (base64)
                self.network.send_data_packet(client_socket, metadata_signature)
                
                # 4. Tạo và gửi SessionKey
                print("\n🔑 Tạo SessionKey...")
                session_key = self.crypto.generate_session_key()
                print(f"   SessionKey: {session_key.hex()[:16]}...")
                
                # Lấy public key của server từ file
                with open("server_public_key.pem", "rb") as f:
                    server_public_key = self.crypto.deserialize_public_key(f.read())
                
                self.network.send_session_key(client_socket, session_key, server_public_key)
                
                # 5. Gửi các chunk
                print(f"\n📤 Gửi {len(chunks)} chunk...")
                for i, chunk in enumerate(chunks):
                    print(f"   Đang gửi chunk {i+1}/{len(chunks)}...")
                    # Tạo hash và chữ ký để in ra
                    chunk_hash = self.crypto.hash_sha512(chunk)
                    signature = self.crypto.sign_rsa(chunk_hash, self.private_key)
                    print(f"      Chunk size: {len(chunk)} bytes, hash: {chunk_hash.hex()[:16]}..., sig: {signature.hex()[:16]}...")
                    self.network.send_chunk(client_socket, chunk, session_key, self.private_key)
                    print(f"   ✅ Đã gửi chunk {i+1}")
                
                # 6. Nhận phản hồi từ server
                print("\n⏳ Chờ phản hồi từ server...")
                response = self.network.receive_response(client_socket)
                
                if response:
                    print("🎉 Gửi file thành công!")
                    return True
                else:
                    print("❌ Gửi file thất bại!")
                    return False
            
            finally:
                client_socket.close()
                print("🔌 Đã đóng kết nối")
        
        except Exception as e:
            print(f"❌ Lỗi gửi file: {e}")
            return False
    
    def test_connection(self):
        """Test kết nối đến server"""
        print("🧪 Test kết nối đến server...")
        
        try:
            client_socket = self.network.create_client_socket(self.host, self.port)
            
            if self.network.handshake_client(client_socket):
                print("✅ Kết nối thành công!")
                client_socket.close()
                return True
            else:
                print("❌ Kết nối thất bại!")
                client_socket.close()
                return False
        
        except Exception as e:
            print(f"❌ Lỗi kết nối: {e}")
            return False

def main():
    """Hàm main"""
    parser = argparse.ArgumentParser(description='Client gửi file âm thanh an toàn')
    parser.add_argument('file_path', help='Đường dẫn đến file âm thanh cần gửi')
    parser.add_argument('--host', default='localhost', help='Địa chỉ server (mặc định: localhost)')
    parser.add_argument('--port', type=int, default=12345, help='Cổng server (mặc định: 12345)')
    parser.add_argument('--test', action='store_true', help='Chỉ test kết nối')
    
    args = parser.parse_args()
    
    # Tạo client
    client = SecureAudioClient(args.host, args.port)
    
    if args.test:
        # Chỉ test kết nối
        client.test_connection()
    else:
        # Gửi file
        success = client.send_file(args.file_path)
        if success:
            print("\n🎊 Hoàn thành!")
        else:
            print("\n💥 Thất bại!")
            sys.exit(1)

if __name__ == "__main__":
    main() 
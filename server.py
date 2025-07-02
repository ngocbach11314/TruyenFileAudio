#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from crypto_utils import CryptoUtils
from file_utils import FileUtils
from network_utils import NetworkUtils

class SecureAudioServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.crypto = CryptoUtils()
        self.file_utils = FileUtils()
        self.network = NetworkUtils()
        
        # Tạo cặp khóa RSA cho server
        print("🔑 Tạo cặp khóa RSA cho server...")
        self.private_key, self.public_key = self.crypto.generate_rsa_key_pair()
        print("✅ Đã tạo cặp khóa RSA 2048-bit")
        # Lưu public key của server ra file để client sử dụng
        with open("server_public_key.pem", "wb") as f:
            f.write(self.crypto.serialize_public_key(self.public_key))
    
    def start(self):
        """Khởi động server"""
        print("🎵 === SERVER NHẬN FILE ÂM THANH AN TOÀN ===")
        print(f"📍 Địa chỉ: {self.host}:{self.port}")
        
        try:
            # Tạo server socket
            server_socket = self.network.create_server_socket(self.host, self.port)
            
            while True:
                print("\n" + "="*50)
                print("⏳ Chờ kết nối từ client...")
                
                # Chấp nhận kết nối
                client_socket, client_address = server_socket.accept()
                print(f"✅ Client {client_address} đã kết nối")
                
                try:
                    # Xử lý phiên làm việc với client
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"❌ Lỗi xử lý client: {e}")
                finally:
                    client_socket.close()
                    print(f"🔌 Đã đóng kết nối với {client_address}")
        
        except KeyboardInterrupt:
            print("\n🛑 Server đã dừng")
        except Exception as e:
            print(f"❌ Lỗi server: {e}")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket):
        """Xử lý phiên làm việc với client"""
        print("\n🔄 Bắt đầu phiên làm việc...")
        
        try:
            # 1. Handshake
            if not self.network.handshake_server(client_socket):
                print("❌ Handshake thất bại!")
                return
            
            # 2. Nhận metadata và chữ ký số
            client_public_key_bytes = self.network.receive_data_packet(client_socket)
            client_public_key = self.crypto.deserialize_public_key(client_public_key_bytes)
            
            metadata = self.network.receive_json(client_socket)
            metadata_signature = self.network.receive_data_packet(client_socket)
            
            # Hiển thị thông tin metadata
            print(f"\n📋 Thông tin file:")
            print(f"   Tên file: {metadata['file_name']}")
            print(f"   Kích thước: {self.file_utils.format_file_size(metadata['file_size'])}")
            print(f"   Số chunk: {metadata['num_chunks']}")
            print(f"   Session ID: {metadata['session_id']}")
            print(f"   Thời gian: {self.file_utils.format_timestamp(metadata['timestamp'])}")
            
            # 3. Nhận SessionKey
            session_key = self.network.receive_session_key(client_socket, self.private_key)
            print(f"🔑 SessionKey: {session_key.hex()[:16]}...")
            
            # 4. Nhận và xử lý các chunk
            chunks = []
            success = True
            
            for i in range(metadata['num_chunks']):
                print(f"\n📦 Đang nhận chunk {i+1}/{metadata['num_chunks']}...")
                
                chunk_data, chunk_hash, signature = self.network.receive_chunk(
                    client_socket, 
                    session_key, 
                    client_public_key
                )
                if chunk_data is not None:
                    print(f"      Chunk size: {len(chunk_data)} bytes, hash: {chunk_hash.hex()[:16]}..., sig: {signature.hex()[:16]}...")
                    chunks.append(chunk_data)
                    print(f"✅ Đã nhận chunk {i+1}: {self.file_utils.format_file_size(len(chunk_data))}")
                else:
                    print(f"❌ Lỗi nhận chunk {i+1}")
                    success = False
                    break
            
            # 5. Ghép file và lưu
            if success and len(chunks) == metadata['num_chunks']:
                print(f"\n🔧 Ghép {len(chunks)} chunk...")
                combined_data = self.file_utils.combine_chunks(chunks)
                
                # Tạo tên file output
                output_filename = self.file_utils.create_output_filename(
                    metadata['file_name'], 
                    f"received_{int(time.time())}"
                )
                
                # Lưu file
                self.file_utils.write_file(output_filename, combined_data)
                
                print(f"💾 Đã lưu file: {output_filename}")
                print(f"📊 Kích thước file gốc: {self.file_utils.format_file_size(metadata['file_size'])}")
                print(f"📊 Kích thước file nhận: {self.file_utils.format_file_size(len(combined_data))}")
                
                # Kiểm tra toàn vẹn
                if len(combined_data) == metadata['file_size']:
                    print("✅ File nhận thành công và toàn vẹn!")
                    self.network.send_ack(client_socket)
                else:
                    print("❌ Kích thước file không khớp!")
                    self.network.send_nack(client_socket)
            else:
                print("❌ Có lỗi trong quá trình nhận file!")
                self.network.send_nack(client_socket)
        
        except Exception as e:
            print(f"❌ Lỗi xử lý: {e}")
            self.network.send_nack(client_socket)

def main():
    """Hàm main"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Server nhận file âm thanh an toàn')
    parser.add_argument('--host', default='localhost', help='Địa chỉ host (mặc định: localhost)')
    parser.add_argument('--port', type=int, default=12345, help='Cổng (mặc định: 12345)')
    
    args = parser.parse_args()
    
    # Tạo và khởi động server
    server = SecureAudioServer(args.host, args.port)
    server.start()

if __name__ == "__main__":
    main() 
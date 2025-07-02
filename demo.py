#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import subprocess
import threading
from file_utils import FileUtils

def create_test_file(filename="test_recording.mp3", size_mb=1):
    """Tạo file test với kích thước chỉ định"""
    print(f"📝 Tạo file test: {filename} ({size_mb}MB)")
    
    # Tạo dữ liệu test (giả lập file MP3)
    test_data = b'ID3' + b'\x00' * 100  # Header MP3 giả
    test_data += b'TEST_AUDIO_DATA' * (size_mb * 1024 * 1024 // 15)  # Dữ liệu test
    
    with open(filename, 'wb') as f:
        f.write(test_data)
    
    print(f"✅ Đã tạo file test: {filename}")
    return filename

def run_server():
    """Chạy server trong thread riêng"""
    print("🚀 Khởi động server...")
    subprocess.run([sys.executable, "server.py"], check=True)

def run_client(file_path):
    """Chạy client để gửi file"""
    print("📤 Khởi động client...")
    subprocess.run([sys.executable, "client.py", file_path], check=True)

def main():
    """Hàm main cho demo"""
    print("🎵 === DEMO HỆ THỐNG GỬI FILE ÂM THANH AN TOÀN ===")
    
    # Tạo file test
    test_file = create_test_file("test_recording.mp3", 1)  # 1MB
    
    try:
        # Khởi động server trong thread riêng
        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        
        # Đợi server khởi động
        time.sleep(2)
        
        # Chạy client
        run_client(test_file)
        
        print("\n🎊 Demo hoàn thành!")
        
        # Kiểm tra file output
        file_utils = FileUtils()
        if os.path.exists("test_recording_received_*.mp3"):
            print("✅ File đã được nhận thành công!")
        else:
            print("❌ Không tìm thấy file output!")
    
    except KeyboardInterrupt:
        print("\n🛑 Demo bị dừng")
    except Exception as e:
        print(f"❌ Lỗi demo: {e}")
    finally:
        # Dọn dẹp
        if os.path.exists(test_file):
            os.remove(test_file)
            print(f"🧹 Đã xóa file test: {test_file}")

if __name__ == "__main__":
    import sys
    main() 
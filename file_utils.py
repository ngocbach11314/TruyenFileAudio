import os
import json
import time
from datetime import datetime

class FileUtils:
    def __init__(self):
        pass
    
    def get_file_info(self, file_path):
        """Lấy thông tin file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} không tồn tại")
        
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        creation_time = os.path.getctime(file_path)
        modification_time = os.path.getmtime(file_path)
        
        return {
            'name': file_name,
            'size': file_size,
            'creation_time': creation_time,
            'modification_time': modification_time,
            'path': file_path
        }
    
    def read_file(self, file_path):
        """Đọc file thành bytes"""
        with open(file_path, 'rb') as f:
            return f.read()
    
    def write_file(self, file_path, data):
        """Ghi bytes vào file"""
        with open(file_path, 'wb') as f:
            f.write(data)
    
    def split_file(self, file_path, num_chunks=3):
        """Chia file thành các đoạn nhỏ"""
        file_data = self.read_file(file_path)
        file_size = len(file_data)
        chunk_size = file_size // num_chunks
        
        chunks = []
        for i in range(num_chunks):
            start = i * chunk_size
            if i == num_chunks - 1:  # Đoạn cuối lấy hết phần còn lại
                end = file_size
            else:
                end = start + chunk_size
            
            chunk = file_data[start:end]
            chunks.append(chunk)
        
        return chunks
    
    def combine_chunks(self, chunks):
        """Ghép các đoạn file lại"""
        return b''.join(chunks)
    
    def create_metadata(self, file_path, session_id=None):
        """Tạo metadata cho file"""
        file_info = self.get_file_info(file_path)
        
        if session_id is None:
            session_id = f"session_{int(time.time())}"
        
        metadata = {
            'session_id': session_id,
            'file_name': file_info['name'],
            'file_size': file_info['size'],
            'creation_time': file_info['creation_time'],
            'modification_time': file_info['modification_time'],
            'timestamp': time.time(),
            'num_chunks': 3,
            'version': '1.0'
        }
        
        return metadata
    
    def save_metadata(self, metadata, output_path):
        """Lưu metadata vào file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    def load_metadata(self, metadata_path):
        """Đọc metadata từ file"""
        with open(metadata_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_file_extension(self, file_path):
        """Lấy phần mở rộng của file"""
        return os.path.splitext(file_path)[1].lower()
    
    def is_audio_file(self, file_path):
        """Kiểm tra có phải file âm thanh không"""
        audio_extensions = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a']
        return self.get_file_extension(file_path) in audio_extensions
    
    def create_output_filename(self, original_path, suffix=""):
        """Tạo tên file output"""
        base_name = os.path.splitext(original_path)[0]
        extension = os.path.splitext(original_path)[1]
        
        if suffix:
            return f"{base_name}_{suffix}{extension}"
        else:
            return f"{base_name}_output{extension}"
    
    def format_file_size(self, size_bytes):
        """Format kích thước file để hiển thị"""
        if size_bytes == 0:
            return "0B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.2f} {size_names[i]}"
    
    def format_timestamp(self, timestamp):
        """Format timestamp để hiển thị"""
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') 
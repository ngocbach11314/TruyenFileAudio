# Mô phỏng Gửi File Âm Thanh An Toàn

Dự án mô phỏng gửi file âm thanh an toàn qua mạng không ổn định với các tính năng bảo mật:

## Tính năng chính:
- Chia file âm thanh thành các đoạn nhỏ
- Mã hóa Triple DES với SessionKey
- Hash SHA-512 để kiểm tra toàn vẹn
- Ký số RSA 2048-bit
- Handshake an toàn giữa client và server
- Xử lý lỗi và gửi ACK/NACK

## Cấu trúc dự án:
```
AMNHAC/
├── client.py          # Chương trình client (người gửi)
├── server.py          # Chương trình server (người nhận)
├── crypto_utils.py    # Các hàm tiện ích mã hóa
├── file_utils.py      # Các hàm xử lý file
├── network_utils.py   # Các hàm giao tiếp mạng
├── requirements.txt   # Thư viện cần thiết
└── README.md         # Hướng dẫn sử dụng
```

## Cách sử dụng:
1. Cài đặt thư viện: `pip install -r requirements.txt`
2. Chạy server: `python server.py`
3. Chạy client: `python client.py`

## Quy trình hoạt động:
1. Handshake: Client gửi "Hello!" → Server trả "Ready!"
2. Gửi metadata + chữ ký số
3. Gửi SessionKey được mã hóa RSA
4. Gửi 3 gói tin (iv, cipher, hash, sig)
5. Server kiểm tra và trả ACK/NACK 
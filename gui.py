import socket
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Cipher import DES, DES3, PKCS1_OAEP
import os

# --- Cấu hình ---
HOST = '192.168.1.4'
PORT = 12345
METADATA_CONTENT = "TênBàiHát: Bản Quyền Độc Quyền | Nghệ Sĩ: Tên Nghệ Sĩ | ID Bản Quyền: ABCXYZ123"
RECEIVER_PUBLIC_KEY_FILE = 'receiver_public_key.pem'

# --- Hàm hỗ trợ RSA ---
def load_receiver_public_key():
    if not os.path.exists(RECEIVER_PUBLIC_KEY_FILE):
        print(f"Lỗi: File {RECEIVER_PUBLIC_KEY_FILE} không tồn tại. Vui lòng chạy nhan.py trước để tạo khóa.")
        exit()
    try:
        with open(RECEIVER_PUBLIC_KEY_FILE, 'r', encoding='utf-8') as f:
            pem_data = f.read()
            pem_lines = [line.strip() for line in pem_data.splitlines() 
                        if line.strip() and not line.strip().startswith('#')]
            pem_clean = '\n'.join(pem_lines)
            public_key = RSA.import_key(pem_clean.encode('utf-8'))
            if public_key.size_in_bits() != 1024:
                print(f"Lỗi: Khóa trong {RECEIVER_PUBLIC_KEY_FILE} không phải 1024-bit.")
                exit()
            if not public_key.has_private():
                print("Khóa được đọc là khóa công khai (đúng như mong đợi).")
            else:
                print(f"Lỗi: File {RECEIVER_PUBLIC_KEY_FILE} chứa khóa riêng, không phải khóa công khai.")
                exit()
            return public_key
    except Exception as e:
        print(f"Lỗi: Không thể đọc khóa công khai từ {RECEIVER_PUBLIC_KEY_FILE}: {e}")
        exit()

def encrypt_with_rsa_pub(public_key, data):
    try:
        max_length = (public_key.size_in_bits() // 8) - 11  # Với SHA-1 (mặc định), trừ 11 bytes
        if len(data) <= max_length:
            cipher = PKCS1_OAEP.new(public_key)  # Dùng SHA-1 mặc định để tương thích RSA 1024
            encrypted_data = cipher.encrypt(data)
            return encrypted_data
        else:
            raise ValueError("Dữ liệu vượt quá kích thước cho phép của RSA.")
    except Exception as e:
        print(f"Lỗi mã hóa RSA: {e}")
        exit()

def encrypt_triple_des(key, iv, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pad_len = 8 - (len(plaintext) % 8)
    padded_plaintext = plaintext + bytes([pad_len]) * pad_len
    return cipher.encrypt(padded_plaintext)

def encrypt_des(key, iv, plaintext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pad_len = 8 - (len(plaintext) % 8)
    padded_plaintext = plaintext + bytes([pad_len]) * pad_len
    return cipher.encrypt(padded_plaintext)

def send_data(conn, data):
    conn.sendall(data.encode('utf-8') if isinstance(data, str) else data)

def receive_data(conn, buffer_size=4096):
    data = conn.recv(buffer_size)
    return data.decode('utf-8')

def receive_large_data(conn):
    data_len_bytes = conn.recv(4)
    if not data_len_bytes:
        return b''
    data_len = int.from_bytes(data_len_bytes, 'big')
    received_chunks = []
    bytes_recd = 0
    while bytes_recd < data_len:
        chunk = conn.recv(min(data_len - bytes_recd, 4096))
        if not chunk:
            raise RuntimeError("Kết nối socket bị ngắt hoặc không nhận được dữ liệu")
        received_chunks.append(chunk)
        bytes_recd += len(chunk)
    return b''.join(received_chunks)

if __name__ == "__main__":
    FILE_TO_SEND = input("Nhập đường dẫn file cần gửi (ví dụ: song.mp3): ").strip()
    if not os.path.exists(FILE_TO_SEND):
        print(f"Lỗi: File {FILE_TO_SEND} không tồn tại. Vui lòng kiểm tra đường dẫn.")
        exit()
    print(f"File đã chọn: {FILE_TO_SEND}")

    receiver_public_key = load_receiver_public_key()
    print(f"Đã đọc khóa công khai của người nhận từ {RECEIVER_PUBLIC_KEY_FILE}")

    print(f"Người gửi đang cố gắng kết nối tới {HOST}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Đã kết nối thành công tới {HOST}:{PORT}")

        print("1. Handshake: Gửi 'Hello!'")
        send_data(s, "Hello!")
        response = receive_data(s)
        if response != "Ready!":
            print("Lỗi handshake: Không nhận được 'Ready!'")
            exit()
        print("1. Handshake: Nhận được 'Ready!'")

        print("\n2. Trao khóa:")
        session_key = os.urandom(24)
        des_key = session_key[:8]
        encrypted_session_key = encrypt_with_rsa_pub(receiver_public_key, session_key)
        s.sendall(len(encrypted_session_key).to_bytes(4, 'big'))
        s.sendall(encrypted_session_key)
        print("    - Đã gửi SessionKey đã mã hóa.")

        print("\n3. Mã hóa & Kiểm tra toàn vẹn:")
        encrypted_file_content = b''
        with open(FILE_TO_SEND, 'rb') as f:
            file_data = f.read()
            iv_triple_des = os.urandom(8)
            encrypted_file_content = encrypt_triple_des(session_key, iv_triple_des, file_data)
        print("    - Đã mã hóa file bằng Triple DES.")

        encrypted_metadata = encrypt_des(des_key, iv_triple_des, METADATA_CONTENT.encode('utf-8'))
        print("    - Đã mã hóa metadata bằng DES.")

        data_for_hash = iv_triple_des + encrypted_file_content
        hasher = SHA512.new(data_for_hash)
        computed_hash = hasher.hexdigest()
        print("    - Đã tính hash (SHA-512) của IV và ciphertext.")

        package = {
            "iv": base64.b64encode(iv_triple_des).decode('utf-8'),
            "cipher": base64.b64encode(encrypted_file_content).decode('utf-8'),
            "meta": base64.b64encode(encrypted_metadata).decode('utf-8'),
            "hash": computed_hash
        }
        json_package = json.dumps(package).encode('utf-8')

        s.sendall(len(json_package).to_bytes(4, 'big'))
        s.sendall(json_package)

        response_from_receiver = receive_data(s)
        if response_from_receiver == "ACK":
            print("\nNhận được ACK từ Người nhận. File đã được truyền và xử lý thành công!")
        else:
            print(f"\nNhận được NACK từ Người nhận: {response_from_receiver}. Có lỗi xảy ra.")

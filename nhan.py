import socket
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Cipher import DES, DES3, PKCS1_OAEP
import os
import sys
from datetime import datetime

# --- Cấu hình ---
HOST = '0.0.0.0'
PORT = 12345
RECEIVED_FILE_NAME = 'song.mp3'
PRIVATE_KEY_FILE = 'receiver_private_key.pem'
PUBLIC_KEY_FILE = 'receiver_public_key.pem'

# --- Hàm hỗ trợ RSA ---
def decrypt_with_rsa_priv(private_key, encrypted_data):
    try:
        block_size = private_key.size_in_bits() // 8
        if len(encrypted_data) <= block_size:
            cipher = PKCS1_OAEP.new(private_key)  # Dùng SHA-1 mặc định
            decrypted_data = cipher.decrypt(encrypted_data)
            return decrypted_data
        else:
            raise ValueError("Encrypted data quá lớn hoặc không hợp lệ.")
    except Exception as e:
        print(f"Lỗi giải mã RSA: {e}")
        sys.exit(1)

# --- Hàm hỗ trợ giải mã đối xứng ---
def decrypt_triple_des(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]

def decrypt_des(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]

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

# --- Load hoặc tạo cặp khóa ---
def load_or_generate_rsa_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        try:
            with open(PRIVATE_KEY_FILE, 'r', encoding='utf-8') as f:
                private_pem = ''.join([line.strip() for line in f if line.strip() and not line.startswith('#')])
                private_key = RSA.import_key(private_pem.encode('utf-8'))
            with open(PUBLIC_KEY_FILE, 'r', encoding='utf-8') as f:
                public_pem = ''.join([line.strip() for line in f if line.strip() and not line.startswith('#')])
                public_key = RSA.import_key(public_pem.encode('utf-8'))
            return private_key, public_key
        except Exception as e:
            print(f"Lỗi khi đọc khóa từ file: {e}. Tạo khóa mới.")

    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    with open(PRIVATE_KEY_FILE, 'w', encoding='utf-8') as f:
        f.write(private_key.export_key().decode())
    with open(PUBLIC_KEY_FILE, 'w', encoding='utf-8') as f:
        f.write(public_key.export_key().decode())
    return private_key, public_key

# --- Logic chính ---
if __name__ == "__main__":
    private_key, public_key = load_or_generate_rsa_keys()
    print("Người nhận đang chờ kết nối...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Đã kết nối với: {addr}")
            greeting = receive_data(conn)
            if greeting != "Hello!":
                send_data(conn, "NACK")
                sys.exit(1)
            send_data(conn, "Ready!")

            encrypted_session_key = receive_large_data(conn)
            session_key = decrypt_with_rsa_priv(private_key, encrypted_session_key)
            des_key = session_key[:8]

            json_package_bytes = receive_large_data(conn)
            package = json.loads(json_package_bytes.decode('utf-8'))
            iv_triple_des = base64.b64decode(package['iv'])
            encrypted_file_content = base64.b64decode(package['cipher'])
            encrypted_metadata = base64.b64decode(package['meta'])
            received_hash = package['hash']

            hasher = SHA512.new(iv_triple_des + encrypted_file_content)
            if hasher.hexdigest() != received_hash:
                send_data(conn, "NACK: Hash mismatch")
                sys.exit(1)

            file_data = decrypt_triple_des(session_key, iv_triple_des, encrypted_file_content)
            metadata = decrypt_des(des_key, iv_triple_des, encrypted_metadata)
            with open(RECEIVED_FILE_NAME, 'wb') as f:
                f.write(file_data)
            print("Đã giải mã và lưu file thành công.")
            print("Metadata:", metadata.decode())
            send_data(conn, "ACK")

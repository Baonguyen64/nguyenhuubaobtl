import socket
import base64
import json
from Crypto.Cipher import DES3, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
import zlib
import logging

class NguoiGui:
    def __init__(self):
        self.SERVER_HOST = "127.0.0.1"
        self.SERVER_PORT = 12345
        self.rsa_key = RSA.generate(1024)
        self.session_key = None
        logging.basicConfig(filename='log_gui.txt', level=logging.INFO, format='%(asctime)s: %(message)s')

    def nhat_ky(self, thong_bao):
        print(f"{thong_bao}")
        logging.info(thong_bao)

    def _dinh_dang(self, du_lieu, block_size):
        do_dai_dinh_dang = block_size - (len(du_lieu) % block_size)
        return du_lieu + bytes([do_dai_dinh_dang] * do_dai_dinh_dang)

    def gui_file(self, duong_dan_file, metadata_ban_quyen):
        try:
            with open(duong_dan_file, 'rb') as f:
                du_lieu = f.read()
            du_lieu_nen = zlib.compress(du_lieu)
            self.nhat_ky(f"Đã nén file: {duong_dan_file}")

            # Tạo khóa phiên và IV
            self.session_key = get_random_bytes(24)  # 24 bytes cho Triple DES
            iv = get_random_bytes(8)  # 8 bytes cho Triple DES và DES

            # Mã hóa file bằng Triple DES
            cipher = DES3.new(self.session_key, DES3.MODE_CBC, iv)
            du_lieu_dinh_dang = self._dinh_dang(du_lieu_nen, 8)
            ban_ma = cipher.encrypt(du_lieu_dinh_dang)

            # Mã hóa metadata bằng DES
            metadata = metadata_ban_quyen.encode()
            cipher_des = DES.new(self.session_key[:8], DES.MODE_CBC, iv)
            metadata_dinh_dang = self._dinh_dang(metadata, 8)
            metadata_ma_hoa = cipher_des.encrypt(metadata_dinh_dang)

            # Tính hash và ký số
            doi_tuong_hash = SHA512.new(iv + ban_ma + metadata_ma_hoa)
            chu_ky = pkcs1_15.new(self.rsa_key).sign(doi_tuong_hash)

            # Tạo gói tin
            goi_tin = {
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ban_ma).decode(),
                "meta": base64.b64encode(metadata_ma_hoa).decode(),
                "hash": doi_tuong_hash.hexdigest(),
                "sig": base64.b64encode(chu_ky).decode()
            }

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.SERVER_HOST, self.SERVER_PORT))
                self.nhat_ky(f"Kết nối tới người nhận tại {self.SERVER_HOST}:{self.SERVER_PORT}")
                s.sendall(b"Hello!")
                phan_hoi = s.recv(1024).decode()
                if phan_hoi != "Ready!":
                    self.nhat_ky("Bắt tay thất bại")
                    return

                # Gửi khóa công khai và nhận khóa công khai của người nhận
                s.sendall(self.rsa_key.publickey().export_key())
                khoa_nguoi_nhan = RSA.import_key(s.recv(4096))
                cipher_rsa = PKCS1_OAEP.new(khoa_nguoi_nhan)
                khoa_phien_ma_hoa = cipher_rsa.encrypt(self.session_key)
                s.sendall(base64.b64encode(khoa_phien_ma_hoa))

                # Gửi gói tin
                s.sendall(json.dumps(goi_tin).encode())
                phan_hoi = s.recv(1024).decode()
                self.nhat_ky(f"Phản hồi từ người nhận: {phan_hoi}")
                if phan_hoi == "ACK":
                    self.nhat_ky(f"Gửi file {duong_dan_file} thành công qua local!")
                else:
                    self.nhat_ky(f"Gửi file thất bại: {phan_hoi}")

        except Exception as e:
            self.nhat_ky(f"Lỗi khi gửi qua local: {str(e)}")

if __name__ == "__main__":
    app = NguoiGui()
    duong_dan_file = input("Nhập đường dẫn file song.mp3: ")
    metadata_ban_quyen = input("Nhập metadata bản quyền: ")
    app.gui_file(duong_dan_file, metadata_ban_quyen)
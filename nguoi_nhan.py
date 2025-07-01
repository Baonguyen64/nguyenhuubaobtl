import socket
import base64
import json
from Crypto.Cipher import DES3, DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_OAEP
import zlib
import logging

class NguoiNhan:
    def __init__(self):
        self.SERVER_HOST = "127.0.0.1"
        self.SERVER_PORT = 12345
        self.rsa_key = RSA.generate(1024)
        logging.basicConfig(filename='log_nhan.txt', level=logging.INFO, format='%(asctime)s: %(message)s')

    def nhat_ky(self, thong_bao):
        print(f"{thong_bao}")
        logging.info(thong_bao)

    def _giai_dinh_dang(self, du_lieu):
        do_dai_dinh_dang = du_lieu[-1]
        return du_lieu[:-do_dai_dinh_dang]

    def nhan_file(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.SERVER_HOST, self.SERVER_PORT))
                s.listen()
                self.nhat_ky(f"Đang lắng nghe tại {self.SERVER_HOST}:{self.SERVER_PORT}")
                
                conn, addr = s.accept()
                with conn:
                    self.nhat_ky(f"Nhận kết nối từ {addr[0]}:{addr[1]}")
                    du_lieu = conn.recv(1024).decode()
                    if du_lieu != "Hello!":
                        self.nhat_ky("Bắt tay không hợp lệ")
                        return
                    conn.sendall(b"Ready!")

                    # Nhận khóa công khai và gửi khóa công khai của mình
                    khoa_gui = RSA.import_key(conn.recv(4096))
                    conn.sendall(self.rsa_key.publickey().export_key())

                    # Giải mã khóa phiên
                    khoa_phien_ma_hoa = base64.b64decode(conn.recv(4096))
                    cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
                    khoa_phien = cipher_rsa.decrypt(khoa_phien_ma_hoa)
                    if khoa_phien is None:
                        conn.sendall(b"NACK: Không thể giải mã khóa phiên")
                        self.nhat_ky("Không thể giải mã khóa phiên")
                        return
                    self.nhat_ky("Đã giải mã khóa phiên thành công")

                    # Nhận gói tin
                    goi_tin = json.loads(conn.recv(4096).decode())
                    iv = base64.b64decode(goi_tin['iv'])
                    ban_ma = base64.b64decode(goi_tin['cipher'])
                    metadata_ma_hoa = base64.b64decode(goi_tin['meta'])

                    # Kiểm tra hash
                    doi_tuong_hash = SHA512.new(iv + ban_ma + metadata_ma_hoa)
                    if doi_tuong_hash.hexdigest() != goi_tin['hash']:
                        conn.sendall(b"NACK: Hash không hợp lệ")
                        self.nhat_ky("File bị từ chối: Hash không hợp lệ")
                        return
                    self.nhat_ky("Kiểm tra hash: Hợp lệ")

                    # Kiểm tra chữ ký
                    chu_ky = base64.b64decode(goi_tin['sig'])
                    try:
                        pkcs1_15.new(khoa_gui).verify(doi_tuong_hash, chu_ky)
                        self.nhat_ky("Kiểm tra chữ ký: Hợp lệ")
                    except:
                        conn.sendall(b"NACK: Chữ ký không hợp lệ")
                        self.nhat_ky("File bị từ chối: Chữ ký không hợp lệ")
                        return

                    # Giải mã file bằng Triple DES
                    cipher = DES3.new(khoa_phien, DES3.MODE_CBC, iv)
                    du_lieu_giai_ma = cipher.decrypt(ban_ma)
                    du_lieu_giai_nen = zlib.decompress(self._giai_dinh_dang(du_lieu_giai_ma))

                    # Giải mã metadata bằng DES
                    cipher_des = DES.new(khoa_phien[:8], DES.MODE_CBC, iv)
                    metadata_giai_ma = cipher_des.decrypt(metadata_ma_hoa)
                    metadata = self._giai_dinh_dang(metadata_giai_ma).decode()

                    # Lưu file
                    with open("song.mp3", 'wb') as f:
                        f.write(du_lieu_giai_nen)
                    
                    self.nhat_ky(f"Đã nhận và lưu file song.mp3 thành công từ {addr[0]}:{addr[1]}")
                    self.nhat_ky(f"Metadata bản quyền: {metadata}")
                    conn.sendall(b"ACK")

        except Exception as e:
            self.nhat_ky(f"Lỗi khi nhận qua local: {str(e)}")
            if 'conn' in locals():
                conn.sendall(f"NACK: {str(e)}".encode())

if __name__ == "__main__":
    app = NguoiNhan()
    print(f"Khóa công khai của người nhận:\n{app.rsa_key.publickey().export_key().decode()}")
    app.nhan_file()
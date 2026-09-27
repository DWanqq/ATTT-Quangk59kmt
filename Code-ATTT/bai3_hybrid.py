from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

print("--- BÀI 3: MÔ HÌNH MÃ HÓA LAI (RSA + AES) ---")

# Tình huống: Bob muốn gửi 1 file dữ liệu lớn cho Alice.
# Alice tạo sẵn cặp khóa RSA và gửi Public Key cho Bob.
alice_keypair = RSA.generate(2048)
alice_pubkey = alice_keypair.publickey()

# ----------------- PHÍA BOB (NGƯỜI GỬI) -----------------
print("\n[BOB] Đang chuẩn bị gửi dữ liệu...")
data_to_send = b"Noi dung file dung luong rat lon cua Bob..."

# Bob tạo 1 khóa phiên AES ngẫu nhiên
session_key = get_random_bytes(16)

# Bob mã hóa dữ liệu bằng AES
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data_to_send)

# Bob dùng Public Key của Alice để mã hóa chính cái session_key đó
cipher_rsa = PKCS1_OAEP.new(alice_pubkey)
enc_session_key = cipher_rsa.encrypt(session_key)

print("[BOB] Đã gửi gói tin gồm: {Khóa AES đã mã hóa RSA + Dữ liệu đã mã hóa AES}")

# ----------------- PHÍA ALICE (NGƯỜI NHẬN) -----------------
print("\n[ALICE] Đã nhận được gói tin, tiến hành giải mã...")

# Alice dùng Private Key của mình để giải mã lấy lại Khóa phiên AES
decrypt_rsa = PKCS1_OAEP.new(alice_keypair)
dec_session_key = decrypt_rsa.decrypt(enc_session_key)

# Alice dùng Khóa phiên AES vừa gỡ được để giải mã dữ liệu chính
cipher_aes_dec = AES.new(dec_session_key, AES.MODE_EAX, cipher_aes.nonce)
original_data = cipher_aes_dec.decrypt_and_verify(ciphertext, tag)

print(f"[ALICE] Dữ liệu gốc thu được: {original_data.decode('utf-8')}")
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

print("--- BÀI 1: THUẬT TOÁN MÃ HÓA ĐỐI XỨNG AES ---")

# 1. Khởi tạo khóa AES 128-bit (16 bytes) ngẫu nhiên
key = get_random_bytes(16)
print(f"Khóa AES (Hex): {key.hex()}")

# 2. Dữ liệu cần mã hóa
data = "Thông tin tuyệt mật cần bảo vệ bằng AES!".encode('utf-8')
print(f"Bản rõ ban đầu: {data.decode('utf-8')}")

# 3. Mã hóa (Sử dụng mode EAX để đảm bảo cả tính bí mật và toàn vẹn)
cipher_encrypt = AES.new(key, AES.MODE_EAX)
nonce = cipher_encrypt.nonce # Số ngẫu nhiên dùng 1 lần
ciphertext, tag = cipher_encrypt.encrypt_and_digest(data)

print(f"Bản mã (Ciphertext): {ciphertext.hex()}")

# 4. Giải mã
cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted_data = cipher_decrypt.decrypt_and_verify(ciphertext, tag)

print(f"Dữ liệu sau khi giải mã: {decrypted_data.decode('utf-8')}")
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

print("--- BÀI 2: THUẬT TOÁN MÃ HÓA BẤT ĐỐI XỨNG RSA ---")

# 1. Sinh cặp khóa RSA 2048-bit
print("Đang tạo cặp khóa RSA (có thể mất vài giây)...")
keyPair = RSA.generate(2048)

pubKey = keyPair.publickey()
print(f"Public Key sinh ra thành công (dùng để mã hóa).")
print(f"Private Key sinh ra thành công (dùng để giải mã).")

# 2. Dữ liệu cần mã hóa
message = b"Day la mat khau ngan hang cua toi: 123456"
print(f"\nBản rõ ban đầu: {message.decode('utf-8')}")

# 3. Mã hóa bằng Khóa công khai (Public Key)
encryptor = PKCS1_OAEP.new(pubKey)
encrypted_msg = encryptor.encrypt(message)
print(f"Bản mã RSA (Hex): {binascii.hexlify(encrypted_msg)[:50]}... (đã rút gọn)")

# 4. Giải mã bằng Khóa bí mật (Private Key)
decryptor = PKCS1_OAEP.new(keyPair)
decrypted_msg = decryptor.decrypt(encrypted_msg)
print(f"Dữ liệu sau khi giải mã: {decrypted_msg.decode('utf-8')}")
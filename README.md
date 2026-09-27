# BÁO CÁO BÀI TẬP MÔN: AN TOÀN VÀ BẢO MẬT THÔNG TIN

- **Sinh viên thực hiện:** Trần Đình Quang
- **Lớp:** K59KMT
- **Mã số sinh viên:** K235480106057
- **Hình thức:** Báo cáo lý thuyết & Mã nguồn thực hành

---

## MỤC LỤC
1. [Bài tập 1: Thuật toán mã hóa đối xứng DES và AES](#bài-tập-1-thuật-toán-mã-hóa-đối-xứng-des-và-aes)
   - [1.1 Thuật toán mã hóa DES](#11-thuật-toán-mã-hóa-des-data-encryption-standard)
   - [1.2 Thuật toán mã hóa AES](#12-thuật-toán-mã-hóa-aes-advanced-encryption-standard)
   - [1.3 Mã nguồn thực hành AES (Python)](#13-mã-nguồn-thực-hành-aes-python)
2. [Bài tập 2: Thuật toán mã hóa bất đối xứng RSA](#bài-tập-2-thuật-toán-mã-hóa-bất-đối-xứng-rsa)
   - [2.1 Khái niệm cơ bản](#21-khái-niệm-cơ-bản)
   - [2.2 Nguyên lý sinh cặp khóa RSA](#22-nguyên-lý-sinh-cặp-khóa-rsa)
   - [2.3 Quy trình Mã hóa và Giải mã](#23-quy-trình-mã-hóa-và-giải-mã)
   - [2.4 Mã nguồn thực hành RSA (Python)](#24-mã-nguồn-thực-hành-rsa-python)
3. [Bài tập 3: Mô hình áp dụng, So sánh & Mã hóa lai](#bài-tập-3-mô-hình-áp-dụng-so-sánh--mã-hóa-lai)
   - [3.1 Các mô hình áp dụng thuật toán RSA](#31-các-mô-hình-áp-dụng-thuật-toán-rsa)
   - [3.2 So sánh thời gian xử lý giữa RSA và AES](#32-so-sánh-thời-gian-xử-lý-giữa-rsa-và-aes)
   - [3.3 Mô hình Mã hóa lai (Hybrid Encryption)](#33-mô-hình-mã-hóa-lai-hybrid-encryption-system)
   - [3.4 Mã nguồn thực hành Mã hóa lai (Python)](#34-mã-nguồn-thực-hành-mã-hóa-lai-python)

---

## BÀI TẬP 1: THUẬT TOÁN MÃ HÓA ĐỐI XỨNG DES VÀ AES

### 1.1 Thuật toán mã hóa DES (Data Encryption Standard)

#### A. Mô tả tổng quan
DES là thuật toán mã hóa đối xứng theo khối (block cipher), xử lý từng khối dữ liệu **64-bit** cố định với độ dài khóa đầu vào là **64-bit** (trong đó 8 bit dùng kiểm tra chẵn lẻ - parity, độ dài khóa thực tế có hiệu lực bảo mật là **56-bit**). DES hoạt động dựa trên cấu trúc **Mạng Feistel (Feistel Network)** gồm **16 vòng lặp (rounds)**.

#### B. Quy trình mã hóa DES
1. **Hoán vị ban đầu (IP):** Khối dữ liệu 64-bit được đảo vị trí các bit dựa trên ma trận hoán vị IP.
2. **Phân chia khối:** Chia khối dữ liệu thành hai phần: nửa trái $L_0$ (32-bit) và nửa phải $R_0$ (32-bit).
3. **16 vòng biến đổi Feistel:** Tại mỗi vòng $i$ ($1 \le i \le 16$):
   - $L_i = R_{i-1}$
   - $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$
   - Hàm $f$: Mở rộng $R_{i-1}$ từ 32-bit lên 48-bit $\rightarrow$ XOR với khóa con $K_i$ (48-bit) $\rightarrow$ Đưa qua 8 hộp thế $S$-Boxes biến thành 32-bit $\rightarrow$ Hoán vị qua P-Box.
4. **Hoán vị nghịch đảo ($IP^{-1}$):** Ghép $(R_{16}, L_{16})$ và hoán vị qua bảng $IP^{-1}$ thu được bản mã 64-bit.

#### C. Quy trình giải mã
Quy trình giải mã hoàn toàn giống mã hóa, chỉ đảo ngược thứ tự các khóa con áp dụng từ $K_{16}$ quay về $K_1$.

---

### 1.2 Thuật toán mã hóa AES (Advanced Encryption Standard)

#### A. Mô tả tổng quan
AES xử lý khối dữ liệu cố định **128-bit** (dưới dạng ma trận State $4 \times 4$ byte). AES dựa trên cấu trúc **Mạng thay thế - hoán vị (SPN)** với các độ dài khóa:
* **AES-128:** Khóa 128-bit $\rightarrow$ 10 vòng (rounds).
* **AES-192:** Khóa 192-bit $\rightarrow$ 12 vòng (rounds).
* **AES-256:** Khóa 256-bit $\rightarrow$ 14 vòng (rounds).

#### B. Quy trình mã hóa AES-128 (10 vòng)
1. **Vòng khởi tạo (Round 0):** Thực hiện `AddRoundKey` giữa ma trận State với khóa vòng $K_0$.
2. **Vòng 1 đến 9:**
   - **`SubBytes`:** Thay thế phi tuyến từng byte qua bảng S-Box.
   - **`ShiftRows`:** Dịch chuyển xoay vòng các byte trên từng hàng.
   - **`MixColumns`:** Trộn các cột trên trường Galois $GF(2^8)$.
   - **`AddRoundKey`:** XOR ma trận State với khóa vòng $K_i$.
3. **Vòng 10 (Cuối):** Thực hiện `SubBytes` $\rightarrow$ `ShiftRows` $\rightarrow$ `AddRoundKey` (bỏ qua `MixColumns`).

---

### 1.3 Mã nguồn thực hành AES (Python)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

print("--- BÀI 1: THUẬT TOÁN MÃ HÓA ĐỐI XỨNG AES ---")

# 1. Khởi tạo khóa AES 128-bit (16 bytes) ngẫu nhiên
key = get_random_bytes(16)
print(f"Khóa AES (Hex): {key.hex()}")

# 2. Dữ liệu cần mã hóa
data = "Thông tin tuyệt mật cần bảo vệ bằng AES!".encode('utf-8')
print(f"Bản rõ ban đầu: {data.decode('utf-8')}")

# 3. Mã hóa (Sử dụng mode EAX)
cipher_encrypt = AES.new(key, AES.MODE_EAX)
nonce = cipher_encrypt.nonce 
ciphertext, tag = cipher_encrypt.encrypt_and_digest(data)
print(f"Bản mã (Ciphertext): {ciphertext.hex()}")

# 4. Giải mã
cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted_data = cipher_decrypt.decrypt_and_verify(ciphertext, tag)
print(f"Dữ liệu sau khi giải mã: {decrypted_data.decode('utf-8')}")
```

---

## BÀI TẬP 2: THUẬT TOÁN MÃ HÓA BẤT ĐỐI XỨNG RSA

### 2.1 Khái niệm cơ bản
RSA là thuật toán mã hóa bất đối xứng. Độ an toàn của RSA dựa trên độ khó của việc **phân tích số nguyên lớn thành tích hai số nguyên tố**.
* **Khóa công khai (Public Key):** Dùng để mã hóa hoặc kiểm tra chữ ký số (công khai).
* **Khóa bí mật (Private Key):** Dùng để giải mã hoặc tạo chữ ký số (giữ bí mật).

---

### 2.2 Nguyên lý sinh cặp khóa RSA
1. Chọn 2 số nguyên tố lớn $p$ và $q$ ($p \neq q$).
2. Tính $n = p \times q$.
3. Tính hàm Euler $\phi(n) = (p - 1)(q - 1)$.
4. Chọn số $e$ sao cho $1 < e < \phi(n)$ và $\gcd(e, \phi(n)) = 1$ (thường chọn $e = 65537$).
5. Tính $d = e^{-1} \pmod{\phi(n)}$ (dùng thuật toán Euclid mở rộng).
6. **Bộ khóa:** Public Key $PU = \{e, n\}$, Private Key $PR = \{d, n\}$.

---

### 2.3 Quy trình Mã hóa và Giải mã
* **Mã hóa:** $C = M^e \pmod n$ (Sử dụng Public Key của người nhận)
* **Giải mã:** $M = C^d \pmod n$ (Sử dụng Private Key của người nhận)

---

### 2.4 Mã nguồn thực hành RSA (Python)

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

print("--- BÀI 2: THUẬT TOÁN MÃ HÓA BẤT ĐỐI XỨNG RSA ---")

# 1. Sinh cặp khóa RSA 2048-bit
print("Đang tạo cặp khóa RSA...")
keyPair = RSA.generate(2048)
pubKey = keyPair.publickey()

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
```

---

## BÀI TẬP 3: MÔ HÌNH ÁP DỤNG, SO SÁNH & MÃ HÓA LAI

### 3.1 Các mô hình áp dụng thuật toán RSA
1. **Mô hình Bảo đảm tính Bí mật:** Người gửi dùng **Public Key của người nhận** để mã hóa. Chỉ có **Private Key của người nhận** mới giải mã được.
2. **Mô hình Chữ ký số (Xác thực):** Người gửi dùng **Private Key của mình** để ký. Người nhận dùng **Public Key của người gửi** để xác minh danh tính và tính toàn vẹn.
3. **Mô hình Kết hợp:** Vừa ký bằng Private Key người gửi, vừa mã hóa bằng Public Key người nhận.

---

### 3.2 So sánh thời gian xử lý giữa RSA và AES

| Tiêu chí so sánh | Mã hóa đối xứng AES | Mã hóa bất đối xứng RSA |
| :--- | :--- | :--- |
| **Bản chất khóa** | Dùng chung 1 khóa bí mật | Dùng cặp khóa (Public Key / Private Key) |
| **Kích thước khóa** | 128, 192, 256 bits | 2048, 3072, 4096 bits |
| **Tốc độ xử lý** | **Cực kỳ nhanh** | **Rất chậm** (chậm hơn AES 100 - 1000 lần) |
| **Kích thước file** | Mã hóa file dung lượng lớn (GBs) | Chỉ mã hóa dữ liệu nhỏ hơn độ dài khóa |
| **Quản lý khóa** | Khó phân phối khóa an toàn | Dễ dàng chia sẻ Public Key công khai |

---

### 3.3 Mô hình Mã hóa lai (Hybrid Encryption System)
Mô hình mã hóa lai kết hợp tốc độ cao của **AES** và khả năng quản lý khóa an toàn của **RSA**:
1. **Tạo khóa phiên:** Sinh ngẫu nhiên một khóa AES tạm thời (Session Key).
2. **Mã hóa dữ liệu:** Dùng khóa AES vừa tạo để mã hóa tập tin dữ liệu lớn (nhanh chóng).
3. **Mã hóa khóa phiên:** Dùng **Public Key RSA của người nhận** để mã hóa khóa AES.
4. **Truyền tin:** Gửi cả `{Dữ liệu đã mã hóa AES + Khóa AES đã mã hóa RSA}` cho người nhận.
5. **Giải mã:** Người nhận dùng **Private Key RSA** giải mã lấy khóa AES, sau đó dùng khóa AES giải mã lấy dữ liệu gốc.

---

### 3.4 Mã nguồn thực hành Mã hóa lai (Python)

```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

print("--- BÀI 3: MÔ HÌNH MÃ HÓA LAI (RSA + AES) ---")

alice_keypair = RSA.generate(2048)
alice_pubkey = alice_keypair.publickey()

# --- PHÍA BOB (NGƯỜI GỬI) ---
data_to_send = b"Noi dung file dung luong rat lon cua Bob..."
session_key = get_random_bytes(16)

# Mã hóa dữ liệu bằng AES
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data_to_send)

# Mã hóa session_key bằng RSA
cipher_rsa = PKCS1_OAEP.new(alice_pubkey)
enc_session_key = cipher_rsa.encrypt(session_key)

# --- PHÍA ALICE (NGƯỜI NHẬN) ---
# Giải mã RSA để lấy lại session_key
decrypt_rsa = PKCS1_OAEP.new(alice_keypair)
dec_session_key = decrypt_rsa.decrypt(enc_session_key)

# Giải mã AES để lấy dữ liệu gốc
cipher_aes_dec = AES.new(dec_session_key, AES.MODE_EAX, cipher_aes.nonce)
original_data = cipher_aes_dec.decrypt_and_verify(ciphertext, tag)

print(f"Dữ liệu gốc thu được: {original_data.decode('utf-8')}")
```

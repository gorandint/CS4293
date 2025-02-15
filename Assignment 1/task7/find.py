from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

def pad_key(key):
    """用 # 字符填充密钥到 16 字节"""
    return key.encode() + b'#' * (16 - len(key))

def encrypt_message(key, iv, plaintext):
    """使用给定的密钥和 IV 进行 AES-128-CBC 加密"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 使用 PKCS7 填充
    padded_text = plaintext + bytes([16 - (len(plaintext) % 16)] * (16 - (len(plaintext) % 16)))
    return cipher.encrypt(padded_text)

def main():
    # 已知的参数
    plaintext = b'This is a top secret.'
    ciphertext = unhexlify('764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2')
    iv = unhexlify('aabbccddeeff00998877665544332211')

    # 读取单词列表
    with open('words.txt', 'r') as f:
        words = [word.strip() for word in f if len(word.strip()) < 16]

    print(f"开始尝试 {len(words)} 个可能的密钥...")

    # 尝试每个单词作为密钥
    for word in words:
        key = pad_key(word)
        try:
            result = encrypt_message(key, iv, plaintext)
            if result == ciphertext:
                print(f"\n找到匹配的密钥！")
                print(f"密钥单词: {word}")
                print(f"填充后的密钥 (hex): {hexlify(key).decode()}")
                return
        except Exception as e:
            continue

    print("\n未找到匹配的密钥")

if __name__ == "__main__":
    main()
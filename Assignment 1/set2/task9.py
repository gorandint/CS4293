import hashlib
import os
import random
from pathlib import Path

def md5_hash(data):
    return hashlib.md5(data).hexdigest()

def generate_random_suffix(length):
    return bytes([random.randint(0, 255) for _ in range(length)])

def main():
    try:
        with open('out1.bin', 'rb') as f1, open('out2.bin', 'rb') as f2:
            data1 = f1.read()
            data2 = f2.read()
    except IOError as e:
        print(e)
        return
    
    hash1 = md5_hash(data1)
    hash2 = md5_hash(data2)
    assert hash1 == hash2, 'The two files have different MD5 hashes'
    print(f'MD5 hash: {hash1}')

    repeat = 1000
    for _ in range(repeat):
        suf_len = random.randint(1, 512)
        suffix = generate_random_suffix(suf_len)
        hash1 = md5_hash(data1 + suffix)
        hash2 = md5_hash(data2 + suffix)
        assert hash1 == hash2, f'Different MD5 hashes found upon concatenation with {suffix.hex()}'
    
    print(f'Passed {repeat} tests')

if __name__ == '__main__':
    random.seed(2147483647)
    main()
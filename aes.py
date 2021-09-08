from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from binascii import b2a_hex, a2b_hex


def add_to_16(value):
    tmp_val = value.encode('utf-8')
    m = 16 - (len(tmp_val) % 16)
    if m != 0:
        for i in range(m):
            value += '\0'
    return str.encode(value)


def secret():
    key = '130806B41B0F3352'
    text = 'MapleStory'
    aes = AES.new(key.encode("utf-8"), AES.MODE_OFB, b'0000000000000000')
    encrypt_aes = aes.encrypt(add_to_16(text))
    text = b2a_hex(encrypt_aes)
    text = str(text, encoding=('utf-8'))
    return text


def decrypt(text):
    key = '130806B41B0F3352'
    aes = AES.new(key.encode('utf-8'), AES.MODE_OFB, b'0000000000000000')
    plain_text = aes.decrypt(a2b_hex(text))
    ss = str(plain_text, encoding='utf-8')
    #print(ss)
    print(ss.rstrip('\0'))

    return ss


if __name__ == '__main__':
   iv = get_random_bytes(32)
   text = secret()
   print(text)
   decrypt(text)
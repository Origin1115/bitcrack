import hashlib
import base58
import codecs
import ecdsa
import random
from bit import Key
import multiprocessing



def generate_private_key():
    c1 = "0000000000000000000000000000000"
    	  
    c32 = str(random.choice('23'))
    c33 = str(random.choice('0123456789ABCDEF'))
    c34 = str(random.choice('0123456789ABCDEF'))
    c35 = str(random.choice('0123456789ABCDEF'))
    c36 = str(random.choice('0123456789ABCDEF'))
    c37 = str(random.choice('0123456789ABCDEF'))
    c38 = str(random.choice('0123456789ABCDEF'))
    c39 = str(random.choice('0123456789ABCDEF'))
    c40 = str(random.choice('0123456789ABCDEF'))
    c41 = str(random.choice('0123456789ABCDEF'))
    c42 = str(random.choice('0123456789ABCDEF'))
    c43 = str(random.choice('0123456789ABCDEF'))
    c44 = str(random.choice('0123456789ABCDEF'))
    c45 = str(random.choice('0123456789ABCDEF'))
    c46 = str(random.choice('0123456789ABCDEF'))
    c47 = str(random.choice('0123456789ABCDEF'))
    c48 = str(random.choice('0123456789ABCDEF'))
    c49 = str(random.choice('0123456789ABCDEF'))
    c50 = str(random.choice('0123456789ABCDEF'))
    c51 = str(random.choice('0123456789ABCDEF'))
    c52 = str(random.choice('0123456789ABCDEF'))
    c53 = str(random.choice('0123456789ABCDEF'))
    c54 = str(random.choice('0123456789ABCDEF'))
    c55 = str(random.choice('0123456789ABCDEF'))
    c56 = str(random.choice('0123456789ABCDEF'))
    c57 = str(random.choice('0123456789ABCDEF'))
    c58 = str(random.choice('0123456789ABCDEF'))
    c59 = str(random.choice('0123456789ABCDEF'))
    c60 = str(random.choice('0123456789ABCDEF'))
    c61 = str(random.choice('0123456789ABCDEF'))
    c62 = str(random.choice('0123456789ABCDEF'))
    c63 = str(random.choice('0123456789ABCDEF'))
    c64 = str(random.choice('0123456789ABCDEF'))
    magic = (c1 + c32 + c33 + c34 + c35 + c36 + c37 + c38 + c39 + c40 + c41 + c42 + c43 + c44 + c45 + c46 + c47 + c48 + c49 + c50 + c51 + c52 + c53 + c54 + c55 + c56 + c57 + c58 + c59 + c60 + c61 + c62 + c63 + c64)
    return str(magic)
    # return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
# def main():
while True:
    # key = Key()
    private_key = generate_private_key()
    print(private_key)
    # Hex decoding the private key to bytes using codecs library
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Generating a public key in bytes using SECP256k1 & ecdsa library
    public_key_raw = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    public_key_bytes = public_key_raw.to_string()
    # Hex encoding the public key from bytes
    public_key_hex = codecs.encode(public_key_bytes, 'hex')
    # Bitcoin public key begins with bytes 0x04 so we have to add the bytes at the start
    public_key = (b'04' + public_key_hex).decode("utf-8")
    # Checking if the last byte is odd or even
    if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
        public_key_compressed = '02'
    else:
        public_key_compressed = '03'
    
    # Add bytes 0x02 to the X of the key if even or 0x03 if odd
    public_key_compressed += public_key[2:66]
    # Converting to bytearray for SHA-256 hashing
    hex_str = bytearray.fromhex(public_key_compressed)
    sha = hashlib.sha256()
    sha.update(hex_str)
    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()
    modified_key_hash = "00" + key_hash
    key_bytes = codecs.decode(modified_key_hash, 'hex')
    address = base58.b58encode_check(key_bytes).decode('utf-8')
    # # print(private_key)
    # print(address)
    # print(private_key)

    if address == "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua":
        with open('plutus.txt', 'a') as plutus:
            plutus.write(private_key)
            break

# if __name__ == '__main__':
#     for cpu in range(12):
#         multiprocessing.Process(target=main).start()
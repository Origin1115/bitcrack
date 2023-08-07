import hashlib
import base58
import codecs
import ecdsa
import binascii
import os

database = []
with open("blockchair_bitcoin_addresses_and_balance_LATEST.tsv") as file:
    for line in file:
        address1 = line.split('\t')
        address = address1[0]
        address = address.strip()
        if address.startswith('1'):
            database.append(address)
            if address == "1QH6VyNSHPHZK3WqMDdD6saPYRoQiLVF9N":
                break
    print("done")
    print(len(database))
def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
while True:
    private_key = generate_private_key()
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
    print(address)

    if address in database:
        with open('plutus.txt', 'a') as plutus:
            plutus.write(private_key)


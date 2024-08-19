from hashlib import sha1

hash_algo = sha1
hash_len = 0x14

data_checksum_offset = 0x0
key_checksum_offset = 0x14

iv_offset = 0x28
iv_len = 0x10

ciphertext_offset = hash_len*2 + iv_len

line_len = 64

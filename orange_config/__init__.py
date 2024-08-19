from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from . import keys, common
from .config_type import Orange_config

def loads(data_b64):
    data = b64decode(data_b64)

    assert len(data) > common.ciphertext_offset

    data_checksum = data[
            common.data_checksum_offset:
            common.data_checksum_offset + common.hash_len
    ]
    data_checksum_expected = common.hash_algo(
            data[common.key_checksum_offset:]).digest()
    assert data_checksum == data_checksum_expected

    key_checksum = data[
            common.key_checksum_offset:
            common.key_checksum_offset + common.hash_len
    ]
    key = keys.checksum_to_key.get(key_checksum)
    if not key:
        raise Exception(f"Couldn't find a key with the following checksum: "
                        f"{key_checksum.hex()}\n"
                        f"Either your modem is not (yet) supported by this program "
                        f"or that you've provided an incorrect/corrupted file")

    iv = data[
            common.iv_offset:
            common.iv_offset + common.iv_len
    ]

    ciphertext = data[common.ciphertext_offset:]

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext).rstrip(b"\0")

    return Orange_config(
            plaintext,
            key,
            iv
    )

def dumps(cfg, keep_iv=False):
    if keep_iv:
        cipher = AES.new(cfg.key, AES.MODE_CBC, iv=cfg.iv)
    else:
        cipher = AES.new(cfg.key, AES.MODE_CBC)

    padding_len = 16 - len(cfg.data) % 16
    plain_padded = cfg.data + b"\0" * padding_len

    ciphertext = cipher.encrypt(plain_padded)

    key_checksum = common.hash_algo(cfg.key)
    data_checksum = common.hash_algo()
    data_checksum.update(key_checksum.digest())
    data_checksum.update(cipher.iv)
    data_checksum.update(ciphertext)

    data = data_checksum.digest() \
         + key_checksum.digest() \
         + cipher.iv \
         + ciphertext

    data_b64 = b64encode(data)

    output = b""
    for i in range(0, len(data_b64), common.line_len):
        output += data_b64[i:i+common.line_len] + b"\n"

    return output + b"\n"

def cli_decrypt(args):
    cfg = loads(args.input.read())
    key_name = keys.keys[cfg.key]

    print(f"Name of the used key: {key_name}")
    print(f"IV: {cfg.iv.hex()}")

    args.output.write(cfg.data)

def cli_encrypt(args):
    plaintext = args.input.read()
    key = keys.name_to_key[args.key]
    if args.iv is None:
        iv = get_random_bytes(common.iv_len)
    else:
        iv = bytes.fromhex(args.iv)

    cfg = Orange_config(plaintext, key, iv)

    # keep_iv is true because if iv is not given then it's generated above
    # so that it can be later printed
    ciphertext = dumps(cfg, keep_iv=True)

    print(f"Name of the used key: {args.key}")
    print(f"IV: {cfg.iv.hex()}")

    args.output.write(ciphertext)

def main():
    import argparse
    parser = argparse.ArgumentParser(
            prog="Orange_config",
            description="Decrypt and encrypt config files from orange modems")
    subparsers = parser.add_subparsers(required=True)

    parser_decrypt = subparsers.add_parser("decrypt", aliases=["d"], help="perform decryption")
    parser_decrypt.add_argument("input", type=argparse.FileType("rb"))
    parser_decrypt.add_argument("--output", type=argparse.FileType("wb"), default="-")
    parser_decrypt.set_defaults(func=cli_decrypt)

    parser_encrypt = subparsers.add_parser("encrypt", aliases=["e"], help="perform encryption")
    parser_encrypt.add_argument("input", type=argparse.FileType("rb"))
    parser_encrypt.add_argument("--output", type=argparse.FileType("wb"), default="-")
    parser_encrypt.add_argument("--key", \
                                choices=keys.name_to_key.keys(), \
                                required=True, \
                                help="for the encrypted config to work you have to "
                                "choose which device's key to use for encryption "
                                "as the keys differ by model")
    parser_encrypt.add_argument("--iv", \
                                help="initialization vector used for encryption, "
                                "you can safely ignore this argument")
    parser_encrypt.set_defaults(func=cli_encrypt)

    args = parser.parse_args()
    args.func(args)

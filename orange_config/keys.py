from . import common

keys = {
    bytes.fromhex("b8bbf65e64694ba61e597e6f3c566e0a"): "funbox2",
    bytes.fromhex("7711bef5acff1356a0b00f459f4f7057"): "funbox2_fallback", # 2nd line from hgwcfg.key
}

name_to_key = {}
checksum_to_key = {}

for key in keys:
    key_hash = common.hash_algo(key).digest()
    checksum_to_key[key_hash] = key

    key_name = keys[key]
    name_to_key[key_name] = key


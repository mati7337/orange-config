orange-config
=============

This program allows you to decrypt and encrypt config files used by Orange modems.

## Supported modems

- :white_check_mark: Funbox 2.0
- :grey_question: Funbox 2.6
- :grey_question: Funbox 3.0
- :x: Funbox 6
- :grey_question: Funbox 10

If you have any of the modems with a :grey_question: next to them and checked that this program can decrypt their configs then please file an issue to let me know so I can update this list.

## Usage

If you don't already have a venv, set one up

```shell
python -m venv venv
source venv/bin/activate
```

Then install orange-config

```shell
pip install git+https://github.com/mati7337/orange-config
```

Now you can use orange-config like this

```shell
# Decrypt config from CONFIG_PATH.funbox and save it to decrypted.xml
orange-config decrypt CONFIG_PATH.funbox --output decrypted.xml

# Modify/look around the config with your favourite editor
vim decrypted.xml

# Reencrypt the config file using the Funbox 2.0 key
orange-config encrypt decrypted.xml --output edited.funbox --key funbox2
# Now you can import the edited.funbox config file
```

It's also possible to use this as a library

```python
import orange_config
cfg = orange_config.loads(CONFIG_AS_STR)
print(cfg.data) # Actual config
print(cfg.key.hex()) # key
print(cfg.iv.hex()) # iv
cfg_encrypted = orange_config.dumps(cfg)

# It's also possible to construct Orange_config from scratch
cfg_new = orange_config.config_type.Orange_config( \
	DATA, \
	KEY, \
	IV \ # You can set IV to None if you don't use keep_iv=True
)

# If you want to use a specific IV for encryption use the keep_iv flag
orange_config.dumps(cfg_new, keep_iv=True)
# otherwise a random one will be generated
```

## Format

The format used by funbox for exporting config isn't too complicated. The config is base64 encoded and after decoding it follows this structure:

- SHA1(everything after this hash)
- SHA1(key)
- 16 bytes of IV
- AES(config, key, IV)

the AES encryption uses the CBC mode with null padding.

## Adding new keys

To retrieve config encryption keys from your unsupported modem you have to get access to the root filesystem, which isn't an easy task. You need to have some electronic and reverse engineering skills to do it, but if you decide to do it here are some tips from my experience on funbox 2, your model might be different.

To get access to rootfs you have to either do it like me by desoldering the NAND and reading it directly or alternatively you can exploit some vulnerability in the firmware to get access to it, but from my experience there doesn't seem to be any trivial shell injection vulnerabilities.

### NAND dumping

If you go the desoldering route once you have the dump with stripped OOB data you'll have to extract the root filesystem which is on the partAll partition (in the case of funbox 2 it's at the 768k offset and it's 125184k in size). MTD devices don't have a partitioning table like regular disks, partition sizes are instead passed in as kernel parameters. One way to find them is to do `cat dump.img | grep "mtdparts="`.

partAll should be partitioned using UBI, to extract UBI images use [ubi_reader's](https://github.com/onekey-sec/ubi_reader) ubireader_extract_images.

The main rootfs should be located in the `operational` image. It uses a gsdf format, which seems to be sagemcom's proprietary format for packaging a signature, kernel and a rootfs. The easiest way to extract rootfs from it is to just use binwalk to find the squashfs magic values and use e.g. unsquashfs to extract it.

### Extracting the keys

The actual keys should be located in `/security/hgwcfg/hgwcfg.key`. This file might contain multiple keys, one per line. During decryption all of them are tried, and for encryption the first one is used.

To add these keys to `orange-config` first convert them to hex using
```shell
python -c "import base64; print(base64.b64decode('1 LINE FROM hgwcfg.key').hex())"`.
```
You can then add the key with some sensible name to `orange_config/keys.py` to the `keys` dict.

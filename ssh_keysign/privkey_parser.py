from base64 import b64decode
from ssh_keysign.utils import lv_parser, bytes2hex
from ssh_keysign.types import KeyPair
from bcrypt import kdf
import pyaes
import warnings



def privkey_parser(path: str, psw: str=None):
    with open(path) as f:
        p = b64decode("".join(f.readlines()[1:-1]))
        meta = lv_parser(p[15:], ["cipher", "kdfname", "kdf", "key_num", "sshpub", "rnd_prv_comd_pad"],  [4])
        if not meta["cipher"] == b"none":
            if meta["cipher"] != b"aes256-ctr":
                raise Exception("Unsupported cipher %s" % meta["cipher"])
            assert psw, "Pasword of your SSH KEY required"
            meta["salt/iv"] = lv_parser(meta['kdf'], ["salt"])['salt']
            meta["rounds"] = int.from_bytes(meta['kdf'][-4:], "big")
            meta["rnd_prv_comd_pad"] = decrypt_aes256ctr(meta["salt/iv"], psw.encode(), meta["rnd_prv_comd_pad"])

        keypair = lv_parser(meta["rnd_prv_comd_pad"][8:], ["type", "pk", "skpk", "comment"])
        keypair["type"] = keypair["type"].decode()
        keypair["sk"] = bytes2hex(keypair["skpk"][:-32])
        keypair["pk"] = bytes2hex(keypair["pk"])
        keypair["skpk"] = bytes2hex(keypair["skpk"])
        keypair["comment"] = keypair["comment"].decode()
        return KeyPair(**keypair)

def decrypt_aes256ctr(salt_iv: str, psw: str, enc: str) -> bytes:
    warnings.filterwarnings("ignore")
    data = kdf(
        password=psw,
        salt=salt_iv,
        desired_key_bytes=32 + 16,
        rounds=10)
    key, iv = data[:32], data[32:]
    iv = int.from_bytes(iv, "big")
    counter = pyaes.Counter(iv)
    aes = pyaes.AESModeOfOperationCTR(key, counter)
    return aes.decrypt(enc)

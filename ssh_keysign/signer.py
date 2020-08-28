from pure25519 import _ed25519 as ed25519
from ssh_keysign.types import KeyPair
from ssh_keysign.utils import hex2bytes
from hashlib import sha256
from typing import Union


def ed25519_sign(kp: KeyPair, msg: Union[str, bytes]) -> bytes:
    assert kp.type == "ssh-ed25519"
    if isinstance(msg, str):
        msg = msg.encode()
    return ed25519.sign(msg, hex2bytes(kp.skpk))[:-len(msg)]


def ed25519_sign_sha256(kp: KeyPair, msg: bytes) -> str:
    return "0x" + sha256(sign(kp, msg)).hexdigest()

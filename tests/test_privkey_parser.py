import os
from ssh_keysign.privkey_parser import privkey_parser
from ssh_keysign.signer import ed25519_sign, ed25519_sign_sha256
from ssh_keysign.utils import hex2bytes
from pure25519 import _ed25519 as ed25519


def test_ed25519_key():
    os.system("rm -rf ./tests/ed25519*")
    os.system("ssh-keygen -t ed25519 -N '' -b 123 -f ./tests/ed25519")
    keypair = privkey_parser("tests/ed25519")
    assert keypair
    assert keypair.pk
    assert keypair.sk
    assert keypair.skpk
    assert hex2bytes(keypair.skpk) == ed25519.publickey(hex2bytes(keypair.sk))[1]
    assert hex2bytes(keypair.pk) == ed25519.publickey(hex2bytes(keypair.sk))[0]
    msg = "hello world".encode()
    keypair = privkey_parser("tests/ed25519")
    sig = ed25519_sign(keypair, msg)
    assert ed25519.sign(msg, ed25519.publickey(hex2bytes(keypair.sk))[1])[:-len(msg)] == sig
    assert ed25519.open(sig+msg, hex2bytes(keypair.pk))
    os.system("rm -rf ./tests/ed25519*")

    mypass = "password 1234"
    os.system("ssh-keygen -t ed25519 -N '%s' -a '10' -b 123 -f ./tests/ed25519" % mypass)
    keypair = privkey_parser("tests/ed25519", mypass)
    assert keypair
    assert keypair.pk
    assert keypair.sk
    assert keypair.skpk
    assert hex2bytes(keypair.skpk) == ed25519.publickey(hex2bytes(keypair.sk))[1]
    assert hex2bytes(keypair.pk) == ed25519.publickey(hex2bytes(keypair.sk))[0]
    msg = "hello world".encode()
    keypair = privkey_parser("tests/ed25519", mypass)
    sig = ed25519_sign(keypair, msg)
    assert ed25519.sign(msg, ed25519.publickey(hex2bytes(keypair.sk))[1])[:-len(msg)] == sig
    assert ed25519.open(sig+msg, hex2bytes(keypair.pk))

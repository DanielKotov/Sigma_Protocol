from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from hmac import *
from collections import namedtuple
from os import urandom


curve = ec.SECP256K1()
R = 16
HASH_LEN = 32
NONCE_LENGTH = 8


class ECDSA:
    def __init__(self):
        self.sk = ec.generate_private_key(curve)
        self.pk = None

    def sign(self, msg):
        return self.sk.sign(msg, ec.ECDSA(chosen_hash))

    def verify(self, msg: bytes, sig: bytes):
        check = True
        if self.pk is None:
            raise ValueError("Can't verify the signature without public key")
        if not isinstance(sig, bytes):
            raise TypeError("Incorrect type of signature")
        try:
            self.pk.verify(sig, msg, ec.ECDSA(chosen_hash))
        except InvalidSignature:
            check = False
        return check

    def set_public_key(self, pk):
        self.pk = pk

    def get_public_key(self):
        return self.sk.public_key()


class ECDH:
    def __init__(self):
        self.sk = ec.generate_private_key(curve)
        self.pk = self.sk.public_key()

    def shared_secret(self, pk):
        shared_key = self.sk.exchange(ec.ECDH(), pk)
        derived_key = HKDF(
                algorithm=chosen_hash,
                length=HASH_LEN,
                salt=None,
                info=b""
        ).derive(shared_key)
        return derived_key

    def get_serialize_public_key(self, pk=None):
        if pk is None:
            return self.pk.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
        else:
            return pk.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )



fst_data = namedtuple("fst_data", ["ecdh_pk", "r"])
snd_data = namedtuple("snd_data", ["ecdh_pk", "r", "hello", "ecdsa_sig", "hmac"])
thd_data = namedtuple("thd_data", ["hello", "ecdsa_sig", "hmac"])
enc_data = namedtuple("enc_data", ["iv_ct", "hmac"])



class Alice:
    def __init__(self, alice_hello="I'm alice"):
        self.ecdh = ECDH()
        self.ecdsa = ECDSA()
        self.r_a = urandom(R)
        self.hello = alice_hello.encode()
        self.k_m = None
        self.k_e = None
        self.b_pk = None

    def get_pk(self, pk):
        self.ecdsa.set_public_key(pk)

    def send_pk(self):
        return self.ecdsa.get_public_key()

    def send_params(self):
        return fst_data(self.ecdh.pk, self.r_a)

    def process_send_data(self, data):
        if not isinstance(data, snd_data):
            raise TypeError("Incorrect type of data was sent")
        bob_hello, bob_sig, hmac = data.hello, data.ecdsa_sig, data.hmac
        keys = create_hmac(self.r_a + data.r, self.ecdh.shared_secret(data.ecdh_pk))
        self.k_m, self.k_e, self.b_pk = keys[:R], keys[R:], data.ecdh_pk

        if not verify_hmac(self.k_m, bob_hello, hmac):
            raise ValueError("Incorrect value of given HMAC")

        if not self.ecdsa.verify(
                self.ecdh.get_serialize_public_key() + self.ecdh.get_serialize_public_key(self.b_pk),
                bob_sig):
                raise ValueError("Incorrect value of give ECDSA sig")

        return thd_data(
            self.hello,
            self.ecdsa.sign(
                self.ecdh.get_serialize_public_key(self.b_pk) + self.ecdh.get_serialize_public_key()),
            create_hmac(self.k_m, self.hello)
            )

    def encrypt(self):
        msg = urandom(10) + b"Hello, I'm Alice"
        cipher = AES.new(self.k_e, AES.MODE_CTR)
        ciphertext = cipher.encrypt(msg)
        return enc_data(
                cipher.nonce + ciphertext,
                create_hmac(self.k_m, ciphertext)
                )

    def decrypt_check(self, enc_data):
        nonce, ct, tag = enc_data.iv_ct[:NONCE_LENGTH], enc_data.iv_ct[NONCE_LENGTH:], enc_data.hmac
        cipher = AES.new(self.k_e, AES.MODE_CTR, nonce=nonce)
        if not verify_hmac(self.k_m, cipher, tag):
            raise ValueError("Incorrect hmac for authenticated encryption")
        else:
            return cipher.decrypt(ct)


class Bob:
    def __init__(self, bob_hello="I'm bob"):
        self.ecdh = ECDH()
        self.ecdsa = ECDSA()
        self.r_b = urandom(R)
        self.hello = bob_hello.encode()
        self.k_m = None
        self.k_e = None
        self.a_pk = None

    def get_pk(self, pk):
        self.ecdsa.set_public_key(pk)

    def send_pk(self):
        return self.ecdsa.get_public_key()

    def process_send_data(self, data):
        if not isinstance(data, fst_data):
            raise TypeError("Incorrect type of data was sent")
        keys = create_hmac(data.r + self.r_b, self.ecdh.shared_secret(data.ecdh_pk))
        self.k_m, self.k_e, self.a_pk = keys[:R], keys[R:], data.ecdh_pk
        return snd_data(
                self.ecdh.pk,
                self.r_b,
                self.hello,
                self.ecdsa.sign(
                    self.ecdh.get_serialize_public_key(self.a_pk) + self.ecdh.get_serialize_public_key()),
                    create_hmac(self.k_m, self.hello)
                )

    def final_check(self, data):
        if not isinstance(data, thd_data):
            raise TypeError("Incorrect type of data was sent")
        if not verify_hmac(self.k_m, data.hello, data.hmac):
            raise ValueError("Incorrect value of given HMAC")
        if not self.ecdsa.verify(
                 self.ecdh.get_serialize_public_key() + self.ecdh.get_serialize_public_key(self.a_pk),
                data.ecdsa_sig):
            raise ValueError("Incorrect value of given ECDSA signature")

    def encrypt(self):
        msg = urandom(10) + b"Hello, I'm Bob"
        cipher = AES.new(self.k_e, AES.MODE_CTR)
        ciphertext = cipher.encrypt(msg)
        return enc_data(
                cipher.nonce + ciphertext,
                create_hmac(self.k_m, ciphertext)
                )

    def check_decrypt(self, enc_data):
        nonce, ct, tag = enc_data.iv_ct[:NONCE_LENGTH], enc_data.iv_ct[NONCE_LENGTH:], enc_data.hmac
        cipher = AES.new(self.k_e, AES.MODE_CTR, nonce=nonce)
        if not verify_hmac(self.k_m, ct, tag):
            raise ValueError("Incorrect hmac for authenticated encryption")
        else:
            return cipher.decrypt(ct)


def sigma(alice, bob):
    alice_params = alice.send_params()
    bob_params = bob.process_send_data(alice_params)
    alice_final = alice.process_send_data(bob_params)
    bob.final_check(alice_final)
    print(bob.check_decrypt(alice.encrypt()))


def main():
    alice = Alice()
    bob = Bob()
    bob.get_pk(alice.send_pk())
    alice.get_pk(bob.send_pk())
    sigma(alice, bob)


if __name__ == "__main__":
    main()


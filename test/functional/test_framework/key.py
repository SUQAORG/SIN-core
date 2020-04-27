# Copyright (c) 2011 Sam Rushing
"""ECC secp256k1 OpenSSL wrapper.

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!

from .address import byte_to_base58

def modinv(a, n):
    """Compute the modular inverse of a modulo n
>>>>>>> eef90c14e... Merge #16528: Native Descriptor Wallets using DescriptorScriptPubKeyMan

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_ORDER_HALF = SECP256K1_ORDER // 2

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def _check_result(val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = _check_result

class CECKey():
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)

    def __del__(self):
        if ssl:
            ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
        group = ssl.EC_KEY_get0_group(self.k)
        pub_key = ssl.EC_POINT_new(group)
        ctx = ssl.BN_CTX_new()
        if not ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        ssl.EC_KEY_set_private_key(self.k, priv_key)
        ssl.EC_KEY_set_public_key(self.k, pub_key)
        ssl.EC_POINT_free(pub_key)
        ssl.BN_CTX_free(ctx)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_keybuffer = ctypes.create_string_buffer(32)
        r = ssl.ECDH_compute_key(ctypes.pointer(ecdh_keybuffer), 32,
                                 ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, 0)
        if r != 32:
            raise Exception('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return ecdh_keybuffer.raw

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def sign(self, hash, low_s = True):
        # FIXME: need unit tests for below cases
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result
        assert mb_sig.raw[0] == 0x30
        assert mb_sig.raw[1] == sig_size0.value - 2
        total_size = mb_sig.raw[1]
        assert mb_sig.raw[2] == 2
        r_size = mb_sig.raw[3]
        assert mb_sig.raw[4 + r_size] == 2
        s_size = mb_sig.raw[5 + r_size]
        s_value = int.from_bytes(mb_sig.raw[6+r_size:6+r_size+s_size], byteorder='big')
        if (not low_s) or s_value <= SECP256K1_ORDER_HALF:
            return mb_sig.raw[:sig_size0.value]
        else:
            low_s_value = SECP256K1_ORDER - s_value
            low_s_bytes = (low_s_value).to_bytes(33, byteorder='big')
            while len(low_s_bytes) > 1 and low_s_bytes[0] == 0 and low_s_bytes[1] < 0x80:
                low_s_bytes = low_s_bytes[1:]
            new_s_size = len(low_s_bytes)
            new_total_size_byte = (total_size + new_s_size - s_size).to_bytes(1,byteorder='big')
            new_s_size_byte = (new_s_size).to_bytes(1,byteorder='big')
            return b'\x30' + new_total_size_byte + mb_sig.raw[2:5+r_size] + new_s_size_byte + low_s_bytes

    def verify(self, hash, sig):
        """Verify a DER signature"""
        return ssl.ECDSA_verify(0, hash, len(hash), sig, len(sig), self.k) == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        ssl.EC_KEY_set_conv_form(self.k, form)


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()
    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()
    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) != 0
        return self

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig):
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())

<<<<<<< HEAD
=======
    def get_pubkey(self):
        """Compute an ECPubKey object for this secret key."""
        assert(self.valid)
        ret = ECPubKey()
        p = SECP256K1.mul([(SECP256K1_G, self.secret)])
        ret.p = p
        ret.valid = True
        ret.compressed = self.compressed
        return ret

    def sign_ecdsa(self, msg, low_s=True):
        """Construct a DER-encoded ECDSA signature with this key.

        See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for the
        ECDSA signer algorithm."""
        assert(self.valid)
        z = int.from_bytes(msg, 'big')
        # Note: no RFC6979, but a simple random nonce (some tests rely on distinct transactions for the same operation)
        k = random.randrange(1, SECP256K1_ORDER)
        R = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, k)]))
        r = R[0] % SECP256K1_ORDER
        s = (modinv(k, SECP256K1_ORDER) * (z + self.secret * r)) % SECP256K1_ORDER
        if low_s and s > SECP256K1_ORDER_HALF:
            s = SECP256K1_ORDER - s
        # Represent in DER format. The byte representations of r and s have
        # length rounded up (255 bits becomes 32 bytes and 256 bits becomes 33
        # bytes).
        rb = r.to_bytes((r.bit_length() + 8) // 8, 'big')
        sb = s.to_bytes((s.bit_length() + 8) // 8, 'big')
        return b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb

def bytes_to_wif(b, compressed=True):
    if compressed:
        b += b'\x01'
    return byte_to_base58(b, 239)

def generate_wif_key():
    # Makes a WIF privkey for imports
    k = ECKey()
    k.generate()
    return bytes_to_wif(k.get_bytes(), k.is_compressed)


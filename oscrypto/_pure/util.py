#https://codereview.stackexchange.com/questions/87538/python-pbkdf2-using-core-modules
import hmac
import struct
import hashlib
import ctypes
from .._types import type_name, byte_cls, int_types
from .._errors import pretty_message

def pbkdf2(hash_algorithm, password, salt, iterations, key_length):
    """
        PBKDF2 from PKCS#5

        :param hash_algorithm:
            The string name of the hash algorithm to use: "sha1", "sha224", "sha256", "sha384", "sha512"

        :param password:
            A byte string of the password to use an input to the KDF

        :param salt:
            A cryptographic random byte string

        :param iterations:
            The numbers of iterations to use when deriving the key

        :param key_length:
            The length of the desired key in bytes

        :raises:
            ValueError - when any of the parameters contain an invalid value
            TypeError - when any of the parameters are of the wrong type

        :return:
            The derived key as a byte string
    """

    if not isinstance(password, byte_cls):
        raise TypeError(pretty_message(
            '''
            password must be a byte string, not %s
            ''',
            type_name(password)
        ))

    if not isinstance(salt, byte_cls):
        raise TypeError(pretty_message(
            '''
            salt must be a byte string, not %s
            ''',
            type_name(salt)
        ))

    if not isinstance(iterations, int_types):
        raise TypeError(pretty_message(
            '''
            iterations must be an integer, not %s
            ''',
            type_name(iterations)
        ))

    if iterations < 1:
        raise ValueError('iterations must be greater than 0')

    if not isinstance(key_length, int_types):
        raise TypeError(pretty_message(
            '''
            key_length must be an integer, not %s
            ''',
            type_name(key_length)
        ))

    if key_length < 1:
        raise ValueError('key_length must be greater than 0')

    if hash_algorithm not in set(['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']):
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of "md5", "sha1", "sha224", "sha256", "sha384",
            "sha512", not %s
            ''',
            repr(hash_algorithm)
        ))
    
    ld = {
        'md5'   : hashlib.md5,
        'sha1'  : hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512, 
    }



    h = hmac.new(password, digestmod=ld[hash_algorithm])
    def prf(data):
        hm = h.copy()
        hm.update(data)
        return bytearray(hm.digest())

    key = bytearray()
    i = 1
    while len(key) < key_length:
        T = U = prf(salt + struct.pack('>i', i))
        for _ in range(iterations - 1):
            U = prf(U)
            T = bytearray(x ^ y for x, y in zip(T, U))
        key += T
        i += 1

    return key[:key_length]

def pkcs12_kdf(hash_algorithm, password, salt, iterations, key_length, id_):
    """
    KDF from RFC7292 appendix B.2 - https://tools.ietf.org/html/rfc7292#page-19

    :param hash_algorithm:
        The string name of the hash algorithm to use: "md5", "sha1", "sha224", "sha256", "sha384", "sha512"

    :param password:
        A byte string of the password to use an input to the KDF

    :param salt:
        A cryptographic random byte string

    :param iterations:
        The numbers of iterations to use when deriving the key

    :param key_length:
        The length of the desired key in bytes

    :param id_:
        The ID of the usage - 1 for key, 2 for iv, 3 for mac

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type

    :return:
        The derived key as a byte string
    """
    if not isinstance(password, byte_cls):
        raise TypeError(pretty_message(
            '''
            password must be a byte string, not %s
            ''',
            type_name(password)
        ))

    if not isinstance(salt, byte_cls):
        raise TypeError(pretty_message(
            '''
            salt must be a byte string, not %s
            ''',
            type_name(salt)
        ))

    if not isinstance(iterations, int_types):
        raise TypeError(pretty_message(
            '''
            iterations must be an integer, not %s
            ''',
            type_name(iterations)
        ))

    if iterations < 1:
        raise ValueError(pretty_message(
            '''
            iterations must be greater than 0 - is %s
            ''',
            repr(iterations)
        ))

    if not isinstance(key_length, int_types):
        raise TypeError(pretty_message(
            '''
            key_length must be an integer, not %s
            ''',
            type_name(key_length)
        ))

    if key_length < 1:
        raise ValueError(pretty_message(
            '''
            key_length must be greater than 0 - is %s
            ''',
            repr(key_length)
        ))
    
    ld = {
        'md5'   : hashlib.md5,
        'sha1'  : hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512, 
    }

    def derive_key(hashfn, purpose_byte, password_str, salt, iteration_count, desired_key_size):
        """
        Implements PKCS#12 key derivation as specified in RFC 7292, Appendix B, "Deriving Keys and IVs from Passwords and Salt".
        Ported from BC's implementation in org.bouncycastle.crypto.generators.PKCS12ParametersGenerator.
    
        hashfn:            hash function to use (expected to support the hashlib interface and attributes)
        password_str:      text string (not yet transformed into bytes)
        salt:              byte sequence
        purpose:           "purpose byte", signifies the purpose of the generated pseudorandom key material
        desired_key_size:  desired amount of bytes of key material to generate
        """
		# https://programtalk.com/vs2/python/7170/pyjks/jks/rfc7292.py/
        def _adjust(a, a_offset, b):
            """
            a = bytearray
            a_offset = int
            b = bytearray
            """
            x = (b[-1] & 0xFF) + (a[a_offset + len(b) - 1] & 0xFF) + 1
            a[a_offset + len(b) - 1] = ctypes.c_ubyte(x).value
            x >>= 8
        
            for i in range(len(b)-2, -1, -1):
                x += (b[i] & 0xFF) + (a[a_offset + i] & 0xFF)
                a[a_offset + i] = ctypes.c_ubyte(x).value
                x >>= 8

        password_bytes = (password_str.encode('utf-16be') + b"\x00\x00") if len(password_str) > 0 else b"\x00\x00"
        u = hashfn().digest_size # in bytes
        v = hashfn().block_size  # in bytes
    
        _salt = bytearray(salt)
        _password_bytes = bytearray(password_bytes)
    
        D = bytearray([purpose_byte])*v
        S_len = ((len(_salt) + v -1)//v)*v
        S = bytearray([_salt[n % len(_salt)] for n in range(S_len)])
        P_len = ((len(_password_bytes) + v -1)//v)*v
        P = bytearray([_password_bytes[n % len(_password_bytes)] for n in range(P_len)])
    
        I = S + P
        c = (desired_key_size + u - 1)//u
        derived_key = b""
    
        for i in range(1,c+1):
            A = hashfn(bytes(D + I)).digest()
            for j in range(iteration_count - 1):
                A = hashfn(A).digest()
    
            A = bytearray(A)
            B = bytearray([A[n % len(A)] for n in range(v)])
    
            # Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
            # blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
            # setting I_j=(I_j+B+1) mod 2^v for each j.
            for j in range(len(I)//v):
                _adjust(I, j*v, B)
    
            derived_key += bytes(A)
    
        # truncate derived_key to the desired size
        derived_key = derived_key[:desired_key_size]
        return derived_key
    password = password.decode()
    return derive_key(ld[hash_algorithm], id_, password, salt, iterations, key_length)
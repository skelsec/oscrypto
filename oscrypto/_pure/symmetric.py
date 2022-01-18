from .._errors import pretty_message
from ..util import rand_bytes
from .._types import type_name, byte_cls
from .external.aes.AES import AESModeOfOperationCBC
from .external.aes.blockfeeder import PADDING_NONE, Encrypter, PADDING_DEFAULT, Decrypter
from .external.RC4 import RC4
from .external.RC2 import RC2, PADDING_PKCS5 as RC2_PADDING_PKCS5, MODE_CBC as RC2_MODE_CBC
from .external.des import des, triple_des, CBC as DES_CBC ,PAD_PKCS5 as DES_PAD_PKCS5

__all__ = [
    'aes_cbc_no_padding_decrypt',
    'aes_cbc_no_padding_encrypt',
    'aes_cbc_pkcs7_decrypt',
    'aes_cbc_pkcs7_encrypt',
    'des_cbc_pkcs5_decrypt',
    'des_cbc_pkcs5_encrypt',
    'rc2_cbc_pkcs5_decrypt',
    'rc2_cbc_pkcs5_encrypt',
    'rc4_decrypt',
    'rc4_encrypt',
    'tripledes_cbc_pkcs5_decrypt',
    'tripledes_cbc_pkcs5_encrypt',
]

def aes_cbc_no_padding_encrypt(key, data, iv):
    """
    Encrypts plaintext using AES in CBC mode with a 128, 192 or 256 bit key and
    no padding. This means the ciphertext must be an exact multiple of 16 bytes
    long.

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - either a byte string 16-bytes long or None
        to generate an IV

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if not iv:
        iv = rand_bytes(16)
    elif len(iv) != 16:
        raise ValueError(pretty_message(
            '''
            iv must be 16 bytes long - is %s
            ''',
            len(iv)
        ))

    if len(data) % 16 != 0:
        raise ValueError(pretty_message(
            '''
            data must be a multiple of 16 bytes long - is %s
            ''',
            len(data)
        ))
    ciphertext = b''
    encrypter = Encrypter(AESModeOfOperationCBC(key, iv), padding=PADDING_NONE)
    ciphertext += encrypter.feed(data)
    ciphertext += encrypter.feed()

    return (iv, ciphertext)


def aes_cbc_no_padding_decrypt(key, data, iv):
    """
    Decrypts AES ciphertext in CBC mode using a 128, 192 or 256 bit key and no
    padding.

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 16-bytes long

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the plaintext
    """

    if len(iv) != 16:
        raise ValueError(pretty_message(
            '''
            iv must be 16 bytes long - is %s
            ''',
            len(iv)
        ))
    
    decrypter = Decrypter(AESModeOfOperationCBC(key, iv), padding=PADDING_NONE)
    decrypted = decrypter.feed(data)
    decrypted += decrypter.feed()

    return decrypted


def aes_cbc_pkcs7_encrypt(key, data, iv):
    """
    Encrypts plaintext using AES in CBC mode with a 128, 192 or 256 bit key and
    PKCS#7 padding.

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - either a byte string 16-bytes long or None
        to generate an IV

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if not iv:
        iv = rand_bytes(16)
    elif len(iv) != 16:
        raise ValueError(pretty_message(
            '''
            iv must be 16 bytes long - is %s
            ''',
            len(iv)
        ))
    ciphertext = b''
    encrypter = Encrypter(AESModeOfOperationCBC(key, iv), padding=PADDING_DEFAULT)
    ciphertext += encrypter.feed(data)
    ciphertext += encrypter.feed()

    return (iv, ciphertext)

def aes_cbc_pkcs7_decrypt(key, data, iv):
    """
    Decrypts AES ciphertext in CBC mode using a 128, 192 or 256 bit key

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 16-bytes long

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the plaintext
    """

    if len(iv) != 16:
        raise ValueError(pretty_message(
            '''
            iv must be 16 bytes long - is %s
            ''',
            len(iv)
        ))
    
    decrypter = Decrypter(AESModeOfOperationCBC(key, iv), padding=PADDING_DEFAULT)
    decrypted = decrypter.feed(data)
    decrypted += decrypter.feed()

    return decrypted

def rc4_encrypt(key, data):
    """
    Encrypts plaintext using RC4 with a 40-128 bit key

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The plaintext - a byte string

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the ciphertext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError(pretty_message(
            '''
            key must be 5 to 16 bytes (40 to 128 bits) long - is %s
            ''',
            len(key)
        ))
    ctx = RC4(key)
    return ctx.encrypt(data)

def rc4_decrypt(key, data):
    """
    Decrypts RC4 ciphertext using a 40-128 bit key

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The ciphertext - a byte string

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the plaintext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError(pretty_message(
            '''
            key must be 5 to 16 bytes (40 to 128 bits) long - is %s
            ''',
            len(key)
        ))

    ctx = RC4(key)
    return ctx.decrypt(data)

def rc2_cbc_pkcs5_encrypt(key, data, iv):
    """
    Encrypts plaintext using RC2 in CBC mode with a 40-128 bit key and PKCS#5
    padding.

    :param key:
        The encryption key - a byte string 8 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - a byte string 8-bytes long or None
        to generate an IV

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError(pretty_message(
            '''
            key must be 5 to 16 bytes (40 to 128 bits) long - is %s
            ''',
            len(key)
        ))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError(pretty_message(
            '''
            iv must be 8 bytes long - is %s
            ''',
            len(iv)
        ))
    
    ctx = RC2(key)
    return (iv, ctx.encrypt(data, RC2_MODE_CBC, iv, RC2_PADDING_PKCS5))


def rc2_cbc_pkcs5_decrypt(key, data, iv):
    """
    Decrypts RC2 ciphertext ib CBC mode using a 40-128 bit key and PKCS#5
    padding.

    :param key:
        The encryption key - a byte string 8 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 8 bytes long

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the plaintext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError(pretty_message(
            '''
            key must be 5 to 16 bytes (40 to 128 bits) long - is %s
            ''',
            len(key)
        ))

    if len(iv) != 8:
        raise ValueError(pretty_message(
            '''
            iv must be 8 bytes long - is %s
            ''',
            len(iv)
        ))
    ctx = RC2(key)
    return ctx.decrypt(data, RC2_MODE_CBC, iv, RC2_PADDING_PKCS5)

def tripledes_cbc_pkcs5_encrypt(key, data, iv):
    """
    Encrypts plaintext using 3DES in CBC mode using either the 2 or 3 key
    variant (16 or 24 byte long key) and PKCS#5 padding.

    :param key:
        The encryption key - a byte string 16 or 24 bytes long (2 or 3 key mode)

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - a byte string 8-bytes long or None
        to generate an IV

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) != 16 and len(key) != 24:
        raise ValueError(pretty_message(
            '''
            key must be 16 bytes (2 key) or 24 bytes (3 key) long - %s
            ''',
            len(key)
        ))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError(pretty_message(
            '''
            iv must be 8 bytes long - %s
            ''',
            len(iv)
        ))

    ctx = triple_des(key, mode=DES_CBC, IV=iv, padmode=DES_PAD_PKCS5)
    return (iv, ctx.encrypt(data))

def tripledes_cbc_pkcs5_decrypt(key, data, iv):
    """
    Decrypts 3DES ciphertext in CBC mode using either the 2 or 3 key variant
    (16 or 24 byte long key) and PKCS#5 padding.

    :param key:
        The encryption key - a byte string 16 or 24 bytes long (2 or 3 key mode)

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 8-bytes long

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the plaintext
    """

    if len(key) != 16 and len(key) != 24:
        raise ValueError(pretty_message(
            '''
            key must be 16 bytes (2 key) or 24 bytes (3 key) long - is %s
            ''',
            len(key)
        ))

    if len(iv) != 8:
        raise ValueError(pretty_message(
            '''
            iv must be 8 bytes long - is %s
            ''',
            len(iv)
        ))

    ctx = triple_des(key, mode=DES_CBC, IV=iv, padmode=DES_PAD_PKCS5)
    return ctx.decrypt(data)

def des_cbc_pkcs5_encrypt(key, data, iv):
    """
    Encrypts plaintext using DES in CBC mode with a 56 bit key and PKCS#5
    padding.

    :param key:
        The encryption key - a byte string 8 bytes long (includes error correction bits)

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - a byte string 8-bytes long or None
        to generate an IV

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) != 8:
        raise ValueError(pretty_message(
            '''
            key must be 8 bytes (56 bits + 8 parity bits) long - is %s
            ''',
            len(key)
        ))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError(pretty_message(
            '''
            iv must be 8 bytes long - is %s
            ''',
            len(iv)
        ))
    
    ctx = des(key, mode=DES_CBC, IV=iv, padmode=DES_PAD_PKCS5)
    return (iv, ctx.encrypt(data))

def des_cbc_pkcs5_decrypt(key, data, iv):
    """
    Decrypts DES ciphertext in CBC mode using a 56 bit key and PKCS#5 padding.

    :param key:
        The encryption key - a byte string 8 bytes long (includes error correction bits)

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 8-bytes long

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string of the plaintext
    """

    if len(key) != 8:
        raise ValueError(pretty_message(
            '''
            key must be 8 bytes (56 bits + 8 parity bits) long - is %s
            ''',
            len(key)
        ))

    if len(iv) != 8:
        raise ValueError(pretty_message(
            '''
            iv must be 8 bytes long - is %s
            ''',
            len(iv)
        ))
    
    ctx = des(key, mode=DES_CBC, IV=iv, padmode=DES_PAD_PKCS5)
    return ctx.decrypt(data)
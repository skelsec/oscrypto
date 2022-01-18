import hashlib
from shutil import ExecError
from .._errors import pretty_message
from asn1crypto import keys
from .._asn1 import (
    Certificate as Asn1Certificate,
    DHParameters,
    ECDomainParameters,
    PrivateKeyInfo,
    PublicKeyAlgorithm,
    PublicKeyInfo,
    RSAPublicKey,
    RSAPrivateKey,
)

from .._asymmetric import (
    _CertificateBase,
    _fingerprint,
    _parse_pkcs12,
    _PrivateKeyBase,
    _PublicKeyBase,
    _unwrap_private_key_info,
    parse_certificate,
    parse_private,
    parse_public,
)

from ..errors import AsymmetricKeyError, IncompleteAsymmetricKeyError, SignatureError
from .._types import type_name, str_cls, byte_cls, int_types
from ..util import constant_compare
from .external.pkcs1.primes import get_prime, is_prime
from .external.pkcs1.keys import MultiPrimeRsaPrivateKey, RsaPublicKey, generate_key_pair
from .external.pkcs1.rsaes_oaep import encrypt as encrypt_rsaes_oaep, decrypt as decrypt_rsaes_oaep
from .external.pkcs1.rsaes_pkcs1_v15 import encrypt as encrypt_rsaes_pkcs1_v15, decrypt as decrypt_rsaes_pkcs1_v15
from .external.pkcs1.rsassa_pkcs1_v15 import sign as sign_rsassa_pkcs1_v15, verify as verify_rsassa_pkcs1_v15
from .external.pkcs1.rsassa_pss import sign as sign_rsassa_pss, verify as verify_rsassa_pss
from .external.pkcs1.exceptions import InvalidSignature

__all__ = [
    'Certificate',
    'dsa_sign',
    'dsa_verify',
    'ecdsa_sign',
    'ecdsa_verify',
    'generate_pair',
    'load_certificate',
    'load_pkcs12',
    'load_private_key',
    'load_public_key',
    'parse_pkcs12',
    'PrivateKey',
    'PublicKey',
    'rsa_oaep_decrypt',
    'rsa_oaep_encrypt',
    'rsa_pkcs1v15_decrypt',
    'rsa_pkcs1v15_encrypt',
    'rsa_pkcs1v15_sign',
    'rsa_pkcs1v15_verify',
    'rsa_pss_sign',
    'rsa_pss_verify',
]

primes = {
    1024: {
        'p' : int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
        'g' : 2
    },
	1536: { 
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
	"g": 2
	},

	2048: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
	"g": 2
	},

	3072: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
	"g": 2
	},

	4096: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
	"g": 2
	},

	6144: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
	"g": 2
	},
	8192: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF,
	"g": 2
	}
}


class PrivateKey(_PrivateKeyBase):
    """
    Container for the OpenSSL representation of a private key
    """

    pkey = None
    _public_key = None

    # A reference to the library used in the destructor to make sure it hasn't
    # been garbage collected by the time this object is garbage collected
    _lib = None

    def __init__(self, pkey, asn1):
        """
        :param pkey:
            An MultiPrimeRSAKey from loading/importing the key

        :param asn1:
            An asn1crypto.keys.PrivateKeyInfo object
        """
        self.pkey = pkey
        self.asn1 = asn1


    @property
    def public_key(self):
        """
        :return:
            A PublicKey object corresponding to this private key.
        """

        raise NotImplementedError()

    @property
    def fingerprint(self):
        """
        Creates a fingerprint that can be compared with a public key to see if
        the two form a pair.

        This fingerprint is not compatible with fingerprints generated by any
        other software.

        :return:
            A byte string that is a sha256 hash of selected components (based
            on the key type)
        """

        if self._fingerprint is None:
            self._fingerprint = _fingerprint(self.asn1, load_private_key)
        return self._fingerprint

    def __del__(self):
        return

class PublicKey(_PublicKeyBase):
    """
    Container for the OpenSSL representation of a public key
    """

    evp_pkey = None

    # A reference to the library used in the destructor to make sure it hasn't
    # been garbage collected by the time this object is garbage collected
    _lib = None

    def __init__(self, evp_pkey, asn1):
        """
        :param evp_pkey:
            An OpenSSL EVP_PKEY value from loading/importing the key

        :param asn1:
            An asn1crypto.keys.PublicKeyInfo object
        """

        self.evp_pkey = evp_pkey
        self.asn1 = asn1
    
    @property
    def public_key(self):
        return self.evp_pkey

    def __del__(self):
        return


class Certificate(_CertificateBase):
    """
    Container for the OpenSSL representation of a certificate
    """

    x509 = None
    _public_key = None
    _self_signed = None

    def __init__(self, x509, asn1):
        """
        :param x509:
            An OpenSSL X509 value from loading/importing the certificate

        :param asn1:
            An asn1crypto.x509.Certificate object
        """

        self.x509 = x509
        self.asn1 = asn1

    @property
    def evp_pkey(self):
        """
        :return:
            The EVP_PKEY of the public key this certificate contains
        """

        return self.public_key.evp_pkey

    @property
    def public_key(self):
        """
        :return:
            The PublicKey object for the public key this certificate contains
        """
        if self.asn1['tbs_certificate']['subject_public_key_info'].algorithm != 'rsa':
            raise NotImplementedError()

        pk = PublicKey(None, self.asn1['tbs_certificate']['subject_public_key_info']).unwrap()
        if not self._public_key and self.asn1:
            evp_pkey = RsaPublicKey(
                n = int(pk['modulus']),
                e = int(pk['public_exponent'])
            )
            self._public_key = PublicKey(evp_pkey, self.asn1['tbs_certificate']['subject_public_key_info'])

        return self._public_key

    @property
    def self_signed(self):
        """
        :return:
            A boolean - if the certificate is self-signed
        """

        if self._self_signed is None:
            self._self_signed = False
            if self.asn1.self_signed in set(['yes', 'maybe']):

                signature_algo = self.asn1['signature_algorithm'].signature_algo
                hash_algo = self.asn1['signature_algorithm'].hash_algo

                if signature_algo == 'rsassa_pkcs1v15':
                    verify_func = rsa_pkcs1v15_verify
                elif signature_algo == 'dsa':
                    verify_func = dsa_verify
                elif signature_algo == 'ecdsa':
                    verify_func = ecdsa_verify
                else:
                    raise OSError(pretty_message(
                        '''
                        Unable to verify the signature of the certificate since
                        it uses the unsupported algorithm %s
                        ''',
                        signature_algo
                    ))

                try:
                    verify_func(
                        self.public_key,
                        self.asn1['signature_value'].native,
                        self.asn1['tbs_certificate'].dump(),
                        hash_algo
                    )
                    self._self_signed = True
                except (SignatureError):
                    pass

        return self._self_signed

    def __del__(self):
        return


def generate_pair(algorithm, bit_size=None, curve=None):
    """
    Generates a public/private key pair

    :param algorithm:
        The key algorithm - "rsa", "dsa" or "ec"

    :param bit_size:
        An integer - used for "rsa" and "dsa". For "rsa" the value maye be 1024,
        2048, 3072 or 4096. For "dsa" the value may be 1024, plus 2048 or 3072
        if OpenSSL 1.0.0 or newer is available.

    :param curve:
        A unicode string - used for "ec" keys. Valid values include "secp256r1",
        "secp384r1" and "secp521r1".

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A 2-element tuple of (PublicKey, PrivateKey). The contents of each key
        may be saved by calling .asn1.dump().
    """

    if algorithm not in set(['rsa', 'dsa', 'ec']):
        raise ValueError(pretty_message(
            '''
            algorithm must be one of "rsa", "dsa", "ec", not %s
            ''',
            repr(algorithm)
        ))

    if algorithm == 'rsa':
        if bit_size not in set([1024, 2048, 3072, 4096]):
            raise ValueError(pretty_message(
                '''
                bit_size must be one of 1024, 2048, 3072, 4096, not %s
                ''',
                repr(bit_size)
            ))

    elif algorithm == 'dsa':
        if bit_size not in set([1024, 2048, 3072]):
            raise ValueError(pretty_message(
                '''
                bit_size must be one of 1024, 2048, 3072, not %s
                ''',
                repr(bit_size)
            ))

    elif algorithm == 'ec':
        if curve not in set(['secp256r1', 'secp384r1', 'secp521r1']):
            raise ValueError(pretty_message(
                '''
                curve must be one of "secp256r1", "secp384r1", "secp521r1",
                not %s
                ''',
                repr(curve)
            ))

    if algorithm == 'rsa':
        public, private = generate_key_pair(bit_size)
        pubkeydict = {
            'modulus': public.n,
            'public_exponent': public.e
        }
        puka = {
            'algorithm' : keys.PublicKeyAlgorithmId('rsa')
        }
        puki = {
            'algorithm' : PublicKeyAlgorithm(puka),
            'public_key': keys.RSAPublicKey(pubkeydict),
        }

        privkey = keys.RSAPrivateKey()
        privkey['version'] = keys.RSAPrivateKeyVersion(0)
        privkey['modulus'] = private.n
        privkey['public_exponent'] = private.e
        privkey['private_exponent'] = private.blind_inv
        privkey['prime1'] = private.primes[0]
        privkey['prime2'] = private.primes[1]
        privkey['exponent1'] = private.exponents[0]
        privkey['exponent2'] = private.exponents[1]
        privkey['coefficient'] = private.crts[0]


        private_key_algo = keys.PrivateKeyAlgorithm()
        private_key_algo['algorithm'] = keys.PrivateKeyAlgorithmId('rsa')
        
        pki = {
            'version': 0,
            'private_key_algorithm' : private_key_algo,
            'private_key' : privkey,   
        }
        
        pubkey = PublicKey(public, PublicKeyInfo(puki))
        privkey = PrivateKey(private, PrivateKeyInfo(pki))

    elif algorithm == 'dsa':
        raise NotImplementedError()
        

    elif algorithm == 'ec':
        #curve_id = {
        #    'secp256r1': LibcryptoConst.NID_X9_62_prime256v1,
        #    'secp384r1': LibcryptoConst.NID_secp384r1,
        #    'secp521r1': LibcryptoConst.NID_secp521r1,
        #}[curve]
        raise NotImplementedError()

    return (pubkey, privkey)

def generate_dh_parameters(bit_size):
    """
    Generates DH parameters for use with Diffie-Hellman key exchange. Returns
    a structure in the format of DHParameter defined in PKCS#3, which is also
    used by the OpenSSL dhparam tool.

    THIS CAN BE VERY TIME CONSUMING!

    :param bit_size:
        The integer bit size of the parameters to generate. Must be between 512
        and 4096, and divisible by 64. Recommended secure value as of early 2016
        is 2048, with an absolute minimum of 1024.

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        An asn1crypto.algos.DHParameters object. Use
        oscrypto.asymmetric.dump_dh_parameters() to save to disk for usage with
        web servers.
    """

    if not isinstance(bit_size, int_types):
        raise TypeError(pretty_message(
            '''
            bit_size must be an integer, not %s
            ''',
            type_name(bit_size)
        ))

    if bit_size < 512:
        raise ValueError('bit_size must be greater than or equal to 512')

    if bit_size > 4096:
        raise ValueError('bit_size must be less than or equal to 4096')

    if bit_size % 64 != 0:
        raise ValueError('bit_size must be a multiple of 64')
    
    if bit_size not in primes:
        raise NotImplementedError("Pure python DH parameter generation will take forever. Please use the pre-baked parameters with bit_size=[%s]" % ','.join(str(k) for k in primes))
        # 1. generate prime Q
        # 2. (2Q + 1) = P should be also a prime
        # 3. G can be anything (2 should work) [random between 0 and Q and check if (val)**Q mod P == 1 and if it does then ok!)]
        # 4. Q is a pribe
        p = None
        g = 2
        while True:
            q = get_prime()
            p = (2*q) + 1
            if is_prime(p) is True:
                break
        dh = {
            'p' : p,
            'g' : g,
        }
    

    return DHParameters(primes[bit_size])


def load_certificate(source):
    """
    Loads an x509 certificate into a Certificate object

    :param source:
        A byte string of file contents, a unicode string filename or an
        asn1crypto.x509.Certificate object

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A Certificate object
    """

    if isinstance(source, Asn1Certificate):
        certificate = source

    elif isinstance(source, byte_cls):
        certificate = parse_certificate(source)

    elif isinstance(source, str_cls):
        with open(source, 'rb') as f:
            certificate = parse_certificate(f.read())

    else:
        raise TypeError(pretty_message(
            '''
            source must be a byte string, unicode string or
            asn1crypto.x509.Certificate object, not %s
            ''',
            type_name(source)
        ))

    return _load_x509(certificate)


def _load_x509(certificate):
    """
    Loads an ASN.1 object of an x509 certificate into a Certificate object

    :param certificate:
        An asn1crypto.x509.Certificate object

    :return:
        A Certificate object
    """
    return Certificate(None, certificate)

def load_private_key(source, password=None):
    """
    Loads a private key into a PrivateKey object

    :param source:
        A byte string of file contents, a unicode string filename or an
        asn1crypto.keys.PrivateKeyInfo object

    :param password:
        A byte or unicode string to decrypt the private key file. Unicode
        strings will be encoded using UTF-8. Not used is the source is a
        PrivateKeyInfo object.

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when the private key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A PrivateKey object
    """

    if isinstance(source, PrivateKeyInfo):
        private_object = source

    else:
        if password is not None:
            if isinstance(password, str_cls):
                password = password.encode('utf-8')
            if not isinstance(password, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    password must be a byte string, not %s
                    ''',
                    type_name(password)
                ))

        if isinstance(source, str_cls):
            with open(source, 'rb') as f:
                source = f.read()

        elif not isinstance(source, byte_cls):
            raise TypeError(pretty_message(
                '''
                source must be a byte string, unicode string or
                asn1crypto.keys.PrivateKeyInfo object, not %s
                ''',
                type_name(source)
            ))

        private_object = parse_private(source, password)

    return _load_key(private_object)

def _load_key(private_object):
    """
    Loads a private key into a PrivateKey object

    :param private_object:
        An asn1crypto.keys.PrivateKeyInfo object

    :return:
        A PrivateKey object
    """
    if private_object.algorithm != 'rsa':
        raise NotImplementedError()

    source = _unwrap_private_key_info(private_object).dump()
    source = RSAPrivateKey.load(source)
    pkey = MultiPrimeRsaPrivateKey(
        primes = [int(source['prime1']), int(source['prime2'])], 
        e = int(source['public_exponent']),
        )    
    return PrivateKey(pkey, private_object)

def load_public_key(source):
    """
    Loads a public key into a PublicKey object

    :param source:
        A byte string of file contents, a unicode string filename or an
        asn1crypto.keys.PublicKeyInfo object

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when the public key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A PublicKey object
    """

    if isinstance(source, PublicKeyInfo):
        public_key = source

    elif isinstance(source, byte_cls):
        public_key = parse_public(source)

    elif isinstance(source, str_cls):
        with open(source, 'rb') as f:
            public_key = parse_public(f.read())

    else:
        raise TypeError(pretty_message(
            '''
            source must be a byte string, unicode string or
            asn1crypto.keys.PublicKeyInfo object, not %s
            ''',
            type_name(source)
        ))

    if public_key.algorithm != 'rsa':
        raise NotImplementedError()
    
    try:

        pk = public_key['public_key'].parsed
        pub = RsaPublicKey(
            n = int(pk['modulus']),
            e = int(pk['public_exponent'])
        )

        return PublicKey(pub, public_key)
    except Exception as e:
        print(source)
        raise e

def parse_pkcs12(data, password=None):
    """
    Parses a PKCS#12 ANS.1 DER-encoded structure and extracts certs and keys

    :param data:
        A byte string of a DER-encoded PKCS#12 file

    :param password:
        A byte string of the password to any encrypted data

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by one of the OS decryption functions

    :return:
        A three-element tuple of:
         1. An asn1crypto.keys.PrivateKeyInfo object
         2. An asn1crypto.x509.Certificate object
         3. A list of zero or more asn1crypto.x509.Certificate objects that are
            "extra" certificates, possibly intermediates from the cert chain
    """

    return _parse_pkcs12(data, password, load_private_key)

def load_pkcs12(source, password=None):
    """
    Loads a .p12 or .pfx file into a PrivateKey object and one or more
    Certificates objects

    :param source:
        A byte string of file contents or a unicode string filename

    :param password:
        A byte or unicode string to decrypt the PKCS12 file. Unicode strings
        will be encoded using UTF-8.

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when a contained key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A three-element tuple containing (PrivateKey, Certificate, [Certificate, ...])
    """

    if password is not None:
        if isinstance(password, str_cls):
            password = password.encode('utf-8')
        if not isinstance(password, byte_cls):
            raise TypeError(pretty_message(
                '''
                password must be a byte string, not %s
                ''',
                type_name(password)
            ))

    if isinstance(source, str_cls):
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise TypeError(pretty_message(
            '''
            source must be a byte string or a unicode string, not %s
            ''',
            type_name(source)
        ))

    key_info, cert_info, extra_certs_info = parse_pkcs12(source, password)

    key = None
    cert = None

    if key_info:
        key = _load_key(key_info)

    if cert_info:
        cert = _load_x509(cert_info)

    extra_certs = [_load_x509(info) for info in extra_certs_info]

    return (key, cert, extra_certs)

def rsa_pkcs1v15_encrypt(certificate_or_public_key, data):
    """
    Encrypts a byte string using an RSA public key or certificate. Uses PKCS#1
    v1.5 padding.

    :param certificate_or_public_key:
        A PublicKey or Certificate object

    :param data:
        A byte string, with a maximum length 11 bytes less than the key length
        (in bytes)

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the encrypted data
    """

    return _encrypt(certificate_or_public_key, data, 'RSA_PKCS1_PADDING')

def rsa_pkcs1v15_decrypt(private_key, ciphertext):
    """
    Decrypts a byte string using an RSA private key. Uses PKCS#1 v1.5 padding.

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        A byte string of the encrypted data

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the original plaintext
    """

    return _decrypt(private_key, ciphertext, 'RSA_PKCS1_PADDING')


def rsa_oaep_encrypt(certificate_or_public_key, data):
    """
    Encrypts a byte string using an RSA public key or certificate. Uses PKCS#1
    OAEP padding with SHA1.

    :param certificate_or_public_key:
        A PublicKey or Certificate object

    :param data:
        A byte string, with a maximum length 41 bytes (or more) less than the
        key length (in bytes)

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the encrypted data
    """

    return _encrypt(certificate_or_public_key, data, 'RSA_PKCS1_OAEP_PADDING')

def rsa_oaep_decrypt(private_key, ciphertext):
    """
    Decrypts a byte string using an RSA private key. Uses PKCS#1 OAEP padding
    with SHA1.

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        A byte string of the encrypted data

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the original plaintext
    """

    return _decrypt(private_key, ciphertext, 'RSA_PKCS1_OAEP_PADDING')

def _encrypt(certificate_or_public_key, data, padding):
    """
    Encrypts plaintext using an RSA public key or certificate

    :param certificate_or_public_key:
        A PublicKey, Certificate or PrivateKey object

    :param data:
        The byte string to encrypt

    :param padding:
        The padding mode to use

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the encrypted data
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise TypeError(pretty_message(
            '''
            certificate_or_public_key must be an instance of the Certificate or
            PublicKey class, not %s
            ''',
            type_name(certificate_or_public_key)
        ))

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    rsa = None
    if padding == 'RSA_PKCS1_PADDING':
        return encrypt_rsaes_pkcs1_v15(certificate_or_public_key.public_key, data)
    elif padding == 'RSA_PKCS1_OAEP_PADDING':
        return encrypt_rsaes_oaep(certificate_or_public_key.public_key, data)
    else:
        raise NotImplementedError()

def _decrypt(private_key, ciphertext, padding):
    """
    Decrypts RSA ciphertext using a private key

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        The ciphertext - a byte string

    :param padding:
        The padding mode to use

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the plaintext
    """

    if not isinstance(private_key, PrivateKey):
        raise TypeError(pretty_message(
            '''
            private_key must be an instance of the PrivateKey class, not %s
            ''',
            type_name(private_key)
        ))

    if not isinstance(ciphertext, byte_cls):
        raise TypeError(pretty_message(
            '''
            ciphertext must be a byte string, not %s
            ''',
            type_name(ciphertext)
        ))

    if padding == 'RSA_PKCS1_PADDING':
        return decrypt_rsaes_pkcs1_v15(private_key.pkey, ciphertext)
    elif padding == 'RSA_PKCS1_OAEP_PADDING':
        return decrypt_rsaes_oaep(private_key.pkey, ciphertext)
    else:
        raise NotImplementedError()

def rsa_pkcs1v15_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSASSA-PKCS-v1.5 signature.

    When the hash_algorithm is "raw", the operation is identical to RSA
    public key decryption. That is: the data is not hashed and no ASN.1
    structure with an algorithm identifier of the hash algorithm is placed in
    the encrypted byte string.

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384",
        "sha512" or "raw"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if certificate_or_public_key.algorithm != 'rsa':
        raise ValueError(pretty_message(
            '''
            The key specified is not an RSA public key, but %s
            ''',
            certificate_or_public_key.algorithm.upper()
        ))

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)

def rsa_pss_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSASSA-PSS signature. For the PSS padding the mask gen algorithm
    will be mgf1 using the same hash algorithm as the signature. The salt length
    with be the length of the hash algorithm, and the trailer field with be the
    standard 0xBC byte.

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if certificate_or_public_key.algorithm != 'rsa':
        raise ValueError(pretty_message(
            '''
            The key specified is not an RSA public key, but %s
            ''',
            certificate_or_public_key.algorithm.upper()
        ))

    return _verify(certificate_or_public_key, signature, data, hash_algorithm, rsa_pss_padding=True)

def dsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies a DSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    raise NotImplementedError()


def ecdsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an ECDSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    raise NotImplementedError()


def _verify(certificate_or_public_key, signature, data, hash_algorithm, rsa_pss_padding=False):
    """
    Verifies an RSA, DSA or ECDSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :param rsa_pss_padding:
        If the certificate_or_public_key is an RSA key, this enables PSS padding

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise TypeError(pretty_message(
            '''
            certificate_or_public_key must be an instance of the Certificate or
            PublicKey class, not %s
            ''',
            type_name(certificate_or_public_key)
        ))

    if not isinstance(signature, byte_cls):
        raise TypeError(pretty_message(
            '''
            signature must be a byte string, not %s
            ''',
            type_name(signature)
        ))

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    valid_hash_algorithms = set(['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'])
    if certificate_or_public_key.algorithm == 'rsa' and not rsa_pss_padding:
        valid_hash_algorithms |= set(['raw'])

    if hash_algorithm not in valid_hash_algorithms:
        valid_hash_algorithms_error = '"md5", "sha1", "sha224", "sha256", "sha384", "sha512"'
        if certificate_or_public_key.algorithm == 'rsa' and not rsa_pss_padding:
            valid_hash_algorithms_error += ', "raw"'
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of %s, not %s
            ''',
            valid_hash_algorithms_error,
            repr(hash_algorithm)
        ))

    if certificate_or_public_key.algorithm != 'rsa' and rsa_pss_padding:
        raise ValueError(pretty_message(
            '''
            PSS padding can only be used with RSA keys - the key provided is a
            %s key
            ''',
            certificate_or_public_key.algorithm.upper()
        ))

    if certificate_or_public_key.algorithm == 'rsa' and hash_algorithm == 'raw':
        if len(data) > certificate_or_public_key.byte_size - 11:
            raise ValueError(pretty_message(
                '''
                data must be 11 bytes shorter than the key size when
                hash_algorithm is "raw" - key size is %s bytes, but data is
                %s bytes long
                ''',
                certificate_or_public_key.byte_size,
                len(data)
            ))

        rsa = None

    if certificate_or_public_key.algorithm != 'rsa':
        raise NotImplementedError()
    
    ld = {
        'md5'   : hashlib.md5,
        'sha1'  : hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512, 
    }
    

    try:
        res = False
        if rsa_pss_padding is True:
            res = verify_rsassa_pss(certificate_or_public_key.public_key, data, signature, hash_class=ld[hash_algorithm])
        else:
            res = verify_rsassa_pkcs1_v15(certificate_or_public_key.public_key, data, signature, ld[hash_algorithm])
        if res is False:
            raise InvalidSignature()

    except InvalidSignature:
        raise SignatureError('Signature is invalid')

def rsa_pkcs1v15_sign(private_key, data, hash_algorithm):
    """
    Generates an RSASSA-PKCS-v1.5 signature.

    When the hash_algorithm is "raw", the operation is identical to RSA
    private key encryption. That is: the data is not hashed and no ASN.1
    structure with an algorithm identifier of the hash algorithm is placed in
    the encrypted byte string.

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384",
        "sha512" or "raw"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if private_key.algorithm != 'rsa':
        raise ValueError(pretty_message(
            '''
            The key specified is not an RSA private key, but %s
            ''',
            private_key.algorithm.upper()
        ))

    return _sign(private_key, data, hash_algorithm)


def rsa_pss_sign(private_key, data, hash_algorithm):
    """
    Generates an RSASSA-PSS signature. For the PSS padding the mask gen
    algorithm will be mgf1 using the same hash algorithm as the signature. The
    salt length with be the length of the hash algorithm, and the trailer field
    with be the standard 0xBC byte.

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if private_key.algorithm != 'rsa':
        raise ValueError(pretty_message(
            '''
            The key specified is not an RSA private key, but %s
            ''',
            private_key.algorithm.upper()
        ))

    return _sign(private_key, data, hash_algorithm, rsa_pss_padding=True)


def dsa_sign(private_key, data, hash_algorithm):
    """
    Generates a DSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    raise NotImplementedError()


def ecdsa_sign(private_key, data, hash_algorithm):
    """
    Generates an ECDSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    raise NotImplementedError()


def _sign(private_key, data, hash_algorithm, rsa_pss_padding=False):
    """
    Generates an RSA, DSA or ECDSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :param rsa_pss_padding:
        If the private_key is an RSA key, this enables PSS padding

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if not isinstance(private_key, PrivateKey):
        raise TypeError(pretty_message(
            '''
            private_key must be an instance of PrivateKey, not %s
            ''',
            type_name(private_key)
        ))

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    valid_hash_algorithms = set(['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'])
    if private_key.algorithm == 'rsa' and not rsa_pss_padding:
        valid_hash_algorithms |= set(['raw'])

    if hash_algorithm not in valid_hash_algorithms:
        valid_hash_algorithms_error = '"md5", "sha1", "sha224", "sha256", "sha384", "sha512"'
        if private_key.algorithm == 'rsa' and not rsa_pss_padding:
            valid_hash_algorithms_error += ', "raw"'
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of %s, not %s
            ''',
            valid_hash_algorithms_error,
            repr(hash_algorithm)
        ))

    if private_key.algorithm != 'rsa' and rsa_pss_padding:
        raise ValueError(pretty_message(
            '''
            PSS padding can only be used with RSA keys - the key provided is a
            %s key
            ''',
            private_key.algorithm.upper()
        ))

    ld = {
        'md5'   : hashlib.md5,
        'sha1'  : hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512, 
    }
    
    if rsa_pss_padding is True:
        return sign_rsassa_pss(private_key.pkey, data, hash_class=ld[hash_algorithm])
    
    return sign_rsassa_pkcs1_v15(private_key.pkey, data, hash_class=ld[hash_algorithm])
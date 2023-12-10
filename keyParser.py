import base64
import binascii
import hashlib
import datetime

# Define supported Secure SNI version
ESNI_VERSION = list()
ESNI_VERSION.extend([bytearray([0xff, 0x01]),
                    bytearray([0xff, 0x02]),
                    bytearray([0xff, 0x03])])

ECH_VERSION = list()
ECH_VERSION.extend([bytearray([0xff,0x03]),
                    bytearray([0xff, 0x07]),
                    bytearray([0xfe, 0x08]),
                    bytearray([0xfe, 0x09]),
                    bytearray([0xfe, 0x0a]),
                    bytearray([0xfe, 0x0c]),
                    bytearray([0xfe, 0x0d])])

# TLSv1.3 RFC
# https://tools.ietf.org/html/rfc8446#appendix-B.3.1.4
#
# enum {
#   unallocated_RESERVED(0x0000),
#
#   /* Elliptic Curve Groups (ECDHE) */
#   obsolete_RESERVED(0x0001..0x0016),
#   secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
#   obsolete_RESERVED(0x001A..0x001C),
#   x25519(0x001D), x448(0x001E),
#
#   /* Finite Field Groups (DHE) */
#   ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
#   ffdhe6144(0x0103), ffdhe8192(0x0104),
#
#   /* Reserved Code Points */
#   ffdhe_private_use(0x01FC..0x01FF),
#   ecdhe_private_use(0xFE00..0xFEFF),
#   obsolete_RESERVED(0xFF01..0xFF02),
#   (0xFFFF)
# } NamedGroup;

TLS_NAMED_GROUPS = {
    "0017": "secp256r1",
    "0018": "secp384r1",
    "0019": "secp521r1",
    "001d": "x25519",
    "001e": "x448",
    "0100": "ffdhe2048",
    "0101": "ffdhe3072",
    "0102": "ffdhe4096",
    "0103": "ffdhe6144",
    "0104": "ffdhe8192",
}

# TLSv1.3 RFC
# https://tools.ietf.org/html/rfc8446#appendix-B.4
#
# +------------------------------+-------------+
# | Description                  | Value       |
# +------------------------------+-------------+
# | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
# |                              |             |
# | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
# |                              |             |
# | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
# |                              |             |
# | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
# |                              |             |
# | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
# +------------------------------+-------------+

TLS_CIPHERS = {
    "1301": "TLS_AES_128_GCM_SHA256",
    "1302": "TLS_AES_256_GCM_SHA384",
    "1303": "TLS_CHACHA20_POLY1305_SHA25",
    "1304": "TLS_AES_128_CCM_SHA256",
    "1305": "TLS_AES_128_CCM_8_SHA256",
}

# https://www.rfc-editor.org/rfc/rfc9180#name-key-encapsulation-mechanism
#
# Value	    KEM	                        Nsecret	Nenc    Npk	Nsk	Auth	Reference
# 0x0000	Reserved	                N/A	    N/A	    N/A	N/A	yes	    RFC 9180
# 0x0010	DHKEM(P-256, HKDF-SHA256)	32	    65	    65	32	yes	    [NISTCurves], [RFC5869]
# 0x0011	DHKEM(P-384, HKDF-SHA384)	48	    97	    97	48	yes	    [NISTCurves], [RFC5869]
# 0x0012	DHKEM(P-521, HKDF-SHA512)	64	    133	    133	66	yes	    [NISTCurves], [RFC5869]
# 0x0020	DHKEM(X25519, HKDF-SHA256)	32	    32	    32	32	yes	    [RFC5869], [RFC7748]
# 0x0021	DHKEM(X448, HKDF-SHA512)	64	    56	    56	56	yes	    [RFC5869], [RFC7748]

KEM2Len = {
    "0010": 65,
    "0011": 97,
    "0012": 133,
    "0020": 32,
    "0021": 56
}

KEM = {
    "0010": "DHKEM(P-256, HKDF-SHA256)",
    "0011": "DHKEM(P-384, HKDF-SHA384)",
    "0012": "DHKEM(P-521, HKDF-SHA512)",
    "0020": "DHKEM(X25519, HKDF-SHA256)",
    "0021": "DHKEM(X448, HKDF-SHA512)"
}

# https://www.rfc-editor.org/rfc/rfc9180#name-key-derivation-functions-kd
#
# Value	    KDF	        Nh	Reference
# 0x0000	Reserved	N/A	RFC 9180
# 0x0001	HKDF-SHA256	32	[RFC5869]
# 0x0002	HKDF-SHA384	48	[RFC5869]
# 0x0003	HKDF-SHA512	64	[RFC5869]

KDF = {
    "0001": "HKDF-SHA256",
    "0002": "HKDF-SHA384",
    "0003": "HKDF-SHA512"
}

# https://www.rfc-editor.org/rfc/rfc9180#name-authenticated-encryption-wi
# 
# Value	    AEAD	            Nk	Nn	Nt	Reference
# 0x0000	Reserved	        N/A	N/A	N/A	RFC 9180
# 0x0001	AES-128-GCM	        16	12	16	[GCM]
# 0x0002	AES-256-GCM	        32	12	16	[GCM]
# 0x0003	ChaCha20Poly1305	32	12	16	[RFC8439]
# 0xFFFF	Export-only	        N/A	N/A	N/A	RFC 9180

AEAD = {
    "0001": "AES-128-GCM",
    "0002": "AES-256-GCM",
    "0003": "ChaCha20Poly1305",
    "FFFF": "Export-only"
}

def check_ESNIKey(response):
    # https://tools.ietf.org/html/draft-ietf-tls-esni-03#section-4.1
    #
    # struct {
    #     uint16 version;
    #     uint8 checksum[4];
    #     KeyShareEntry keys<4..2^16-1>;
    #     CipherSuite cipher_suites<2..2^16-2>;
    #     uint16 padded_length;
    #     uint64 not_before;
    #     uint64 not_after;
    #     Extension extensions<0..2^16-1>;
    # } ESNIKeys;

    output = dict()

    try:
        array = bytearray(base64.b64decode(response))
    except binascii.Error as e:
        return False, e, output

    version = array[:2]
    if version in ESNI_VERSION:
        output["version"] = version.hex()
    else:
        return False, "Unknown ESNI draft version", output

    checksum_array = array[:]
    checksum_array[2:6] = b'\x00' * 4
    checksum_hash = hashlib.sha256(checksum_array).digest()
    if checksum_hash[:4] == array[2:6]:
        output["checksum"] = checksum_hash[:4].hex()
    else:
        return False, "The key checksum does not match", output

    array = array[6:]

    keyshare_length = int(array[:2].hex(), 16)

    named_group = TLS_NAMED_GROUPS[array[2:4].hex()]
    output["NamedGroup"] = named_group

    key_exchange = array[4:keyshare_length].hex()
    output["KeyExchange"] = key_exchange

    array = array[4+keyshare_length:]
    cipher = array[:2].hex()
    output["CipherSuites"] = TLS_CIPHERS[cipher]

    padded_len = int(array[2:4].hex(), 16)
    output["PaddedLength"] = padded_len

    not_before = int(array[4:12].hex(), 16)
    output["NotBefore"] = datetime.datetime.utcfromtimestamp(not_before)

    not_after = int(array[12:20].hex(), 16)
    output["NotAfter"] = datetime.datetime.utcfromtimestamp(not_after)

    extensions = array[20:].hex()
    output["extensions"] = extensions

    return True, None, output

def check_ECHKey(response):
    # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#name-encrypted-clienthello-confi
    #
    # opaque HpkePublicKey<1..2^16-1>;
    # uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
    # uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
    # uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke

    # struct {
    #     HpkeKdfId kdf_id;
    #     HpkeAeadId aead_id;
    # } HpkeSymmetricCipherSuite;

    # struct {
    #     uint8 config_id;
    #     HpkeKemId kem_id;
    #     HpkePublicKey public_key;
    #     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
    # } HpkeKeyConfig;

    # struct {
    #     HpkeKeyConfig key_config;
    #     uint8 maximum_name_length;
    #     opaque public_name<1..255>;
    #     Extension extensions<0..2^16-1>;
    # } ECHConfigContents;

    # struct {
    #     uint16 version;
    #     uint16 length;
    #     select (ECHConfig.version) {
    #       case 0xfe0d: ECHConfigContents contents;
    #     }
    # } ECHConfig;
    
    array = response[2:]

    output = dict()

    version = array[:2]
    if version in ECH_VERSION:
        output["version"] = version.hex()
    else:
        return False, "Unknown ECH draft version", output
    
    length = int(array[2:4].hex(), 16)
    output["length"] = length

    # Parse struct HpkeKeyConfig
    config_id = array[4:5].hex()
    output["KeyConf_ConfigID"] = config_id

    kem_id = array[5:7].hex()
    if kem_id in KEM2Len:
        output["KeyConf_KemID"] = kem_id
        length_pubKey = KEM2Len[kem_id]
    else:
        return False, "Unknown KEM ID", output
    
    array = array[7:]
    public_key = array[:length_pubKey]
    output["KeyConf_PublicKey"] = public_key

    # Parse struct HpkeSymmetricCipherSuite
    array = array[length_pubKey+4:]
    kdf_id = array[:2].hex()
    if kdf_id in KDF:
        output["Cipher_KdfID"] = kdf_id
        output["Cipher_Kdf"] = KDF[kdf_id]
    else:
        return False, "Unknown KDF ID", output
    
    aead_id = array[2:4].hex()
    if aead_id in AEAD:
        output["Cipher_AeadID"] = aead_id
        output["Cipher_Aead"] = AEAD[aead_id]
    else:
        return False, "Unknown AEAD ID", output
    
    array = array[4:]
    max_name_length = int(array[:2].hex(), 16)
    public_name = array[2:2+max_name_length].decode("utf-8") 
    output["PublicName"] = public_name

    extensions = array[2+max_name_length:].hex()
    output["extensions"] = extensions

    return True, None, output
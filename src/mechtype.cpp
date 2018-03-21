//----------------------------------------------------------------------------------------
// mechtype.cpp
//
// This source code is licensed under the GPL v2 license found in the
// LICENSE.txt file in the root directory of this source tree.
//
// Written by Benton Stark (benton.stark@gmail.com)
// Sept. 7, 2016
//----------------------------------------------------------------------------------------

#include "mechtype.h"

// pkcs11-curr-v2.40-os mechanism definitions
#define CKM_DSA_SHA3_224                                 0x00000018
#define CKM_DSA_SHA3_256                                 0x00000019
#define CKM_DSA_SHA3_384                                 0x0000001A
#define CKM_DSA_SHA3_512                                 0x0000001B
#define CKM_SHA3_256_RSA_PKCS                            0x00000060
#define CKM_SHA3_384_RSA_PKCS                            0x00000061
#define CKM_SHA3_512_RSA_PKCS                            0x00000062
#define CKM_SHA3_256_RSA_PKCS_PSS                        0x00000063
#define CKM_SHA3_384_RSA_PKCS_PSS                        0x00000064
#define CKM_SHA3_512_RSA_PKCS_PSS                        0x00000065
#define CKM_SHA3_224_RSA_PKCS                            0x00000066
#define CKM_SHA3_224_RSA_PKCS_PSS                        0x00000067
#define CKM_SHA3_256                                     0x000002B0
#define CKM_SHA3_256_HMAC                                0x000002B1
#define CKM_SHA3_256_HMAC_GENERAL                        0x000002B2
#define CKM_SHA3_224                                     0x000002B5
#define CKM_SHA3_224_HMAC                                0x000002B6
#define CKM_SHA3_224_HMAC_GENERAL                        0x000002B7
#define CKM_SHA3_384                                     0x000002C0
#define CKM_SHA3_384_HMAC                                0x000002C1
#define CKM_SHA3_384_HMAC_GENERAL                        0x000002C2
#define CKM_SHA3_512                                     0x000002D0
#define CKM_SHA3_512_HMAC                                0x000002D1
#define CKM_SHA3_512_HMAC_GENERAL                        0x000002D2
#define CKM_SHA3_256_KEY_DERIVE                          0x00000397
#define CKM_SHA3_224_KEY_DERIVE                          0x00000398
#define CKM_SHA3_384_KEY_DERIVE                          0x00000399
#define CKM_SHA3_512_KEY_DERIVE                          0x0000039A
#define CKM_SHAKE_128_KEY_DERIVE                         0x0000039B
#define CKM_SHAKE_256_KEY_DERIVE                         0x0000039C

// additional mechanisms proposed or in-use but not defined in v2.20
#define CKM_ECDSA_SHA224                                 0x00001043
#define CKM_ECDSA_SHA256                                 0x00001044
#define CKM_ECDSA_SHA384                                 0x00001045
#define CKM_ECDSA_SHA512                                 0x00001046
#define CKM_DSA_FIPS_G_GEN                               0x00000013
#define CKM_DSA_SHA224                                   0x00000014
#define CKM_DSA_SHA256                                   0x00000015
#define CKM_DSA_SHA384                                   0x00000016
#define CKM_AES_GCM                                      0x00001087
#define CKM_AES_CCM                                      0x00001088
#define CKM_DSA_PROBABLISTIC_PARAMETER_GEN               0x00002003
#define CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN               0x00002004
#define CKM_AES_OFB                                      0x00002104
#define CKM_AES_CFB64                                    0x00002105
#define CKM_AES_CFB8                                     0x00002106
#define CKM_AES_CFB128                                   0x00002107
#define CKM_AES_CFB1                                     0x00002108
#define CKM_AES_KEY_WRAP                                 0x00002109
#define CKM_AES_KEY_WRAP_PAD                             0x0000210A
#define CKM_RSA_PKCS_TPM_1_1                             0x00004001
#define CKM_RSA_PKCS_OAEP_TPM_1_1                        0x00004002
#define CKM_AES_GMAC                                     0x0000108E

// safenet luna vendor defined mechanisms
#define SAFENET_CKM_ECDSA_SHA224                         0x80000122
#define SAFENET_CKM_ECDSA_SHA256                         0x80000123
#define SAFENET_CKM_ECDSA_SHA384                         0x80000124
#define SAFENET_CKM_ECDSA_SHA512                         0x80000125
#define SAFENET_CKM_AES_CBC_PAD_IPSEC                    0x8000012f
#define SAFENET_CKM_AES_CFB8                             0x80000118
#define SAFENET_CKM_AES_CFB128                           0x80000119
#define SAFENET_CKM_AES_OFB                              0x8000011a
#define SAFENET_CKM_AES_GCM                              0x8000011c
#define SAFENET_CKM_DES3_CBC_PAD_IPSEC                   0x8000012e
#define SAFENET_CKM_ARIA_CMAC                            0x80000128
#define SAFENET_CKM_ARIA_CMAC_GENERAL                    0x80000129
#define SAFENET_CKM_ARIA_CFB8                            0x8000011d
#define SAFENET_CKM_ARIA_CFB128                          0x8000011e
#define SAFENET_CKM_ARIA_OFB                             0x8000011f
#define SAFENET_CKM_ARIA_L_ECB                           0x80000130
#define SAFENET_CKM_ARIA_L_CBC                           0x80000131
#define SAFENET_CKM_ARIA_L_CBC_PAD                       0x80000132
#define SAFENET_CKM_ARIA_L_MAC                           0x80000133
#define SAFENET_CKM_ARIA_L_MAC_GENERAL                   0x80000134
#define SAFENET_CKM_XOR_BASE_AND_DATA_W_KDF              0x80000a01
#define SAFENET_CKM_DSA_SHA224                           0x80000140
#define SAFENET_CKM_DSA_SHA256                           0x80000141
#define SAFENET_CKM_NIST_PRF_KDF                         0x80000a02
#define SAFENET_CKM_PRF_KDF                              0x80000a03
#define SAFENET_CKM_XOR_BASE_AND_KEY                     0x8000001b
#define SAFENET_CKM_PBE_SHA1_DES2_EDE_CBC_OLD            0x0000801f
#define SAFENET_CKM_PBE_SHA1_DES3_EDE_CBC_OLD            0x0000801e
#define SAFENET_CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX     0x0000800d

// thales / ncipher vendor defined mechanisms
#define THALES_CKM_WRAP_RSA_CRT_COMPONENTS               0xde436973
#define THALES_CKM_CAC_TK_DERIVATION                     0xde436974
#define THALES_CKM_SHA_1_HMAC_KEY_GEN                    0xde436975
#define THALES_CKM_MD5_HMAC_KEY_GEN                      0xde436978
#define THALES_CKM_KCDSA                                 0xde43698a
#define THALES_CKM_NC_SHA224_HMAC_KEY_GEN                0xde436996
#define THALES_CKM_NC_SHA256_HMAC_KEY_GEN                0xde436997
#define THALES_CKM_NC_SHA384_HMAC_KEY_GEN                0xde436998
#define THALES_CKM_NC_SHA512_HMAC_KEY_GEN                0xde436999
#define THALES_CKM_NC_AES_CMAC_KEY_DERIVATION            0xde436c72
#define THALES_CKM_NC_AES_CMAC_KEY_DERIVATION_SCP03      0xde436c73
#define THALES_CKM_NC_ECKDF_HYPERLEDGER                  0xde436f82
#define THALES_CKM_NC_AES_CMAC                           0xde4379f9
#define THALES_CKM_PUBLIC_FROM_PRIVATE                   0xde438a72

// utimaco vendor mechanisms
#define UTIMACO_CKM_RSA_PKCS_MULTI                       0x80000001
#define UTIMACO_CKM_RSA_X_509_MULTI                      0x80000003
#define UTIMACO_CKM_DES3_RETAIL_MAC                      0x80000135
#define UTIMACO_CKM_ECDSA_ECIES                          0x80001201
#define UTIMACO_CKM_ECDSA_MULTI                          0x80001401
#define UTIMACO_CKM_DES_CBC_WRAP                         0x80003001
#define UTIMACO_CKM_AES_CBC_WRAP                         0x80003002
#define UTIMACO_CKM_UTI_AES_CMAC                         0x80000136
#define UTIMACO_CKM_UTI_ECDSA_SHA228                     0x80001042
#define UTIMACO_CKM_UTI_ECDSA_SHA256                     0x80001043
#define UTIMACO_CKM_UTI_ECDSA_SHA384                     0x80001044
#define UTIMACO_CKM_UTI_ECDSA_SHA512                     0x80001045
#define UTIMACO_CKM_ECDSA_RIPMD160                       0x8000104a
#define UTIMACO_CKM_ECDSA_SHA3_228                       0x8000104b
#define UTIMACO_CKM_ECDSA_SHA3_256                       0x8000104c
#define UTIMACO_CKM_ECDSA_SHA3_384                       0x8000104d
#define UTIMACO_CKM_ECDSA_SHA3_512                       0x8000104e
#define UTIMACO_CKM_ECKA                                 0x80001101
#define UTIMACO_CKM_UTI_DSA_SHA228                       0x80002042
#define UTIMACO_CKM_UTI_DSA_SHA256                       0x80002043
#define UTIMACO_CKM_UTI_DSA_SHA384                       0x80002044
#define UTIMACO_CKM_UTI_DSA_SHA512                       0x80002045
#define UTIMACO_CKM_DSA_RIPMD160                         0x8000204a


// convert mechanism value to string name
char* __mechanism_type_to_str(CK_MECHANISM_TYPE mech_type) {
    switch (mech_type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        return (char*) "CKM_RSA_PKCS_KEY_PAIR_GEN";
    case CKM_RSA_PKCS:
        return (char*) "CKM_RSA_PKCS";
    case CKM_RSA_9796:
        return (char*) "CKM_RSA_9796";
    case CKM_RSA_X_509:
        return (char*) "CKM_RSA_X_509";
    case CKM_MD2_RSA_PKCS:
        return (char*) "CKM_MD2_RSA_PKCS";
    case CKM_MD5_RSA_PKCS:
        return (char*) "CKM_MD5_RSA_PKCS";
    case CKM_SHA1_RSA_PKCS:
        return (char*) "CKM_SHA1_RSA_PKCS";
    case CKM_RIPEMD128_RSA_PKCS:
        return (char*) "CKM_RIPEMD128_RSA_PKCS";
    case CKM_RIPEMD160_RSA_PKCS:
        return (char*) "CKM_RIPEMD160_RSA_PKCS";
    case CKM_RSA_PKCS_OAEP:
        return (char*) "CKM_RSA_PKCS_OAEP";
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
        return (char*) "CKM_RSA_X9_31_KEY_PAIR_GEN";
    case CKM_RSA_X9_31:
        return (char*) "CKM_RSA_X9_31";
    case CKM_SHA1_RSA_X9_31:
        return (char*) "CKM_SHA1_RSA_X9_31";
    case CKM_RSA_PKCS_PSS:
        return (char*) "CKM_RSA_PKCS_PSS";
    case CKM_SHA1_RSA_PKCS_PSS:
        return (char*) "CKM_SHA1_RSA_PKCS_PSS";
    case CKM_DSA_KEY_PAIR_GEN:
        return (char*) "CKM_DSA_KEY_PAIR_GEN";
    case CKM_DSA:
        return (char*) "CKM_DSA";
    case CKM_DSA_SHA1:
        return (char*) "CKM_DSA_SHA1";
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        return (char*) "CKM_DH_PKCS_KEY_PAIR_GEN";
    case CKM_DH_PKCS_DERIVE:
        return (char*) "CKM_DH_PKCS_DERIVE";
    case CKM_X9_42_DH_KEY_PAIR_GEN:
        return (char*) "CKM_X9_42_DH_KEY_PAIR_GEN";
    case CKM_X9_42_DH_DERIVE:
        return (char*) "CKM_X9_42_DH_DERIVE";
    case CKM_X9_42_DH_HYBRID_DERIVE:
        return (char*) "CKM_X9_42_DH_HYBRID_DERIVE";
    case CKM_X9_42_MQV_DERIVE:
        return (char*) "CKM_X9_42_MQV_DERIVE";
    case CKM_SHA256_RSA_PKCS:
        return (char*) "CKM_SHA256_RSA_PKCS";
    case CKM_SHA384_RSA_PKCS:
        return (char*) "CKM_SHA384_RSA_PKCS";
    case CKM_SHA512_RSA_PKCS:
        return (char*) "CKM_SHA512_RSA_PKCS";
    case CKM_SHA256_RSA_PKCS_PSS:
        return (char*) "CKM_SHA256_RSA_PKCS_PSS";
    case CKM_SHA384_RSA_PKCS_PSS:
        return (char*) "CKM_SHA384_RSA_PKCS_PSS";
    case CKM_SHA512_RSA_PKCS_PSS:
        return (char*) "CKM_SHA512_RSA_PKCS_PSS";
    case CKM_SHA224_RSA_PKCS:
        return (char*) "CKM_SHA224_RSA_PKCS";
    case CKM_SHA224_RSA_PKCS_PSS:
        return (char*) "CKM_SHA224_RSA_PKCS_PSS";
    case CKM_RC2_KEY_GEN:
        return (char*) "CKM_RC2_KEY_GEN";
    case CKM_RC2_ECB:
        return (char*) "CKM_RC2_ECB";
    case CKM_RC2_CBC:
        return (char*) "CKM_RC2_CBC";
    case CKM_RC2_MAC:
        return (char*) "CKM_RC2_MAC";
    case CKM_RC2_MAC_GENERAL:
        return (char*) "CKM_RC2_MAC_GENERAL";
    case CKM_RC2_CBC_PAD:
        return (char*) "CKM_RC2_CBC_PAD";
    case CKM_RC4_KEY_GEN:
        return (char*) "CKM_RC4_KEY_GEN";
    case CKM_RC4:
        return (char*) "CKM_RC4";
    case CKM_DES_KEY_GEN:
        return (char*) "CKM_DES_KEY_GEN";
    case CKM_DES_ECB:
        return (char*) "CKM_DES_ECB";
    case CKM_DES_CBC:
        return (char*) "CKM_DES_CBC";
    case CKM_DES_MAC:
        return (char*) "CKM_DES_MAC";
    case CKM_DES_MAC_GENERAL:
        return (char*) "CKM_DES_MAC_GENERAL";
    case CKM_DES_CBC_PAD:
        return (char*) "CKM_DES_CBC_PAD";
    case CKM_DES2_KEY_GEN:
        return (char*) "CKM_DES2_KEY_GEN";
    case CKM_DES3_KEY_GEN:
        return (char*) "CKM_DES3_KEY_GEN";
    case CKM_DES3_ECB:
        return (char*) "CKM_DES3_ECB";
    case CKM_DES3_CBC:
        return (char*) "CKM_DES3_CBC";
    case CKM_DES3_MAC:
        return (char*) "CKM_DES3_MAC";
    case CKM_DES3_MAC_GENERAL:
        return (char*) "CKM_DES3_MAC_GENERAL";
    case CKM_DES3_CBC_PAD:
        return (char*) "CKM_DES3_CBC_PAD";
    case CKM_DES3_CMAC_GENERAL:
        return (char*) "CKM_DES3_CMAC_GENERAL";
    case CKM_DES3_CMAC:
        return (char*) "CKM_DES3_CMAC";
    case CKM_CDMF_KEY_GEN:
        return (char*) "CKM_CDMF_KEY_GEN";
    case CKM_CDMF_ECB:
        return (char*) "CKM_CDMF_ECB";
    case CKM_CDMF_CBC:
        return (char*) "CKM_CDMF_CBC";
    case CKM_CDMF_MAC:
        return (char*) "CKM_CDMF_MAC";
    case CKM_CDMF_MAC_GENERAL:
        return (char*) "CKM_CDMF_MAC_GENERAL";
    case CKM_CDMF_CBC_PAD:
        return (char*) "CKM_CDMF_CBC_PAD";
    case CKM_DES_OFB64:
        return (char*) "CKM_DES_OFB64";
    case CKM_DES_OFB8:
        return (char*) "CKM_DES_OFB8";
    case CKM_DES_CFB64:
        return (char*) "CKM_DES_CFB64";
    case CKM_DES_CFB8:
        return (char*) "CKM_DES_CFB8";
    case CKM_MD2:
        return (char*) "CKM_MD2";
    case CKM_MD2_HMAC:
        return (char*) "CKM_MD2_HMAC";
    case CKM_MD2_HMAC_GENERAL:
        return (char*) "CKM_MD2_HMAC_GENERAL";
    case CKM_MD5:
        return (char*) "CKM_MD5";
    case CKM_MD5_HMAC:
        return (char*) "CKM_MD5_HMAC";
    case CKM_MD5_HMAC_GENERAL:
        return (char*) "CKM_MD5_HMAC_GENERAL";
    case CKM_SHA_1:
        return (char*) "CKM_SHA_1";
    case CKM_SHA_1_HMAC:
        return (char*) "CKM_SHA_1_HMAC";
    case CKM_SHA_1_HMAC_GENERAL:
        return (char*) "CKM_SHA_1_HMAC_GENERAL";
    case CKM_RIPEMD128:
        return (char*) "CKM_RIPEMD128";
    case CKM_RIPEMD128_HMAC:
        return (char*) "CKM_RIPEMD128_HMAC";
    case CKM_RIPEMD128_HMAC_GENERAL:
        return (char*) "CKM_RIPEMD128_HMAC_GENERAL";
    case CKM_RIPEMD160:
        return (char*) "CKM_RIPEMD160";
    case CKM_RIPEMD160_HMAC:
        return (char*) "CKM_RIPEMD160_HMAC";
    case CKM_RIPEMD160_HMAC_GENERAL:
        return (char*) "CKM_RIPEMD160_HMAC_GENERAL";
    case CKM_SHA256:
        return (char*) "CKM_SHA_256";
    case CKM_SHA256_HMAC:
        return (char*) "CKM_SHA_256_HMAC";
    case CKM_SHA256_HMAC_GENERAL:
        return (char*) "CKM_SHA_256_HMAC_GENERAL";
    case CKM_SHA224:
        return (char*) "CKM_SHA_224";
    case CKM_SHA224_HMAC:
        return (char*) "CKM_SHA_224_HMAC";
    case CKM_SHA224_HMAC_GENERAL:
        return (char*) "CKM_SHA_224_HMAC_GENERAL";
    case CKM_SHA384:
        return (char*) "CKM_SHA_384";
    case CKM_SHA384_HMAC:
        return (char*) "CKM_SHA_384_HMAC";
    case CKM_SHA384_HMAC_GENERAL:
        return (char*) "CKM_SHA_384_HMAC_GENERAL";
    case CKM_SHA512:
        return (char*) "CKM_SHA_512";
    case CKM_SHA512_HMAC:
        return (char*) "CKM_SHA_512_HMAC";
    case CKM_SHA512_HMAC_GENERAL:
        return (char*) "CKM_SHA_512_HMAC_GENERAL";
    case CKM_SECURID_KEY_GEN:
        return (char*) "CKM_SECURID_KEY_GEN";
    case CKM_SECURID:
        return (char*) "CKM_SECURID";
    case CKM_HOTP_KEY_GEN:
        return (char*) "CKM_HOTP_KEY_GEN";
    case CKM_HOTP:
        return (char*) "CKM_HOTP";
    case CKM_ACTI:
        return (char*) "CKM_ACTI";
    case CKM_ACTI_KEY_GEN:
        return (char*) "CKM_ACTI_KEY_GEN";
    case CKM_CAST_KEY_GEN:
        return (char*) "CKM_CAST_KEY_GEN";
    case CKM_CAST_ECB:
        return (char*) "CKM_CAST_ECB";
    case CKM_CAST_CBC:
        return (char*) "CKM_CAST_CBC";
    case CKM_CAST_MAC:
        return (char*) "CKM_CAST_MAC";
    case CKM_CAST_MAC_GENERAL:
        return (char*) "CKM_CAST_MAC_GENERAL";
    case CKM_CAST_CBC_PAD:
        return (char*) "CKM_CAST_CBC_PAD";
    case CKM_CAST3_KEY_GEN:
        return (char*) "CKM_CAST3_KEY_GEN";
    case CKM_CAST3_ECB:
        return (char*) "CKM_CAST3_ECB";
    case CKM_CAST3_CBC:
        return (char*) "CKM_CAST3_CBC";
    case CKM_CAST3_MAC:
        return (char*) "CKM_CAST3_MAC";
    case CKM_CAST3_MAC_GENERAL:
        return (char*) "CKM_CAST3_MAC_GENERAL";
    case CKM_CAST3_CBC_PAD:
        return (char*) "CKM_CAST3_CBC_PAD";
    case CKM_CAST5_KEY_GEN:
        return (char*) "CKM_CAST5_KEY_GEN";
    case CKM_CAST5_ECB:
        return (char*) "CKM_CAST5_ECB";
    case CKM_CAST5_CBC:
        return (char*) "CKM_CAST5_CBC";
    case CKM_CAST5_MAC:
        return (char*) "CKM_CAST5_MAC";
    case CKM_CAST5_MAC_GENERAL:
        return (char*) "CKM_CAST5_MAC_GENERAL";
    case CKM_CAST5_CBC_PAD:
        return (char*) "CKM_CAST5_CBC_PAD";
    case CKM_RC5_KEY_GEN:
        return (char*) "CKM_RC5_KEY_GEN";
    case CKM_RC5_ECB:
        return (char*) "CKM_RC5_ECB";
    case CKM_RC5_CBC:
        return (char*) "CKM_RC5_CBC";
    case CKM_RC5_MAC:
        return (char*) "CKM_RC5_MAC";
    case CKM_RC5_MAC_GENERAL:
        return (char*) "CKM_RC5_MAC_GENERAL";
    case CKM_RC5_CBC_PAD:
        return (char*) "CKM_RC5_CBC_PAD";
    case CKM_IDEA_KEY_GEN:
        return (char*) "CKM_IDEA_KEY_GEN";
    case CKM_IDEA_ECB:
        return (char*) "CKM_IDEA_ECB";
    case CKM_IDEA_CBC:
        return (char*) "CKM_IDEA_CBC";
    case CKM_IDEA_MAC:
        return (char*) "CKM_IDEA_MAC";
    case CKM_IDEA_MAC_GENERAL:
        return (char*) "CKM_IDEA_MAC_GENERAL";
    case CKM_IDEA_CBC_PAD:
        return (char*) "CKM_IDEA_CBC_PAD";
    case CKM_GENERIC_SECRET_KEY_GEN:
        return (char*) "CKM_GENERIC_SECRET_KEY_GEN";
    case CKM_CONCATENATE_BASE_AND_KEY:
        return (char*) "CKM_CONCATENATE_BASE_AND_KEY";
    case CKM_CONCATENATE_BASE_AND_DATA:
        return (char*) "CKM_CONCATENATE_BASE_AND_DATA";
    case CKM_CONCATENATE_DATA_AND_BASE:
        return (char*) "CKM_CONCATENATE_DATA_AND_BASE";
    case CKM_XOR_BASE_AND_DATA:
        return (char*) "CKM_XOR_BASE_AND_DATA";
    case CKM_EXTRACT_KEY_FROM_KEY:
        return (char*) "CKM_EXTRACT_KEY_FROM_KEY";
    case CKM_SSL3_PRE_MASTER_KEY_GEN:
        return (char*) "CKM_SSL3_PRE_MASTER_KEY_GEN";
    case CKM_SSL3_MASTER_KEY_DERIVE:
        return (char*) "CKM_SSL3_MASTER_KEY_DERIVE";
    case CKM_SSL3_KEY_AND_MAC_DERIVE:
        return (char*) "CKM_SSL3_KEY_AND_MAC_DERIVE";
    case CKM_SSL3_MASTER_KEY_DERIVE_DH:
        return (char*) "CKM_SSL3_MASTER_KEY_DERIVE_DH";
    case CKM_TLS_PRE_MASTER_KEY_GEN:
        return (char*) "CKM_TLS_PRE_MASTER_KEY_GEN";
    case CKM_TLS_MASTER_KEY_DERIVE:
        return (char*) "CKM_TLS_MASTER_KEY_DERIVE";
    case CKM_TLS_KEY_AND_MAC_DERIVE:
        return (char*) "CKM_TLS_KEY_AND_MAC_DERIVE";
    case CKM_TLS_MASTER_KEY_DERIVE_DH:
        return (char*) "CKM_TLS_MASTER_KEY_DERIVE_DH";
    case CKM_TLS_PRF:
        return (char*) "CKM_TLS_PRF";
    case CKM_SSL3_MD5_MAC:
        return (char*) "CKM_SSL3_MD5_MAC";
    case CKM_SSL3_SHA1_MAC:
        return (char*) "CKM_SSL3_SHA1_MAC";
    case CKM_MD5_KEY_DERIVATION:
        return (char*) "CKM_MD5_KEY_DERIVATION";
    case CKM_MD2_KEY_DERIVATION:
        return (char*) "CKM_MD2_KEY_DERIVATION";
    case CKM_SHA1_KEY_DERIVATION:
        return (char*) "CKM_SHA1_KEY_DERIVATION";
    case CKM_SHA256_KEY_DERIVATION:
        return (char*) "CKM_SHA256_KEY_DERIVATION";
    case CKM_SHA384_KEY_DERIVATION:
        return (char*) "CKM_SHA384_KEY_DERIVATION";
    case CKM_SHA512_KEY_DERIVATION:
        return (char*) "CKM_SHA512_KEY_DERIVATION";
    case CKM_SHA224_KEY_DERIVATION:
        return (char*) "CKM_SHA224_KEY_DERIVATION";
    case CKM_PBE_MD2_DES_CBC:
        return (char*) "CKM_PBE_MD2_DES_CBC";
    case CKM_PBE_MD5_DES_CBC:
        return (char*) "CKM_PBE_MD5_DES_CBC";
    case CKM_PBE_MD5_CAST_CBC:
        return (char*) "CKM_PBE_MD5_CAST_CBC";
    case CKM_PBE_MD5_CAST3_CBC:
        return (char*) "CKM_PBE_MD5_CAST3_CBC";
    case CKM_PBE_MD5_CAST5_CBC:
        return (char*) "CKM_PBE_MD5_CAST5_CBC";
    case CKM_PBE_SHA1_CAST5_CBC:
        return (char*) "CKM_PBE_SHA1_CAST5_CBC";
    case CKM_PBE_SHA1_RC4_128:
        return (char*) "CKM_PBE_SHA1_RC4_128";
    case CKM_PBE_SHA1_RC4_40:
        return (char*) "CKM_PBE_SHA1_RC4_40";
    case CKM_PBE_SHA1_DES3_EDE_CBC:
        return (char*) "CKM_PBE_SHA1_DES3_EDE_CBC";
    case CKM_PBE_SHA1_DES2_EDE_CBC:
        return (char*) "CKM_PBE_SHA1_DES2_EDE_CBC";
    case CKM_PBE_SHA1_RC2_128_CBC:
        return (char*) "CKM_PBE_SHA1_RC2_128_CBC";
    case CKM_PBE_SHA1_RC2_40_CBC:
        return (char*) "CKM_PBE_SHA1_RC2_40_CBC";
    case CKM_PKCS5_PBKD2:
        return (char*) "CKM_PKCS5_PBKD2";
    case CKM_PBA_SHA1_WITH_SHA1_HMAC:
        return (char*) "CKM_PBA_SHA1_WITH_SHA1_HMAC";
    case CKM_WTLS_PRE_MASTER_KEY_GEN:
        return (char*) "CKM_WTLS_PRE_MASTER_KEY_GEN";
    case CKM_WTLS_MASTER_KEY_DERIVE:
        return (char*) "CKM_WTLS_MASTER_KEY_DERIVE";
    case CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:
        return (char*) "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC";
    case CKM_WTLS_PRF:
        return (char*) "CKM_WTLS_PRF";
    case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
        return (char*) "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
    case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
        return (char*) "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
    case CKM_KEY_WRAP_LYNKS:
        return (char*) "CKM_KEY_WRAP_LYNKS";
    case CKM_KEY_WRAP_SET_OAEP:
        return (char*) "CKM_KEY_WRAP_SET_OAEP";
    case CKM_CMS_SIG:
        return (char*) "CKM_CMS_SIG";
    case CKM_KIP_DERIVE:
        return (char*) "CKM_KIP_DERIVE";
    case CKM_KIP_WRAP:
        return (char*) "CKM_KIP_WRAP";
    case CKM_KIP_MAC:
        return (char*) "CKM_KIP_MAC";
    case CKM_CAMELLIA_KEY_GEN:
        return (char*) "CKM_CAMELLIA_KEY_GEN";
    case CKM_CAMELLIA_ECB:
        return (char*) "CKM_CAMELLIA_ECB";
    case CKM_CAMELLIA_CBC:
        return (char*) "CKM_CAMELLIA_CBC";
    case CKM_CAMELLIA_MAC:
        return (char*) "CKM_CAMELLIA_MAC";
    case CKM_CAMELLIA_MAC_GENERAL:
        return (char*) "CKM_CAMELLIA_MAC_GENERAL";
    case CKM_CAMELLIA_CBC_PAD:
        return (char*) "CKM_CAMELLIA_CBC_PAD";
    case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
        return (char*) "CKM_CAMELLIA_ECB_ENCRYPT_DATA";
    case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
        return (char*) "CKM_CAMELLIA_CBC_ENCRYPT_DATA";
    case CKM_CAMELLIA_CTR:
        return (char*) "CKM_CAMELLIA_CTR";
    case CKM_ARIA_KEY_GEN:
        return (char*) "CKM_ARIA_KEY_GEN";
    case CKM_ARIA_ECB:
        return (char*) "CKM_ARIA_ECB";
    case CKM_ARIA_CBC:
        return (char*) "CKM_ARIA_CBC";
    case CKM_ARIA_MAC:
        return (char*) "CKM_ARIA_MAC";
    case CKM_ARIA_MAC_GENERAL:
        return (char*) "CKM_ARIA_MAC_GENERAL";
    case CKM_ARIA_CBC_PAD:
        return (char*) "CKM_ARIA_CBC_PAD";
    case CKM_ARIA_ECB_ENCRYPT_DATA:
        return (char*) "CKM_ARIA_ECB_ENCRYPT_DATA";
    case CKM_ARIA_CBC_ENCRYPT_DATA:
        return (char*) "CKM_ARIA_CBC_ENCRYPT_DATA";
    case CKM_SKIPJACK_KEY_GEN:
        return (char*) "CKM_SKIPJACK_KEY_GEN";
    case CKM_SKIPJACK_ECB64:
        return (char*) "CKM_SKIPJACK_ECB64";
    case CKM_SKIPJACK_CBC64:
        return (char*) "CKM_SKIPJACK_CBC64";
    case CKM_SKIPJACK_OFB64:
        return (char*) "CKM_SKIPJACK_OFB64";
    case CKM_SKIPJACK_CFB64:
        return (char*) "CKM_SKIPJACK_CFB64";
    case CKM_SKIPJACK_CFB32:
        return (char*) "CKM_SKIPJACK_CFB32";
    case CKM_SKIPJACK_CFB16:
        return (char*) "CKM_SKIPJACK_CFB16";
    case CKM_SKIPJACK_CFB8:
        return (char*) "CKM_SKIPJACK_CFB8";
    case CKM_SKIPJACK_WRAP:
        return (char*) "CKM_SKIPJACK_WRAP";
    case CKM_SKIPJACK_PRIVATE_WRAP:
        return (char*) "CKM_SKIPJACK_PRIVATE_WRAP";
    case CKM_SKIPJACK_RELAYX:
        return (char*) "CKM_SKIPJACK_RELAYX";
    case CKM_KEA_KEY_PAIR_GEN:
        return (char*) "CKM_KEA_KEY_PAIR_GEN";
    case CKM_KEA_KEY_DERIVE:
        return (char*) "CKM_KEA_KEY_DERIVE";
    case CKM_FORTEZZA_TIMESTAMP:
        return (char*) "CKM_FORTEZZA_TIMESTAMP";
    case CKM_BATON_KEY_GEN:
        return (char*) "CKM_BATON_KEY_GEN";
    case CKM_BATON_ECB128:
        return (char*) "CKM_BATON_ECB128";
    case CKM_BATON_ECB96:
        return (char*) "CKM_BATON_ECB96";
    case CKM_BATON_CBC128:
        return (char*) "CKM_BATON_CBC128";
    case CKM_BATON_COUNTER:
        return (char*) "CKM_BATON_COUNTER";
    case CKM_BATON_SHUFFLE:
        return (char*) "CKM_BATON_SHUFFLE";
    case CKM_BATON_WRAP:
        return (char*) "CKM_BATON_WRAP";
    case CKM_ECDSA_KEY_PAIR_GEN:
        return (char*) "CKM_ECDSA_KEY_PAIR_GEN";
    case CKM_ECDSA:
        return (char*) "CKM_ECDSA";
    case CKM_ECDSA_SHA1:
        return (char*) "CKM_ECDSA_SHA1";
    case CKM_ECDSA_SHA224:
        return (char*) "CKM_ECDSA_SHA224";
    case CKM_ECDSA_SHA256:
        return (char*) "CKM_ECDSA_SHA256";
    case CKM_ECDSA_SHA384:
        return (char*) "CKM_ECDSA_SHA384";
    case CKM_ECDSA_SHA512:
        return (char*) "CKM_ECDSA_SHA512";
    case CKM_ECDH1_DERIVE:
        return (char*) "CKM_ECDH1_DERIVE";
    case CKM_ECDH1_COFACTOR_DERIVE:
        return (char*) "CKM_ECDH1_COFACTOR_DERIVE";
    case CKM_ECMQV_DERIVE:
        return (char*) "CKM_ECMQV_DERIVE";
    case CKM_JUNIPER_KEY_GEN:
        return (char*) "CKM_JUNIPER_KEY_GEN";
    case CKM_JUNIPER_ECB128:
        return (char*) "CKM_JUNIPER_ECB128";
    case CKM_JUNIPER_CBC128:
        return (char*) "CKM_JUNIPER_CBC128";
    case CKM_JUNIPER_COUNTER:
        return (char*) "CKM_JUNIPER_COUNTER";
    case CKM_JUNIPER_SHUFFLE:
        return (char*) "CKM_JUNIPER_SHUFFLE";
    case CKM_JUNIPER_WRAP:
        return (char*) "CKM_JUNIPER_WRAP";
    case CKM_FASTHASH:
        return (char*) "CKM_FASTHASH";
    case CKM_AES_KEY_GEN:
        return (char*) "CKM_AES_KEY_GEN";
    case CKM_AES_ECB:
        return (char*) "CKM_AES_ECB";
    case CKM_AES_CBC:
        return (char*) "CKM_AES_CBC";
    case CKM_AES_MAC:
        return (char*) "CKM_AES_MAC";
    case CKM_AES_MAC_GENERAL:
        return (char*) "CKM_AES_MAC_GENERAL";
    case CKM_AES_CBC_PAD:
        return (char*) "CKM_AES_CBC_PAD";
    case CKM_AES_CTR:
        return (char*) "CKM_AES_CTR";
    case CKM_AES_CMAC_GENERAL:
        return (char*) "CKM_AES_CMAC_GENERAL";
    case CKM_AES_CMAC:
        return (char*) "CKM_AES_CMAC";
    case CKM_BLOWFISH_KEY_GEN:
        return (char*) "CKM_BLOWFISH_KEY_GEN";
    case CKM_BLOWFISH_CBC:
        return (char*) "CKM_BLOWFISH_CBC";
    case CKM_TWOFISH_KEY_GEN:
        return (char*) "CKM_TWOFISH_KEY_GEN";
    case CKM_TWOFISH_CBC:
        return (char*) "CKM_TWOFISH_CBC";
    case CKM_DES_ECB_ENCRYPT_DATA:
        return (char*) "CKM_DES_ECB_ENCRYPT_DATA";
    case CKM_DES_CBC_ENCRYPT_DATA:
        return (char*) "CKM_DES_CBC_ENCRYPT_DATA";
    case CKM_DES3_ECB_ENCRYPT_DATA:
        return (char*) "CKM_DES3_ECB_ENCRYPT_DATA";
    case CKM_DES3_CBC_ENCRYPT_DATA:
        return (char*) "CKM_DES3_CBC_ENCRYPT_DATA";
    case CKM_AES_ECB_ENCRYPT_DATA:
        return (char*) "CKM_AES_ECB_ENCRYPT_DATA";
    case CKM_AES_CBC_ENCRYPT_DATA:
        return (char*) "CKM_AES_CBC_ENCRYPT_DATA";
    case CKM_DSA_PARAMETER_GEN:
        return (char*) "CKM_DSA_PARAMETER_GEN";
    case CKM_DH_PKCS_PARAMETER_GEN:
        return (char*) "CKM_DH_PKCS_PARAMETER_GEN";
    case CKM_X9_42_DH_PARAMETER_GEN:
        return (char*) "CKM_X9_42_DH_PARAMETER_GEN";
    case CKM_DSA_SHA3_224:
        return (char*) "CKM_DSA_SHA3_224";
    case CKM_DSA_SHA3_256:
        return (char*) "CKM_DSA_SHA3_256";
    case CKM_DSA_SHA3_384:
        return (char*) "CKM_DSA_SHA3_384";
    case CKM_DSA_SHA3_512:
        return (char*) "CKM_DSA_SHA3_512";
    case CKM_SHA3_256_RSA_PKCS:
        return (char*) "CKM_SHA3_256_RSA_PKCS";
    case CKM_SHA3_384_RSA_PKCS:
        return (char*) "CKM_SHA3_384_RSA_PKCS";
    case CKM_SHA3_512_RSA_PKCS:
        return (char*) "CKM_SHA3_512_RSA_PKCS";
    case CKM_SHA3_256_RSA_PKCS_PSS:
        return (char*) "CKM_SHA3_256_RSA_PKCS_PSS";
    case CKM_SHA3_384_RSA_PKCS_PSS:
        return (char*) "CKM_SHA3_384_RSA_PKCS_PSS";
    case CKM_SHA3_512_RSA_PKCS_PSS:
        return (char*) "CKM_SHA3_512_RSA_PKCS_PSS";
    case CKM_SHA3_224_RSA_PKCS:
        return (char*) "CKM_SHA3_224_RSA_PKCS";
    case CKM_SHA3_224_RSA_PKCS_PSS:
        return (char*) "CKM_SHA3_224_RSA_PKCS_PSS";
    case CKM_SHA3_256:
        return (char*) "CKM_SHA3_256";
    case CKM_SHA3_256_HMAC:
        return (char*) "CKM_SHA3_256_HMAC";
    case CKM_SHA3_256_HMAC_GENERAL:
        return (char*) "CKM_SHA3_256_HMAC_GENERAL";
    case CKM_SHA3_224:
        return (char*) "CKM_SHA3_224";
    case CKM_SHA3_224_HMAC:
        return (char*) "CKM_SHA3_224_HMAC";
    case CKM_SHA3_224_HMAC_GENERAL:
        return (char*) "CKM_SHA3_224_HMAC_GENERAL";
    case CKM_SHA3_384:
        return (char*) "CKM_SHA3_384";
    case CKM_SHA3_384_HMAC:
        return (char*) "CKM_SHA3_384_HMAC";
    case CKM_SHA3_384_HMAC_GENERAL:
        return (char*) "CKM_SHA3_384_HMAC_GENERAL";
    case CKM_SHA3_512:
        return (char*) "CKM_SHA3_512";
    case CKM_SHA3_512_HMAC:
        return (char*) "CKM_SHA3_512_HMAC";
    case CKM_SHA3_512_HMAC_GENERAL:
        return (char*) "CKM_SHA3_512_HMAC_GENERAL";
    case CKM_SHA3_256_KEY_DERIVE:
        return (char*) "CKM_SHA3_256_KEY_DERIVE";
    case CKM_SHA3_224_KEY_DERIVE:
        return (char*) "CKM_SHA3_224_KEY_DERIVE";
    case CKM_SHA3_384_KEY_DERIVE:
        return (char*) "CKM_SHA3_384_KEY_DERIVE";
    case CKM_SHAKE_128_KEY_DERIVE:
        return (char*) "CKM_SHAKE_128_KEY_DERIVE";
    case CKM_SHAKE_256_KEY_DERIVE:
        return (char*) "CKM_SHAKE_256_KEY_DERIVE";
    case CKM_DSA_FIPS_G_GEN:
        return (char*) "CKM_DSA_FIPS_G_GEN";
    case CKM_DSA_SHA224:
        return (char*) "CKM_DSA_SHA224";
    case CKM_DSA_SHA256:
        return (char*) "CKM_DSA_SHA256";
    case CKM_DSA_SHA384:
        return (char*) "CKM_DSA_SHA384";
    case CKM_AES_GCM:
        return (char*) "CKM_AES_GCM";
    case CKM_AES_CCM:
        return (char*) "CKM_AES_CCM";
    case CKM_DSA_PROBABLISTIC_PARAMETER_GEN:
        return (char*) "CKM_DSA_PROBABLISTIC_PARAMETER_GEN";
    case CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
        return (char*) "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN";
    case CKM_AES_OFB:
        return (char*) "CKM_AES_OFB";
    case CKM_AES_CFB64:
        return (char*) "CKM_AES_CFB64";
    case CKM_AES_CFB8:
        return (char*) "CKM_AES_CFB8";
    case CKM_AES_CFB128:
        return (char*) "CKM_AES_CFB128";
    case CKM_AES_CFB1:
        return (char*) "CKM_AES_CFB1";
    case CKM_AES_KEY_WRAP:
        return (char*) "CKM_AES_KEY_WRAP";
    case CKM_AES_KEY_WRAP_PAD:
        return (char*) "CKM_AES_KEY_WRAP_PAD";
    case CKM_RSA_PKCS_TPM_1_1:
        return (char*) "CKM_RSA_PKCS_TPM_1_1";
    case CKM_RSA_PKCS_OAEP_TPM_1_1:
        return (char*) "CKM_RSA_PKCS_OAEP_TPM_1_1";
    case CKM_AES_GMAC:
        return (char*) "CKM_AES_GMAC";
    case CKM_SHA3_512_KEY_DERIVE:
        return (char*) "CKM_SHA3_512_KEY_DERIVE";
    case SAFENET_CKM_ECDSA_SHA224:
        return (char*) "CKM_ECDSA_SHA224 [safenet]";
    case SAFENET_CKM_ECDSA_SHA256:
        return (char*) "CKM_ECDSA_SHA256 [safenet]";
    case SAFENET_CKM_ECDSA_SHA384:
        return (char*) "CKM_ECDSA_SHA384 [safenet]";
    case SAFENET_CKM_ECDSA_SHA512:
        return (char*) "CKM_ECDSA_SHA512 [safenet]";
    case SAFENET_CKM_AES_CBC_PAD_IPSEC:
        return (char*) "CKM_AES_CBC_PAD_IPSEC [safenet]";
    case SAFENET_CKM_AES_CFB8:
        return (char*) "CKM_AES_CFB8 [safenet]";
    case SAFENET_CKM_AES_CFB128:
        return (char*) "CKM_AES_CFB128 [safenet]";
    case SAFENET_CKM_AES_OFB:
        return (char*) "CKM_AES_OFB [safenet]";
    case SAFENET_CKM_AES_GCM:
        return (char*) "CKM_AES_GCM [safenet]";
    case SAFENET_CKM_DES3_CBC_PAD_IPSEC:
        return (char*) "CKM_DES3_CBC_PAD_IPSEC [safenet]";
    case SAFENET_CKM_ARIA_CMAC:
        return (char*) "CKM_ARIA_CMAC [safenet]";
    case SAFENET_CKM_ARIA_CMAC_GENERAL:
        return (char*) "CKM_ARIA_CMAC_GENERAL [safenet]";
    case SAFENET_CKM_ARIA_CFB8:
        return (char*) "CKM_ARIA_CFB8 [safenet]";
    case SAFENET_CKM_ARIA_CFB128:
        return (char*) "CKM_ARIA_CFB128 [safenet]";
    case SAFENET_CKM_ARIA_L_ECB:
        return (char*) "CKM_ARIA_L_ECB [safenet]";
    case SAFENET_CKM_ARIA_L_CBC:
        return (char*) "CKM_ARIA_L_CBC [safenet]";
    case SAFENET_CKM_ARIA_L_CBC_PAD:
        return (char*) "CKM_ARIA_L_CBC_PAD [safenet]";
    case SAFENET_CKM_ARIA_L_MAC:
        return (char*) "CKM_ARIA_L_MAC [safenet]";
    case SAFENET_CKM_ARIA_L_MAC_GENERAL:
        return (char*) "CKM_ARIA_L_MAC_GENERAL [safenet]";
    case SAFENET_CKM_XOR_BASE_AND_DATA_W_KDF:
        return (char*) "CKM_XOR_BASE_AND_DATA_W_KDF [safenet]";
    case SAFENET_CKM_DSA_SHA224:
        return (char*) "CKM_DSA_SHA224 [safenet]";
    case SAFENET_CKM_DSA_SHA256:
        return (char*) "CKM_DSA_SHA256 [safenet]";
    case SAFENET_CKM_NIST_PRF_KDF:
        return (char*) "CKM_NIST_PRF_KDF [safenet]";
    case SAFENET_CKM_PRF_KDF:
        return (char*) "CKM_PRF_KDF [safenet]";
    case SAFENET_CKM_XOR_BASE_AND_KEY:
        return (char*) "CKM_XOR_BASE_AND_KEY [safenet]";
    case SAFENET_CKM_PBE_SHA1_DES2_EDE_CBC_OLD:
        return (char*) "CKM_PBE_SHA1_DES2_EDE_CBC_OLD [safenet]";
    case SAFENET_CKM_PBE_SHA1_DES3_EDE_CBC_OLD:
        return (char*) "CKM_PBE_SHA1_DES3_EDE_CBC_OLD [safenet]";
    case SAFENET_CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX:
        return (char*) "CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX [safenet]";
    case THALES_CKM_WRAP_RSA_CRT_COMPONENTS:
        return (char*) "CKM_WRAP_RSA_CRT_COMPONENTS [thales]";
    case THALES_CKM_CAC_TK_DERIVATION:
        return (char*) "CKM_CAC_TK_DERIVATION [thales]";
    case THALES_CKM_SHA_1_HMAC_KEY_GEN:
        return (char*) "CKM_SHA_1_HMAC_KEY_GEN [thales]";
    case THALES_CKM_MD5_HMAC_KEY_GEN:
        return (char*) "CKM_MD5_HMAC_KEY_GEN [thales]";
    case THALES_CKM_KCDSA:
        return (char*) "CKM_KCDSA [thales]";
    case THALES_CKM_NC_SHA224_HMAC_KEY_GEN:
        return (char*) "CKM_NC_SHA224_HMAC_KEY_GEN [thales]";
    case THALES_CKM_NC_SHA256_HMAC_KEY_GEN:
        return (char*) "CKM_NC_SHA256_HMAC_KEY_GEN [thales]";
    case THALES_CKM_NC_SHA384_HMAC_KEY_GEN:
        return (char*) "CKM_NC_SHA384_HMAC_KEY_GEN [thales]";
    case THALES_CKM_NC_SHA512_HMAC_KEY_GEN:
        return (char*) "CKM_NC_SHA512_HMAC_KEY_GEN [thales]";
    case THALES_CKM_NC_AES_CMAC_KEY_DERIVATION:
        return (char*) "CKM_NC_AES_CMAC_KEY_DERIVATION [thales]";
    case THALES_CKM_NC_AES_CMAC_KEY_DERIVATION_SCP03:
        return (char*) "CKM_NC_AES_CMAC_KEY_DERIVATION_SCP03 [thales]";
    case THALES_CKM_NC_ECKDF_HYPERLEDGER:
        return (char*) "CKM_NC_ECKDF_HYPERLEDGER [thales]";
    case THALES_CKM_NC_AES_CMAC:
        return (char*) "CKM_NC_AES_CMAC [thales]";
    case THALES_CKM_PUBLIC_FROM_PRIVATE:
        return (char*) "CKM_PUBLIC_FROM_PRIVATE [thales]";
    case UTIMACO_CKM_RSA_PKCS_MULTI:
        return (char*) "CKM_RSA_PKCS_MULTI [utimaco]";
    case UTIMACO_CKM_RSA_X_509_MULTI:
        return (char*) "CKM_RSA_X_509_MULTI [utimaco]";
    case UTIMACO_CKM_DES3_RETAIL_MAC:
        return (char*) "CKM_DES3_RETAIL_MAC [utimaco]";
    case UTIMACO_CKM_ECDSA_ECIES:
        return (char*) "CKM_ECDSA_ECIES [utimaco]";
    case UTIMACO_CKM_ECDSA_MULTI:
        return (char*) "CKM_ECDSA_MULTI [utimaco]";
    case UTIMACO_CKM_DES_CBC_WRAP:
        return (char*) "CKM_DES_CBC_WRAP [utimaco]";
    case UTIMACO_CKM_AES_CBC_WRAP:
        return (char*) "CKM_AES_CBC_WRAP [utimaco]";
    case UTIMACO_CKM_UTI_AES_CMAC:
        return (char*) "CKM_UTI_AES_CMAC [utimaco]";
    case UTIMACO_CKM_UTI_ECDSA_SHA228:
        return (char*) "CKM_UTI_ECDSA_SHA228 [utimaco]";
    case UTIMACO_CKM_UTI_ECDSA_SHA256:
        return (char*) "CKM_UTI_ECDSA_SHA256 [utimaco]";
    case UTIMACO_CKM_UTI_ECDSA_SHA384:
        return (char*) "CKM_UTI_ECDSA_SHA384 [utimaco]";
    case UTIMACO_CKM_UTI_ECDSA_SHA512:
        return (char*) "CKM_UTI_ECDSA_SHA512 [utimaco]";
    case UTIMACO_CKM_ECDSA_RIPMD160:
        return (char*) "CKM_ECDSA_RIPMD160 [utimaco]";
    case UTIMACO_CKM_ECDSA_SHA3_228:
        return (char*) "CKM_ECDSA_SHA3_228 [utimaco]";
    case UTIMACO_CKM_ECDSA_SHA3_256:
        return (char*) "CKM_ECDSA_SHA3_256 [utimaco]";
    case UTIMACO_CKM_ECDSA_SHA3_384:
        return (char*) "CKM_ECDSA_SHA3_384 [utimaco]";
    case UTIMACO_CKM_ECDSA_SHA3_512:
        return (char*) "CKM_ECDSA_SHA3_512 [utimaco]";
    case UTIMACO_CKM_ECKA:
        return (char*) "CKM_ECKA [utimaco]";
    case UTIMACO_CKM_UTI_DSA_SHA228:
        return (char*) "CKM_UTI_DSA_SHA228 [utimaco]";
    case UTIMACO_CKM_UTI_DSA_SHA256:
        return (char*) "CKM_UTI_DSA_SHA256 [utimaco]";
    case UTIMACO_CKM_UTI_DSA_SHA384:
        return (char*) "CKM_UTI_DSA_SHA384 [utimaco]";
    case UTIMACO_CKM_UTI_DSA_SHA512:
        return (char*) "CKM_UTI_DSA_SHA512 [utimaco]";
    case UTIMACO_CKM_DSA_RIPMD160:
        return (char*) "CKM_DSA_RIPMD160 [utimaco]";

    default:
        return (char*) "UNKNOWN";
    }


}




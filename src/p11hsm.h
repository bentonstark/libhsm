
//----------------------------------------------------------------------------------------
// p11hsm.h
//
// Header file for the libhsm.so / libhsm.dll shared library.  The library provides
// simplified C-style access to PKCS#11 v2.20 OASIS standard compliant libraries.
//
// This library can be consumed by any programming languages that can invoke C-style
// function calls to bring HSM functionality to those platforms and languages that
// lack any PKCS#11 support.
//
// PKCS#11 v2.20 mechanisms and other definitions can be found in /oasis/pkcs11t.h
//
//
// This source code is licensed under the GPL v2 license found in the
// LICENSE.txt file in the root directory of this source tree.
//
// Written by Benton Stark (benton.stark@gmail.com)
// Sept. 7, 2016
//----------------------------------------------------------------------------------------

#ifndef _p11HSM_H
#define _p11HSM_H


#ifdef OS_WIN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// OS specific macro for extern function decoration and snprintf
#if defined(OS_WIN)
    #define EXTERN_C extern "C" __declspec(dllexport)
    #define snprintf _snprintf
#else
    #define EXTERN_C extern "C"
#endif



//----------------------------------------------------------------------------------------
// get_lib_version()
//  Retrieves string containing the version information for the library.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf             -- contains any error messages
//        version_info        -- contains library version information
//
//    Inputs:
//        msg_buf_len         -- byte length of provided error message buffer
//        version_info_len    -- byte length of versionInfo buffer (minimum 15 bytes)
//----------------------------------------------------------------------------------------
EXTERN_C int get_lib_version(char* msg_buf, unsigned long msg_buf_len, char *version_info, unsigned long version_info_len);

//----------------------------------------------------------------------------------------
// connect()
//    Connect to the PKCS-11 client shared library.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf         -- contains any error messages
//
//    Inputs:
//        msg_buf_len     -- byte length of provided error message buffer
//        lib_path        -- file path char array to shared HSM vendor
//                           PKCS#11 shared dynamic library
//        lib_path_len    -- length of library path
//
//----------------------------------------------------------------------------------------
EXTERN_C int connect(char* msg_buf, unsigned long msg_buf_len, char* lib_path, unsigned long lib_path_len);

//----------------------------------------------------------------------------------------
// disconnect()
//  Disconnect from PKCS-11 client shared library.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf        -- contains any error messages
//
//    Inputs:
//        msg_buf_len    -- byte length of provided error message buffer
//----------------------------------------------------------------------------------------
EXTERN_C int disconnect(char* msg_buf, unsigned long msg_buf_len);

//----------------------------------------------------------------------------------------
// initialize()
//    Calls PKCS#11 C_Initialize().
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf        -- contains any error messages
//
//    Inputs:
//        msg_buf_len    -- byte length of provided error message buffer
//----------------------------------------------------------------------------------------
EXTERN_C int initialize(char* msg_buf, unsigned long msg_buf_len);

//----------------------------------------------------------------------------------------
// finalize()
//  Calls PKCS#11 C_Finalize.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf        -- contains any error messages
//
//    Inputs:
//        msg_buf_len    -- byte length of provided error message buffer
//----------------------------------------------------------------------------------------
EXTERN_C int finalize(char* msg_buf, unsigned long msg_buf_len);

//----------------------------------------------------------------------------------------
// open_session()
//    Scans all the available slots looking for matching serial number.
//    If a slot is found then open a session on the token and returns the session handle
//    and the slot number.  Note: the CKF_SERIAL_SESSION flag is always set.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf          -- contains any error messages
//        h_session        -- session handle of HSM device after a session is successfully opened
//
//    Inputs:
//        slot             -- token slot number
//        msg_buf_len      -- byte length of provided error message buffer
//        flags            -- various login flags (typically use is CKF_RW_SESSION | CKF_SERIAL_SESSION)
//                            CKF_EXCLUSIVE_SESSION       0x0001    - session is exclusive and no other sessions can be opened
//                                                                  (appears to be a SafeNet specific flag option)
//                            CKF_RW_SESSION              0x0002  - session is a read/write session rather than read-only
//                            CKF_SERIAL_SESSION          0x0004    - For legacy reasons, the CKF_SERIAL_SESSION bit must always be set;
//                                                                    if a call to C_OpenSession does not have this bit set, the P11 call should
//                                                                  return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED
//                            CKF_SO_SESSION              0x8000  - security officer session
//                                                                  (appears to be a SafeNet specific flag option)
//                                                                  this flag must be set if the Login CK_USER_TYPE is a CKU_SO
//
//----------------------------------------------------------------------------------------
EXTERN_C int open_session(char* msg_buf, unsigned long msg_buf_len, unsigned long slot, unsigned long flags, unsigned long* h_session);

//----------------------------------------------------------------------------------------
// close_session()
//  Closes specified session on the HSM.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf            -- contains any error messages
//
//    Inputs:
//        msg_buf_len        -- byte length of provided error message buffer
//        h_session          -- session handle to close
//----------------------------------------------------------------------------------------
EXTERN_C int close_session(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session);

//----------------------------------------------------------------------------------------
// close_all_sessions()
//  Closes all open sessions on a given HSM slot.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf            -- contains any error messages
//
//    Inputs:
//        msg_buf_len        -- byte length of provided error message buffer
//        slotId             -- ID of the slot to close all sessions on
//----------------------------------------------------------------------------------------
EXTERN_C int close_all_sessions(char* msg_buf, unsigned long msg_buf_len, unsigned long slot_id);

//----------------------------------------------------------------------------------------
// login()
//    Calls PKCS#11 C_Login().
//  Must have an open session to use.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf          -- contains error messages
//
//    Inputs:
//        msg_buf_len      -- byte length of provided error message buffer.
//        h_session        -- handle number of the session to execute a login operation on
//        user_type        -- type of user to login as (Security Officer = 0, User = 1, Crypto Officer = 2)
//        user_pin         -- user PIN number
//        user_pin_len     -- length of user PIN
//----------------------------------------------------------------------------------------
EXTERN_C int login(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long user_type, unsigned char* user_pin, unsigned long user_pin_len);

//----------------------------------------------------------------------------------------
// logout()
//    Calls PKCS#11 C_Logout().
//  Logs out of the HSM.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf            -- contains any error messages
//
//    Inputs:
//        msg_buf_len        -- byte length of provided error message buffer.
//        h_session          -- active session handle
//----------------------------------------------------------------------------------------
EXTERN_C int logout(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session);

//----------------------------------------------------------------------------------------
// set_pin()
//  Sets the PIN for the authenticated session user.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf            -- contains any error messages
//
//    Inputs:
//        msg_buf_len        -- byte length of provided error message buffer.
//        h_session          -- handle number of the session to execute a login operation on
//        old_pin            -- old user PIN
//        old_pin_len        -- old user PIN length
//        new_pin            -- new user PIN
//        new_pin_len        -- new user PIN length
//----------------------------------------------------------------------------------------
EXTERN_C int set_pin(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* old_pin, unsigned long old_pin_len, unsigned char* new_pin, unsigned long new_pin_len);

//----------------------------------------------------------------------------------------
// find_objects()
//    Queries the HSM for all objects viewable by the currently logged in session user and
//  returns objects handles as an array of integers.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                   -- contains error messages
//        h_object_array            -- modified to contain object handles
//        h_object_array_len        -- length of the object array buffer on input
//
//    Inputs:
//        msg_buf_len               -- length of the error message buffer
//        h_session                 -- handle of an open session with the HSM.
//
//----------------------------------------------------------------------------------------
EXTERN_C int find_objects(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long* h_object_array, unsigned long* h_object_array_len);

//----------------------------------------------------------------------------------------
// get_object_handle()
//    Get the handle of an object on the HSM by label name.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf             -- contains error messages
//        h_object            -- to contain handle of first key that matches supplied label,
//                               or zero if key not found
//    Inputs:
//        msg_buf_len         -- length of the error message buffer
//        object_label        -- object label
//        object_label_len    -- length of object label
//        h_session           -- handle of an open session with the HSM
//----------------------------------------------------------------------------------------
EXTERN_C int get_object_handle(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* object_label, unsigned long object_label_len, unsigned long* h_object);

//----------------------------------------------------------------------------------------
// sign()
//    Signs data buffer using specified signing key and signing key mechanism (algorithm).
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                  -- contains error messages
//        signatureBuf             -- buffer to contain signature
//        signatureBufLen          -- length of signature buffer
//
//    Inputs:
//        msg_buf_len              -- length of the error message buffer
//        data_buf                 -- buffer containing data to be signed
//        data_buf_len             -- byte length of data to be signed
//        h_key                    -- handle of key to be used for signing
//        mech_type                -- mechanism type of the signing algorithm
//        salt_len                 -- optional salt length value (required for PSS signatures)
//        h_session                -- handle of an open session with the HSM
//----------------------------------------------------------------------------------------
EXTERN_C int sign(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len,
         unsigned long h_key, unsigned long mech_type, unsigned long salt_len, unsigned char* sig_buf, unsigned long* sig_buf_len);

//----------------------------------------------------------------------------------------
// verify()
//    Verifies signed data using specified verification key and key mechanism (algorithm)
//  and supplied signature.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                 -- contains error messages
//
//    Inputs:
//        msg_buf_len             -- length of the error message buffer
//        h_session               -- handle of an open session with the HSM
//        data_buf                -- buffer containing data to verify
//        data_buf_len            -- byte length of data buffer
//        h_key                   -- handle of key to be used for verifying
//        mech_type               -- mechanism type of the verification algorithm
//        salt_len                -- optional salt length value (required for PSS signatures)
//        sig_buf                 -- buffer to contain signature
//        sig_buf_Len             -- byte length of signature buffer
//
//----------------------------------------------------------------------------------------
EXTERN_C int verify(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len, unsigned long h_key,
           unsigned long mech_type, unsigned long salt_len, unsigned char* sig_buf, unsigned long sig_buf_len);

//----------------------------------------------------------------------------------------
// encrypt()
//    Encrypts supplied clear-text using designated HSM encryption key and mechanism and returns
//  cipher-text.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                   -- contains error messages
//        encrypted_data_buf        -- buffer to contain encrypted data
//        encrypted_data_buf        -- byte length of supplied buffer; on output, byte
//                                     length of result in enc_data_buf
//    Inputs:
//        msg_buf_len               -- length of the error message buffer
//        h_session                 -- handle of an open session with the HSM
//        data_buf                  -- buffer containing data to be encrypted
//        data_buf_len              -- byte length of data to be encrypted
//        h_key                     -- handle of encryption key to be used to do encryption operation
//        mech_type                 -- algorithm to be used to encrypt the data (e.g. CKM_DES_CBC_PAD, CKM_AES_CBC, etc)
//        iv                        -- encryption initialization vector
//        iv_len                    -- encryption initialization vector length
//----------------------------------------------------------------------------------------
//
EXTERN_C int encrypt(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len,
        unsigned long h_key, unsigned long mech_type, unsigned char* iv, unsigned long iv_len,
        unsigned char* encrypted_data_buf, unsigned long* encrypted_data_buf_len);

//----------------------------------------------------------------------------------------
// decrypt()
//    Decrypts supplied cipher-text using designated HSM encryption key and mechanism and returns
//  clear-text.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                   -- contains error messages
//        decrypted_data_buf        -- buffer to contain decrypted data
//        decrypted_data_buf_len    -- byte length of supplied buffer; on output, byte
//                                     length of result in decryptedData
//    Inputs:
//        msg_buf_len               -- length of the error message buffer
//        h_session                 -- handle of an open session with the HSM.
//        data_buf                  -- buffer containing data to be decrypted.
//        data_buf_len              -- byte length of data to be decrypted.
//        h_decrypt_key             -- handle of key to be used to do decrypt operation
//        mech_type                 -- algorithm to be used to decrypt the data (e.g. CKM_DES_CBC_PAD, CKM_AES_CBC, etc)
//        iv                        -- initialization vector
//        iv_len                    -- initialization vector length
//----------------------------------------------------------------------------------------
//
EXTERN_C int decrypt(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* data_buf, unsigned long data_buf_len, unsigned long h_key,
        unsigned long mech_type, unsigned char* iv, unsigned long iv_len,
        unsigned char* decrypted_data_buf, unsigned long* decrypted_data_buf_len);

//----------------------------------------------------------------------------------------
// digest()
//    Creates a Digest (Hash) of supplied data using the specific mechanism (hashing algorithm)
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                  -- contains error messages
//        data_buf                 -- buffer to contain digest (hashed) data
//        data_buf_len             -- byte length of supplied buffer; on output, byte
//                                    length of result in digestDataBuf
//    Inputs:
//        msg_buf_len              -- length of the error message buffer
//        h_session                -- handle of an open session with the HSM.
//        digest_data_buf          -- buffer containing data to be hashed.
//        digest_data_buf_len      -- byte length of data to be hashed.
//        mech_type                -- algorithm to be used to digest the data (e.g. CKM_SHA256, CKM_SHA512, etc)
//----------------------------------------------------------------------------------------
//
EXTERN_C int digest(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len,
        unsigned long mech_type, unsigned char* digest_data_buf, unsigned long* digest_data_buf_len);


//----------------------------------------------------------------------------------------
// create_rsa_key_pair()
//    Generates RSA public and private keys on the HSM.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                      -- contains error messages
//        h_pub_key                    -- new public key handle
//        h_pvt_key                    -- new private key handle
//
//    Inputs:
//        msg_buf_len                  -- length of the error message buffer
//        h_session                    -- handle of an open session with the HSM.
//        key_size                     -- bit length of requested public modulus (2048, 4096, 8192).
//        pub_key_label                -- label for the public key
//        pub_key_label_len            -- length of public key label
//        pvt_key_label                -- label for the private key
//        pvt_key_label_len            -- length of private key label
//        pub_key_id                   -- id for the public key
//        pub_key_id_len               -- length of public key id
//        pvt_key_id                   -- id for the private key
//        pvt_key_id_len               -- length of private key id
//        mech_type                    -- mechanism type (usually CKM_RSA_X9_31_KEY_PAIR_GEN or CKM_RSA_PKCS_KEY_PAIR_GEN)
//                                        Note: CKM_RSA_X9_31_KEY_PAIR_GEN is functionally identical to CKM_RSA_PKCS_KEY_PAIR_GEN
//                                        but provides stronger guarantee of p and q values as defined in X9.31
//                                        Cavium HSMs only support the CKM_RSA_X9_31_KEY_PAIR_GEN mechanism
//        pub_exp                      -- byte array containing public exponent value
//      pub_exp_len                    -- length of the publicExp byte array
//        token                        -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        pub_private                  -- 1 to indicate the public key is marked private and can only be accessed after authentication; otherwise 0
//        pvt_private                  -- 1 to indicate the private key is marked private and can only be accessed after authentication; otherwise 0
//        sensitive                    -- 1 to indicate the private key is sensitive; otherwise 0
//        modifiable                   -- 1 to indicate the keys can be modified; otherwise 0
//        extractable                  -- 1 to indicate the private key can be extracted; otherwise 0
//        sign                         -- 1 to indicate the private key can sign; otherwise 0
//        verify                       -- 1 to indicate the public key can verify; otherwise 0
//        encrypt                      -- 1 to indicate the public key can encrypt; otherwise 0
//        decrypt                      -- 1 to indicate the private key can decrypt; otherwise 0
//        wrap                         -- 1 to indicate the public key can wrap; otherwise 0
//        unwrap                       -- 1 to indicate the private key can unwrap; otherwise 0
//        derive                       -- 1 to indicate the private key can be used to drive other keys; otherwise 0
//        overwrite                    -- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//
//----------------------------------------------------------------------------------------
EXTERN_C int create_rsa_key_pair(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long key_size,
        unsigned char* pub_key_label, unsigned long pub_key_label_len, unsigned char* pvt_key_label, unsigned long pvt_key_label_len,
        unsigned char* pub_key_id, unsigned long pub_key_id_len, unsigned char* pvt_key_id, unsigned long pvt_key_id_len,
        unsigned long mech_type, unsigned char* pub_exp, unsigned long pub_exp_len, unsigned long token, unsigned long pub_private, unsigned long pvt_private, unsigned long sensitive,
        unsigned long modifiable, unsigned long extractable, unsigned long sign, unsigned long verify, unsigned long encrypt, unsigned long decrypt,
        unsigned long wrap, unsigned long unwrap, unsigned long derive, unsigned long overwrite, unsigned long* h_pub_key, unsigned long* h_pvt_key);

//----------------------------------------------------------------------------------------
// create_ec_key_pair()
//    Generates EC public and private keys on the HSM.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                      -- contains error messages
//        h_pub_key                    -- new public key handle
//        h_pvt_key                    -- new private key handle
//
//    Inputs:
//        msg_buf_len                  -- length of the error message buffer
//        h_session                    -- handle of an open session with the HSM.
//        ec_params                    -- byte string containing the ASN.1 DER encoded curve parameter or OID data
//        ec_params_len                -- length of derParams
//        pub_key_label                -- label for the public key
//        pub_key_label_len            -- length of public key label
//        pvt_key_label                -- label for the private key
//        pvt_key_label_len            -- length of private key label
//        pub_key_id                   -- id for the public key
//        pub_key_id_len               -- length of public key id
//        pvt_key_id                   -- id for the private key
//        pvt_key_id_len               -- length of private key id
//        token                        -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        pub_private                  -- 1 to indicate the public key is marked private and can only be accessed after authentication; otherwise 0
//        pvt_private                  -- 1 to indicate the private key is marked private and can only be accessed after authentication; otherwise 0
//        sensitive                    -- 1 to indicate the private key is sensitive; otherwise 0
//        modifiable                   -- 1 to indicate the keys can be modified; otherwise 0
//        extractable                  -- 1 to indicate the private key can be extracted; otherwise 0
//        sign                         -- 1 to indicate the private key can sign; otherwise 0
//        verify                       -- 1 to indicate the public key can verify; otherwise 0
//        encrypt                      -- 1 to indicate the public key can encrypt; otherwise 0
//        decrypt                      -- 1 to indicate the private key can decrypt; otherwise 0
//        wrap                         -- 1 to indicate the public key can wrap; otherwise 0
//        unwrap                       -- 1 to indicate the private key can unwrap; otherwise 0
//        derive                       -- 1 to indicate the private key can be used to drive other keys; otherwise 0
//        overwrite                    -- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//
//----------------------------------------------------------------------------------------
EXTERN_C int create_ec_key_pair(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* ec_params, unsigned long ec_params_len,
        unsigned char* pub_key_label, unsigned long pub_key_label_len, unsigned char* pvt_key_label, unsigned long pvt_key_label_len,
        unsigned char* pub_key_id, unsigned long pub_key_id_len, unsigned char* pvt_key_id, unsigned long pvt_key_id_len,
        unsigned long token, unsigned long pub_private, unsigned long pvt_private, unsigned long sensitive,
        unsigned long modifiable, unsigned long extractable, unsigned long sign, unsigned long verify,
        unsigned long encrypt, unsigned long decrypt, unsigned long wrap, unsigned long unwrap, unsigned long derive,
        unsigned long overwrite, unsigned long* h_pub_key, unsigned long* h_pvt_key);

//----------------------------------------------------------------------------------------
// create_secret_key()
//    Generates a new secret symmetric key directly on the HSM.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                     -- contains error messages
//        h_secret_key                -- newly created secret key handle
//
//    Inputs:
//        msg_buf_len                 -- length of the error message buffer
//        h_session                   -- handle of an open session with the HSM.
//        key_label                   -- label for the key
//        key_label_len               -- length of key label
//        key_id                      -- id for the key
//        key_id_len                  -- length of key id
//        key_size                    -- size of the key in bits
//        mech_type                   -- type of key mechanism to create
//        token                       -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        private_                    -- 1 to indicate the keys are private to the HSM and require an auth session; otherwise 0
//        sensitive                   -- 1 to indicate the private key is sensitive; otherwise 0
//        modifiable                  -- 1 to indicate the keys can be modified; otherwise 0
//        extractable                 -- 1 to indicate the private key can be extracted; otherwise 0
//        sign                        -- 1 to indicate the private key can sign; otherwise 0
//        verify                      -- 1 to indicate the public key can verify; otherwise 0
//        encrypt                     -- 1 to indicate the public key can encrypt; otherwise 0
//        decrypt                     -- 1 to indicate the private key can decrypt; otherwise 0
//        wrap                        -- 1 to indicate the public key can wrap; otherwise 0
//        unwrap                      -- 1 to indicate the private key can unwrap; otherwise 0
//        derive                      -- 1 to indicate the private key can be used to drive other keys; otherwise 0
//        overwrite                   -- 1 to indicate the an existing key pair with the same label name can be overwriten; otherwise 0
//
//----------------------------------------------------------------------------------------
EXTERN_C int create_secret_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
        unsigned long mech_type, unsigned long key_size,
        unsigned long token, unsigned long private_, unsigned long sensitive, unsigned long modifiable,
        unsigned long extractable, unsigned long sign, unsigned long verify, unsigned long encrypt, unsigned long decrypt,
        unsigned long wrap, unsigned long unwrap, unsigned long derive, unsigned long overwrite,
        unsigned long* h_secret_key);

//----------------------------------------------------------------------------------------
// get_slot_count()
//    Uses C_GetSlotList() to count slots.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf        -- contains any error messages
//        slot_count     -- number of slots on the machine
//
//    Inputs:
//        msg_buf_len    -- byte length of provided buffer
//
//----------------------------------------------------------------------------------------
EXTERN_C int get_slot_count(char* msg_buf, unsigned long msg_buf_len, unsigned long* slot_count);

//----------------------------------------------------------------------------------------
// get_token_count()
//    Returns the number of tokens on the machine.
//
//    Operation:
//        Uses C_GetSlotList() to count slots that have tokens present.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf        -- contains error messages
//        token_count    -- number of tokens on the machine
//
//    Inputs:
//        msg_buf_len    -- byte length of provided buffer
//
//----------------------------------------------------------------------------------------
EXTERN_C int get_token_count(char* msg_buf, unsigned long msg_buf_len, unsigned long* token_count);


//----------------------------------------------------------------------------------------
// get_slot_info()
//    Compiles and returns information about all the slots on the machine that have a
//  token present.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf         -- contains error messages
//        data_buf        -- to contain info with newline separating records and commas
//                           separating fields.
//                           Each record has:
//                                slot ID,
//                                token label,
//                                manufacturer ID,
//                                model,
//                                serial number,
//                                count of open sessions.
//         data_buf_len    -- modifies to the size allocated
//        slot_count       -- number of slots on the machine
//
//    Inputs:
//        msg_buf_len      -- byte length of provided buffer
//        data_buf_len     -- byte length of provided buffer
//
//----------------------------------------------------------------------------------------
EXTERN_C int get_slot_info(char* msg_buf, unsigned long msg_buf_len, char* data_buf, unsigned long* data_buf_len, unsigned long* token_count);

//----------------------------------------------------------------------------------------
// get_attribute_value()
//    Gets the attribute value of an object on the HSM.
//
//    Operation:
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                -- contains any error messages
//        attribute_value        -- contains array of bytes containing attribute value
//        attribute_value_len    -- attribute value length
//
//    Inputs:
//        msg_buf_len            -- byte length of provided error message buffer
//        h_session              -- session handle
//        h_object               -- handle to the object that is to be queried for attribute value
//        attribute_type         -- valid attribute type such as CKA_PRIME_1, CKA_PRIME_2, etc
//----------------------------------------------------------------------------------------
EXTERN_C int get_attribute_value(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_object,
        unsigned long attribute_type, unsigned char *attribute_value, unsigned long* attribute_value_len);

//----------------------------------------------------------------------------------------
// set_attribute_value()
//    Sets an attribute value for an object on the HSM (if allowable).
//
//    Operation:
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                    -- contains any error messages
//        attribute_value            -- contains array of bytes containing attribute value
//        attribute_value_length     -- attribute value length
//
//    Inputs:
//        msg_buf_len                -- byte length of provided error message buffer
//        h_session                  -- session handle
//        h_object                   -- handle to the object to update the attribute
//        attribute_type             -- valid attribute type such as CKA_PRIME_1, CKA_PRIME_2, etc
//----------------------------------------------------------------------------------------
EXTERN_C int set_attribute_value(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_object,
        unsigned long attribute_type, unsigned char *attribute_value, unsigned long attribute_value_len);

//----------------------------------------------------------------------------------------
// generate_random()
//    Generate and return random byte string.  Random data is generated using the HSM
//    PRNG.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                    -- contains any error messages
//        random_data                -- contains array of bytes to stuff random numbers into
//        random_data_len            -- length of random data array
//
//    Inputs:
//        msg_buf_len                -- byte length of provided error message buffer
//        h_session                  -- session handle
//----------------------------------------------------------------------------------------
EXTERN_C int generate_random(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* random_data, unsigned long random_data_len);

//----------------------------------------------------------------------------------------
// seed_random()
//    See the HSM PRNG with a user supplied value.
//
//    Operation:
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf                  -- contains any error messages
//        seed_data                -- contains array of bytes to stuff random numbers into
//        seed_data_len            -- length of random data array
//
//    Inputs:
//        msg_buf_len              -- byte length of provided error message buffer
//        h_session                -- session handle
//----------------------------------------------------------------------------------------
EXTERN_C int seed_random(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* seed_data, unsigned long seed_data_len);

//----------------------------------------------------------------------------------------
// destroy_object()
//    Destroys an object on the HSM.  The operation is not reversible and is destructive.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf            -- contains any error messages
//
//    Inputs:
//        msg_buf_len        -- byte length of provided error message buffer
//        h_session          -- session handle
//        h_object           -- handle of object to destroy
//
//----------------------------------------------------------------------------------------
EXTERN_C int destroy_object(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_object);

//----------------------------------------------------------------------------------------
// import_data_object()
//    Imports a binary data object on the HSM.  Data value is supplied as a parameter.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf            -- contains any error messages
//
//    Inputs:
//        msg_buf_len        -- byte length of provided error message buffer
//        h_session          -- session handle
//        data_label         -- label of the data object on the HSM
//        data_label_len     -- length of data object label
//        data_id            -- id of the data object on the HSM
//        data_id_len        -- length of data object id
//        value              -- binary array containing the data in clear
//        value_len          -- length of the data value array
//        token              -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        overwrite          -- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//
//    Outputs:
//        h_object           -- object handle
//
//----------------------------------------------------------------------------------------
EXTERN_C int import_data_object(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* data_label, unsigned long data_label_len, unsigned char* data_id, unsigned long data_id_len,
        unsigned char* value, unsigned long value_len, unsigned long token, unsigned long overwrite, unsigned long* h_object);

//----------------------------------------------------------------------------------------
// import_rsa_public_key()
//    Imports clear-text RSA public key data object on the HSM.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf               -- contains any error messages
//        h_pub_key             -- public key object handle
//
//    Inputs:
//        msg_buf_len           -- byte length of provided error message buffer
//        h_session             -- session handle
//        key_label             -- label of the RSA public key object on the HSM
//        key_label_len         -- public key label length
//        key_id                -- id for the public key
//        key_id_len            -- length of public key id
//        exp                   -- binary array containing the RSA key public exponent
//        exp_len               -- length of the public exponent array
//        mod                   -- binary array containing the RSA key public modulus
//        mod_len               -- length of the public modulus array
//        token                 -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        private_              -- 1 to indicate the keys are private to the HSM and require an authenticated session; otherwise 0
//        modifiable            -- 1 to indicate the keys can be modified; otherwise 0
//        verify                -- 1 to indicate the public key can verify; otherwise 0
//        encrypt               -- 1 to indicate the public key can encrypt; otherwise 0
//        wrap                  -- 1 to indicate the public key can wrap; otherwise 0
//        overwrite              -- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//----------------------------------------------------------------------------------------
EXTERN_C int import_rsa_public_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
        unsigned char* exp, unsigned long exp_len, unsigned char* mod, unsigned long mod_len,
        unsigned long token, unsigned long _private, unsigned long modifiable, unsigned long verify,
        unsigned long encrypt, unsigned long wrap, unsigned long overwrite, unsigned long* h_pub_key);

//----------------------------------------------------------------------------------------
// import_ec_public_key()
//    Imports clear-text EC public key data object on the HSM.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf               -- contains any error messages
//        h_pub_key             -- public key object handle
//
//    Inputs:
//        msg_buf_len           -- byte length of provided error message buffer
//        h_session             -- session handle
//        key_label             -- label of the EC public key object on the HSM
//        key_label_len         -- public key label length
//        key_id                -- id for the public key
//        key_id_len            -- length of public key id
//        ec_params             -- binary array containing the EC parameters curve definition or OID
//        ec_params_len         -- length of the EC parameters curve definition or OID
//        ec_point              -- binary array containing the unique EC point
//        ec_point_len          -- length of the EC point definition array
//        token                 -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        private_              -- 1 to indicate the keys are private to the HSM and require an authenticated session; otherwise 0
//        modifiable            -- 1 to indicate the keys can be modified; otherwise 0
//        verify                -- 1 to indicate the public key can verify; otherwise 0
//        encrypt               -- 1 to indicate the public key can encrypt; otherwise 0
//        wrap                  -- 1 to indicate the public key can wrap; otherwise 0
//        overwrite             -- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//----------------------------------------------------------------------------------------
EXTERN_C int import_ec_public_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
        unsigned char* ec_params, unsigned long ec_params_len, unsigned char* ec_point, unsigned long ec_point_len,
        unsigned long token, unsigned long _private, unsigned long modifiable, unsigned long verify, unsigned long encrypt, unsigned long wrap, unsigned long overwrite, unsigned long* h_pub_key);

//----------------------------------------------------------------------------------------
// import_public_cert()
//    Imports a public X.509 certificate on the HSM.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf              -- contains any error messages
//        h_cert               -- public certificate object handle
//
//    Inputs:
//        msg_buf_len          -- byte length of provided error message buffer
//        h_session            -- session handle
//        cert_label           -- label of the public certificate object on the HSM
//        cert_label_len       -- public certificate label length
//        cert_id              -- id for the public certificate object
//        cert_id_len          -- length of public certificate object id
//        cert_serial          -- public certificate X.509 serial number
//        cert_serial_len      -- length of public certificate X.509 serial number
//        cert_subject         -- public certificate subject data
//        cert_subject_len     -- length of the public certificate subject data
//        cert_issuer          -- public certificate issuer data
//        cert_issuer_len      -- length of the public certificate issuer data
//        cert_value           -- DER encoded X.509 certificate data value
//        cert_value_len       -- length of the DER encoded X.509 certificate data value
//        token                -- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//        private_             -- 1 to indicate the keys are private to the HSM and require an authenticated session; otherwise 0
//        modifiable           -- 1 to indicate the keys can be modified; otherwise 0
//        overwrite            -- 1 to indicate existing certificate object with the same label name can be overwritten; otherwise 0
//----------------------------------------------------------------------------------------
EXTERN_C int import_public_cert(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned char* cert_label, unsigned long cert_label_len, unsigned char* cert_id, unsigned long cert_id_len,
        unsigned char* cert_serial, unsigned long cert_serial_len, unsigned char* cert_subject, unsigned long cert_subject_len,
        unsigned char* cert_issuer, unsigned long cert_issuer_len, unsigned char* cert_value, unsigned long cert_value_len,
        unsigned long token, unsigned long _private, unsigned long modifiable,
        unsigned long overwrite, unsigned long* h_cert);

//----------------------------------------------------------------------------------------
// wrap_key()
//    Wraps a key off the HSM using a designated symmetric or asymmetric wrapping key.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf          -- contains any error messages
//        key_buf          -- binary array containing the wrapped (encrypted) key
//        key_buf_len      -- length of the keyBuffer
//
//    Inputs:
//        msg_buf_len      -- byte length of provided error message buffer
//        h_session        -- session handle
//        key_label        -- label of the target key to wrap off the HSM
//        h_wrap_key       -- handle to the wrapping key on the HSM to use
//        iv               -- optional IV value to use with the wrapping key (can be null)
//        iv_len           -- optional IV value length (can be 0)
//        mech_type        -- wrapping key mechanism to use (3DES-CBC, AES-128-CBC, etc)
//
//----------------------------------------------------------------------------------------
EXTERN_C int wrap_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_key,
        unsigned long h_wrap_key, unsigned char* iv, unsigned long iv_len, unsigned long mech_type,
        unsigned char *key_buf, unsigned long* key_buf_len);

//----------------------------------------------------------------------------------------
// unwrap_private_key()
//    Unwraps a private asymmetric key onto the HSM using a designated symmetric or asymmetric wrapping key.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf          -- contains any error messages
//
//    Inputs:
//        msg_buf_len      -- byte length of provided error message buffer
//        h_session        -- session handle
//        h_wrap_key       -- handle to the wrapping key on the HSM to use
//        iv               -- optional IV value to use with the wrapping key (can be null)
//        iv_len           -- optional IV value length (can be 0)
//        mech_type        -- wrapping key mechanism to use (3DES-CBC, AES-128-CBC, etc)
//        key_label        -- key label of new private key
//        key_label_len    -- key label length
//        key_id           -- key id of new private key
//        key_id_len       -- key id length
//        key_buf          -- wrapped private key bytes
//        key_buf_len      -- length of the wrapped private key bytes
//        key_type         -- type of private key (DES, DES2, DES3, AES, etc)
//        token            -- 1 to indicate the private key exists on the token and not the session; otherwise 0
//        private_         -- 1 to indicate the private key is private and can only be accessed after authentication; otherwise 0
//        sensitive        -- 1 to indicate the private key is sensitive; otherwise 0
//        modifiable       -- 1 to indicate the private key can be modified; otherwise 0
//        extractable      -- 1 to indicate the private key can be extracted; otherwise 0
//        sign             -- 1 to indicate the private key can sign; otherwise 0
//        decrypt          -- 1 to indicate the private key can decrypt; otherwise 0
//        unwrap           -- 1 to indicate the private key can unwrap; otherwise 0
//        overwrite        -- 1 to indicate the existing private key pair with the same label name can be overwritten; otherwise 0
//        derive           -- 1 to indicate the private key can be used to derive other keys; otherwise 0
//
//    Outputs:
//        h_pvt_key        -- object handle
//----------------------------------------------------------------------------------------
EXTERN_C int unwrap_private_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned long h_wrap_key, unsigned char* iv, unsigned long iv_len, unsigned long mech_type,
        unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
        unsigned char* key_buf, unsigned long key_buf_len, unsigned long key_type,
        unsigned long token, unsigned long private_, unsigned long sensitive, unsigned long modifiable, unsigned long extractable,
        unsigned long sign, unsigned long decrypt, unsigned long unwrap, unsigned long derive, unsigned long overwrite,
        unsigned long* h_pvt_key);

//----------------------------------------------------------------------------------------
// unwrap_secret_key()
//    Unwraps a secret symmetric key onto the HSM using a designated symmetric or asymmetric wrapping key.
//
//    Returns:
//        FALSE if an error occurs; otherwise TRUE
//
//    Modifies:
//        msg_buf         -- contains any error messages
//        h_secret_key    -- newly created secret key handle
//
//    Inputs:
//        msg_buf_len     -- byte length of provided error message buffer
//        h_session       -- session handle
//        h_wrap_key      -- handle to the wrapping key on the HSM to use
//        iv              -- optional IV value to use with the wrapping key (can be null)
//        iv_len          -- optional IV value length (can be 0)
//        mech_type       -- wrapping key mechanism to use (3DES-CBC, AES-128-CBC, etc)
//        key_label       -- key label for new secret key
//        key_label_len   -- length of key label
//        key_id          -- key id for new secret key
//        key_id_len      -- length of key id
//        key_buf         -- wrapped secret key bytes
//        key_buf_len     -- length of the wrapped secret key bytes
//        key_type        -- type of secret key (DES, DES2, DES3, AES, etc)
//        key_size        -- size of the key in bits (112, 128, 192, 256, etc)
//        token           -- 1 to indicate the secret key exists on the token and not the session; otherwise 0
//        private_        -- 1 to indicate the secret key is private and can only be accessed after authentication; otherwise 0
//        sensitive       -- 1 to indicate the private key is sensitive; otherwise 0
//        modifiable      -- 1 to indicate the secret key can be modified; otherwise 0
//        extractable     -- 1 to indicate the secret key can be extracted; otherwise 0
//        sign            -- 1 to indicate the secret key can sign; otherwise 0
//        verify          -- 1 to indicate the secret key can verify; otherwise 0
//        encrypt         -- 1 to indicate the secret key can encrypt; otherwise 0
//        decrypt         -- 1 to indicate the secret key can decrypt; otherwise 0
//        wrap            -- 1 to indicate the secret key can wrap; otherwise 0
//        unwrap          -- 1 to indicate the secret key can unwrap; otherwise 0
//        overwrite       -- 1 to indicate the existing secret key with the same label name can be overwritten; otherwise 0
//        derive          -- 1 to indicate the secret key can be used to derive other keys; otherwise 0
//
//----------------------------------------------------------------------------------------
EXTERN_C int unwrap_secret_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
        unsigned long h_wrap_key, unsigned char* iv, unsigned long iv_len, unsigned long mech_type,
        unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
        unsigned char* key_buf, unsigned long key_buf_len,
        unsigned long key_type, unsigned long key_size,    unsigned long token, unsigned long private_,
        unsigned long sensitive, unsigned long modifiable, unsigned long extractable, unsigned long sign,
        unsigned long verify, unsigned long encrypt, unsigned long decrypt, unsigned long wrap, unsigned long unwrap,
        unsigned long derive, unsigned long overwrite, unsigned long* h_secret_key);


//----------------------------------------------------------------------------------------
// get_mechanism_info()
//    Queries the slot and returns information supported PKCS#11 support mechanism info.
//
//    Returns:
//        FALSE if an error occurs otherwise TRUE
//
//    Modifies:
//        msg_buf         -- contains error messages
//        data_buf        -- to contain info with newline separating records and commas
//                           separating fields.
//                           Each record has:
//                                * mechanism name
//                                * mechanism value in base16 (hex)
//                                * min key size
//                                * max key size
//                                * flags
//         data_buf_len   -- modifies to the size allocated
//        mech_count      -- modified to the number of mechanisms reported
//
//    Inputs:
//        msg_buf_len     -- byte length of provided buffer
//        slot            -- slot number
//        data_buf_len    -- byte length of provided buffer
//
//----------------------------------------------------------------------------------------
EXTERN_C int get_mechanism_info(char* msg_buf, unsigned long msg_buf_len, unsigned long slot, char* data_buf, unsigned long* data_buf_len, unsigned long* mech_count);



#endif // #ifndef _p11HSM_H

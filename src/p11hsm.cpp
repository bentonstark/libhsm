//----------------------------------------------------------------------------------------
// p11hsm.cpp
//
// Implementation file for the libhsm.so / libhsm.dll shared library.  The library provides
// simplified C-style access to PKCS#11 v2.20 OASIS standard compliant libraries.
//
// This library can be consumed by any programming languages that can invoke C-style
// function calls to bring HSM functionality to those platforms and languages that
// lack any PKCS#11 support.
//
// PKCS#11 v2.20 mechanisms and other definitions can be found in /oasis/pkcs11t.h
//
// Written by Benton Stark (bestark@cisco.com)
// Sept. 7, 2016
//----------------------------------------------------------------------------------------


// project includes
#include "p11hsm.h"
#include "mechtype.h"

// compiler include files
#include <cstdio>
#include <ctime>
#include <cctype>
#include <cstring>
#include <cstdlib>

// oasis specific includes
#include "oasis/cryptoki.h"


// global definitions
static CK_FUNCTION_LIST* _p11 = NULL;
#ifdef OS_WIN
static HINSTANCE _p11_lib_handle = 0;
#else
static void* _p11_lib_handle = NULL;
#endif

#ifndef DIM
#define DIM(a) (sizeof(a)/sizeof(a[0]))
#endif

#define HSMLIB_PRODUCT_VERSION "2.4.0"
#define HSMLIB_PRODUCT_VERSION_LEN 20
#define MAX_TOKEN_OBJECT_LABEL_SIZE 200
#define WRAP_BUF_LEN 3000
#define MAX_SLOT_COUNT  50
#define SEED_SIZE 128

// type def
typedef unsigned char uchar;

// prototypes
void __append_return_code(CK_RV code, char* text, unsigned long text_len);


CK_BBOOL __open_P11_library(const char* libPath)
{
	CK_C_GetFunctionList C_GetFunctionList = NULL;

#ifdef OS_WIN
	_p11_lib_handle = LoadLibrary(libPath);
	if( _p11_lib_handle )
	{
		C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress( _p11_lib_handle, "C_GetFunctionList" );
	}

#else
	_p11_lib_handle = dlopen(libPath, RTLD_NOW);
	if( _p11_lib_handle )
	{
		C_GetFunctionList = (CK_C_GetFunctionList)dlsym( _p11_lib_handle, "C_GetFunctionList" );
	}
#endif

	if( !_p11_lib_handle )
	{
		return CK_FALSE;
	}

	if( C_GetFunctionList )
	{
		CK_RV rv = C_GetFunctionList( &_p11 );
		if (rv == CKR_OK)
		{
			return CK_TRUE;
		}
	}

	return CK_FALSE;
}

CK_BBOOL __close_p11_library() {
	if( _p11_lib_handle )
	{
#ifdef OS_WIN
		FreeLibrary( _p11_lib_handle );
#else
		dlclose( _p11_lib_handle );
#endif
	}

	return CK_TRUE;
}


int __copy_fixed_padded_str_to_null_str(CK_CHAR * dest, const CK_CHAR * src, unsigned long size)
{
	CK_CHAR padVal = ' ';

	// find end of the padded string
	unsigned long lastChar = size - 1;
	for(int i=size-1; i >= 0; i--)
	{
		if (src[i] != padVal)
		{
			lastChar = i;
			break;
		}
	}

	// copy the string
	unsigned long j=0;
	for(; j <= lastChar; j++)
	{
		dest[j] = src[j];
	}

	// null terminate the destination string
	// not j was advanced from the previous for loop
	dest[j] = '\0';

	// return the count of characters in the destination string
	return j;
}


//----------------------------------------------------------------------------------------
// __wrap_key()  Wrap key with the supplied key handle.
//
//	Parameters:
//		h_session 		-- A session handle for a logged in session.
//		wrap_buf 		-- pointer to buffer to receive the wrapped private key.
//		wrap_buf_len 	-- length of pbWrapBuffer..
//		h_wrap_key 		-- handle of the wrapping key (DES3).
//		h_key_to_wrap	-- handle of key to be wrapped (private key).
//		mech_type	 	-- encryption mechanism type for the wrapping key algorithm
//		iv				-- initialization vector used by the wrapping key algorithm (optional)
//		iv_len 			-- initialization vector length in bytes (optional)
//
//	Returns:
//	 	 CKR_OK, error code if there is any error.
//
//----------------------------------------------------------------------------------------
CK_RV __wrap_key(CK_SESSION_HANDLE h_session, CK_BYTE_PTR wrap_buf, CK_ULONG_PTR wrap_buf_len, CK_OBJECT_HANDLE h_wrap_key,
				 CK_OBJECT_HANDLE h_key_to_wrap, CK_MECHANISM_TYPE mech_type, CK_BYTE_PTR iv, CK_ULONG iv_len )
{
	CK_RV rv = 0;
	CK_MECHANISM mech;

	mech.mechanism = mech_type;
	mech.pParameter = (void*) iv;
	mech.ulParameterLen = iv_len;

	CK_RSA_PKCS_OAEP_PARAMS oaep;
	memset(&oaep, 0, sizeof(oaep));

	// check to see if the mech type is RSA OAEP and if so set the OAEP parameters
	if (mech_type == CKM_RSA_PKCS_OAEP)
	{
		oaep.hashAlg = CKM_SHA_1;		// hard-coded to SHA-1 as it is widely supported by HSM vendors
		oaep.mgf = CKG_MGF1_SHA1;
		oaep.source = CKZ_DATA_SPECIFIED;
		oaep.pSourceData = (void*) iv;
		oaep.ulSourceDataLen = iv_len;
		// set the oaep parameters to the mechanism
		mech.pParameter = &oaep;
		mech.ulParameterLen = sizeof(oaep);
	}
	else
	{
		mech.pParameter = (void*) iv;
		mech.ulParameterLen = iv_len;
	}

	// wrap the key
	rv = _p11->C_WrapKey(h_session, &mech, h_wrap_key, h_key_to_wrap, wrap_buf, wrap_buf_len);

   return rv;
}


//----------------------------------------------------------------------------------------
// __unwrap_private_key()
//	Unwraps a private asymmetric key onto the HSM using a specified wrapping key and IV.
//
//	Parameters:
//		h_session	 	 -- a session handle for a logged in session.
//		h_wrap_key	 	 -- handle to the wrapping key
//		iv				 -- pointer to the byte array containing the wrapping key initialization vector
//		iv_len			 -- length of the wrapping key IV
//		mech_type		 -- wrapping key mechanism type (DES3, AES, etc)
//		key_label		 -- key label for the new unwrapped private key
//		key_label_len	 -- key label length
//		key_id			 -- key id for the new unwrapped private key
//		key_id_len		 -- key id length
//		key_buf			 -- key buffer containing bytes of wrapped (encrypted) private key
//		key_buf_len		 -- length of the private key buffer in bytes
//		key_type		 -- type of private key (DES, DES2, DES3, AES, etc)
//		token			 -- 1 to indicate the private key exists on the token and not the session; otherwise 0
//		private			 -- 1 to indicate the private key is private and can only be accessed after authentication; otherwise 0
//		sensitive	     -- 1 to indicate the private key is sensitive; otherwise 0
//		modifiable		 -- 1 to indicate the private key can be modified; otherwise 0
//		extractable		 -- 1 to indicate the private key can be extracted; otherwise 0
//		sign			 -- 1 to indicate the private key can sign; otherwise 0
//		decrypt			 -- 1 to indicate the private key can decrypt; otherwise 0
//		unwrap			 -- 1 to indicate the private key can unwrap; otherwise 0
//		derive			 -- 1 to indicate the private key can be used to derive other keys; otherwise 0
//		h_Key			 -- handle of the newly unwrapped key
//
//	Returns:
//		CK_RV, error code if there is any error.
//
//----------------------------------------------------------------------------------------
CK_RV __unwrap_private_key(CK_SESSION_HANDLE h_session, CK_OBJECT_HANDLE h_wrap_key, CK_BYTE_PTR iv, CK_ULONG iv_len, CK_MECHANISM_TYPE mech_type,
					 CK_CHAR_PTR key_label, CK_ULONG key_label_len, CK_CHAR_PTR key_id, CK_ULONG key_id_len,
					 CK_BYTE_PTR key_buf, CK_ULONG key_buf_len,
					 CK_KEY_TYPE key_type, CK_BBOOL token, CK_BBOOL private_,CK_BBOOL sensitive, CK_BBOOL modifiable, CK_BBOOL extractable,
					 CK_BBOOL sign, CK_BBOOL decrypt, CK_BBOOL unwrap, CK_BBOOL derive,
					 CK_OBJECT_HANDLE_PTR h_key)
{
	CK_MECHANISM mech;
	mech.mechanism = mech_type;

	CK_RSA_PKCS_OAEP_PARAMS oaep;
	memset(&oaep, 0, sizeof(oaep));

	// check to see if the mech type is RSA OAEP and if so set the OAEP parameters
	if (mech_type == CKM_RSA_PKCS_OAEP)
	{
		oaep.hashAlg = CKM_SHA_1;		// at the time of the edit only SHA-1 is supported by the Luna K6 and OpenSSL
		oaep.mgf = CKG_MGF1_SHA1;
		oaep.source = CKZ_DATA_SPECIFIED;
		oaep.pSourceData = (void*) iv;
		oaep.ulSourceDataLen = iv_len;
		// set the oaep parameters to the mechanism
		mech.pParameter = &oaep;
		mech.ulParameterLen = sizeof(oaep);
	}
	else
	{
		mech.pParameter = (void*) iv;
		mech.ulParameterLen = iv_len;
	}

	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE key_template[] = {
		{CKA_CLASS,			&key_class,	   	sizeof(key_class)},
		{CKA_KEY_TYPE,		&key_type,	   	sizeof(key_type)},
		{CKA_TOKEN,			&token,	   		sizeof(token)},
		{CKA_SENSITIVE,		&sensitive,   	sizeof(sensitive)},
		{CKA_PRIVATE,		&private_,	   	sizeof(private_)},
		{CKA_DECRYPT,		&decrypt,     	sizeof(decrypt)},
		{CKA_SIGN,			&sign,		   	sizeof(sign)},
		{CKA_UNWRAP,		&unwrap,      	sizeof(unwrap)},
		{CKA_DERIVE,		&derive,	   	sizeof(derive)},
		{CKA_MODIFIABLE,	&modifiable,  	sizeof(modifiable)},
		{CKA_EXTRACTABLE,	&extractable, 	sizeof(extractable)},
		{CKA_ID,			key_id,      	key_id_len},
		{CKA_LABEL,			key_label,      key_label_len}
	};

	CK_ATTRIBUTE_PTR p_key_template = key_template;

	CK_RV rv = _p11->C_UnwrapKey(h_session, &mech, h_wrap_key, key_buf, key_buf_len,
								 p_key_template, DIM(key_template), h_key);

   return rv;
}


//----------------------------------------------------------------------------------------
// __unwrap_secret_key()
//	Unwraps a secret symmetric key onto the HSM using a specified wrapping key and IV.
//
//	Parameters:
//		h_session	 		-- a session handle for a logged in session.
//		h_wrap_key	 		-- handle to the wrapping key
//		iv				 	-- pointer to the byte array containing the wrapping key initialization vector
//		iv_len			 	-- length of the wrapping key IV
//		mech_type			-- wrapping key mechanism type (DES3, AES, etc)
//		key_label			-- key label for the new unwrapped secret key
//		key_label_len		-- key label length
//		key_id				-- key id for the new unwrapped secret key
//		key_id_len			-- key id length
//		key_buf		 		-- key buffer containing bytes of wrapped (encrypted) secret key
//		key_buf_len		 	-- length of the secret key buffer in bytes
//		key_type		 	-- type of secret key (DES, DES2, DES3, AES, etc)
//		key_size			--	size of the secret key in bits (112, 128, 192, 256, etc)
//		token				-- 1 to indicate the secret key exists on the token and not the session; otherwise 0
//		private				-- 1 to indicate the secret key is private and can only be accessed after authentication; otherwise 0
//		sensitive	    	-- 1 to indicate the private key is sensitive; otherwise 0
//		modifiable		 	-- 1 to indicate the secret key can be modified; otherwise 0
//		extractable			-- 1 to indicate the secret key can be extracted; otherwise 0
//		sign				-- 1 to indicate the secret key can sign; otherwise 0
//		verify			 	-- 1 to indicate the secret key can verify; otherwise 0
//		encrypt				-- 1 to indicate the secret key can encrypt; otherwise 0
//		decrypt				-- 1 to indicate the secret key can decrypt; otherwise 0
//		wrap				-- 1 to indicate the secret key can wrap; otherwise 0
//		unwrap			 	-- 1 to indicate the secret key can unwrap; otherwise 0
//		derive			 	-- 1 to indicate the secret key can be used to derive other keys; otherwise 0
//		h_Key	 			-- handle of the newly unwrapped secret key
//
//	Returns:
//		CK_RV, error code if there is any error.
//
//----------------------------------------------------------------------------------------
CK_RV __unwrap_secret_key(CK_SESSION_HANDLE h_session, CK_OBJECT_HANDLE h_wrap_key, CK_BYTE_PTR iv, CK_ULONG iv_len, CK_MECHANISM_TYPE mech_type,
						  CK_CHAR_PTR key_label, CK_ULONG key_label_len, CK_CHAR_PTR key_id, CK_ULONG key_id_len,
						  CK_BYTE_PTR key_buf, CK_ULONG key_buf_len, CK_KEY_TYPE key_type, CK_ULONG key_size,
						  CK_BBOOL token, CK_BBOOL private_, CK_BBOOL sensitive, CK_BBOOL modifiable, CK_BBOOL extractable, CK_BBOOL sign,
						  CK_BBOOL verify, CK_BBOOL encrypt, CK_BBOOL decrypt, CK_BBOOL wrap, CK_BBOOL unwrap, CK_BBOOL derive,
						  CK_OBJECT_HANDLE_PTR h_key)
{
	CK_MECHANISM mech;
	mech.mechanism = mech_type;

	CK_RSA_PKCS_OAEP_PARAMS oaep;
	memset(&oaep, 0, sizeof(oaep));

	// check to see if the mech type is RSA OAEP and if so set the OAEP parameters
	if (mech_type == CKM_RSA_PKCS_OAEP)
	{
		oaep.hashAlg = CKM_SHA_1;		// at the time of the edit only SHA-1 is supported by the Luna K6 and OpenSSL
		oaep.mgf = CKG_MGF1_SHA1;
		oaep.source = CKZ_DATA_SPECIFIED;
		oaep.pSourceData = (void*) iv;
		oaep.ulSourceDataLen = iv_len;
		// set the oaep parameters to the mechanism
		mech.pParameter = &oaep;
		mech.ulParameterLen = sizeof(oaep);
	}
	else
	{
		mech.pParameter = (void*) iv;
		mech.ulParameterLen = iv_len;
	}

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;

	CK_ATTRIBUTE_PTR p_key_template = NULL;
	CK_ULONG key_template_len = 0;

	// convert bits to bytes for the P11 API which expects key size in bytes
	CK_ULONG bytes_key_size = key_size / 8;

	// if the wrapped key is not padded then we have to add the additional attribute
	// for the value length to the attribute template
	CK_ATTRIBUTE key_template[] = {
		{CKA_CLASS,			&key_class,	   		sizeof(key_class)},
		{CKA_KEY_TYPE,		&key_type,	   		sizeof(key_type)},
		{CKA_TOKEN,			&token,	   			sizeof(token)},
		{CKA_SENSITIVE,		&sensitive,   		sizeof(sensitive)},
		{CKA_PRIVATE,		&private_,	   		sizeof(private_)},
		{CKA_ENCRYPT,		&encrypt,     		sizeof(encrypt)},
		{CKA_DECRYPT,		&decrypt,     		sizeof(decrypt)},
		{CKA_SIGN,			&sign,		   		sizeof(sign)},
		{CKA_VERIFY,		&verify,	   		sizeof(verify)},
		{CKA_WRAP,			&wrap,		   		sizeof(wrap)},
		{CKA_UNWRAP,		&unwrap,      		sizeof(unwrap)},
		{CKA_DERIVE,		&derive,	   		sizeof(derive)},
		{CKA_MODIFIABLE,	&modifiable,  		sizeof(modifiable)},
		{CKA_EXTRACTABLE,	&extractable, 		sizeof(extractable)},
		{CKA_VALUE_LEN,		&bytes_key_size, 	sizeof(bytes_key_size)},
		{CKA_ID,			key_id,      		key_id_len},
		{CKA_LABEL,			key_label,      	key_label_len}
	};

	p_key_template = key_template;
	key_template_len = DIM(key_template);

	CK_RV rv = _p11->C_UnwrapKey(h_session, &mech, h_wrap_key, key_buf, key_buf_len, p_key_template, key_template_len, h_key);

    return rv;
}


//----------------------------------------------------------------------------------------
// __gen_rsa_key_pair()
//	Generates a RSA key pair on HSM.
//  for private key which instructs the HSM to do all key operations in hardware.
//
//	Parameters:
//		h_session		-- a session handle for a logged in session.
//		mech_type		-- mechanism type (usually CKM_RSA_X9_31_KEY_PAIR_GEN or CKM_RSA_PKCS_KEY_PAIR_GEN)
// 						   Note: CKM_RSA_X9_31_KEY_PAIR_GEN is functionally identical to CKM_RSA_PKCS_KEY_PAIR_GEN
//						   but provides stronger guarantee of p and q values as defined in X9.31
// 						   Cavium HSMs only support the CKM_RSA_X9_31_KEY_PAIR_GEN mechanism
//		key_size		-- length of keyPair
//		pub_exp			-- public exponent byte array
//		pub_exp_len		-- length of the public exponent byte array
//		pub_label		-- public key label
//		pub_label_len	-- length of public key label
//		pvt_label		-- private key label
//		pvt_label_len	-- length of private key label
//		pub_id			-- public key ID value
//		pub_id_len		-- length of public key ID value
//		pvt_id			-- private key ID value
//		pvt_id_len		-- length of private key ID value
//		token			-- 1 to indicate the keys exist on the token and not the session; otherwise 0
//		pub_private 	-- 1 to indicate the public key is marked private and can only be accessed after authentication; otherwise 0
//		pvt_private 	-- 1 to indicate the private key is marked private and can only be accessed after authentication; otherwise 0
//		sensitive	    -- 1 to indicate the private key is sensitive; otherwise 0
//		modifiable		-- 1 to indicate the keys can be modified; otherwise 0
//		extractable		-- 1 to indicate the private key can be extracted; otherwise 0
//		sign			-- 1 to indicate the private key can sign; otherwise 0
//		verify			-- 1 to indicate the public key can verify; otherwise 0
//		encrypt			-- 1 to indicate the public key can encrypt; otherwise 0
//		decrypt			-- 1 to indicate the private key can decrypt; otherwise 0
//		wrap			-- 1 to indicate the public key can wrap; otherwise 0
//		unwrap			-- 1 to indicate the private key can unwrap; otherwise 0
//		derive			-- 1 to indicate the private key can be used to derive other keys; otherwise 0
//		h_pub_key		-- handle of the public key.
//		h_pvt_key		-- handle of the private key.
//
//	Returns:
//		CK_RV, error code if there is any error.
//
//----------------------------------------------------------------------------------------
CK_RV __gen_rsa_key_pair(CK_SESSION_HANDLE h_session, CK_ULONG key_size, CK_BYTE_PTR pub_exp, CK_ULONG pub_exp_len,
					 CK_CHAR_PTR pub_label, CK_ULONG pub_label_len, CK_CHAR_PTR pvt_label, CK_ULONG pvt_label_len,
					 CK_BYTE_PTR pub_id, CK_ULONG pub_id_len, CK_BYTE_PTR pvt_id, CK_ULONG pvt_id_len,
					 CK_MECHANISM_TYPE mech_type, CK_BBOOL token, CK_BBOOL pub_private, CK_BBOOL pvt_private,
					 CK_BBOOL sensitive, CK_BBOOL modifiable, CK_BBOOL extractable, CK_BBOOL sign,
					 CK_BBOOL verify, CK_BBOOL encrypt, CK_BBOOL decrypt, CK_BBOOL wrap, CK_BBOOL unwrap, CK_BBOOL derive,
					 CK_OBJECT_HANDLE_PTR h_pub, CK_OBJECT_HANDLE_PTR h_pvt)
{
	CK_RV rv = CKR_OK;
	CK_ULONG pub_template_len = 0;
	CK_ULONG pvt_template_len = 0;

	CK_MECHANISM mech = {mech_type, 0, 0};
	CK_OBJECT_CLASS	pub_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS	pvt_class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type = CKK_RSA;

	CK_ATTRIBUTE_PTR  p_pub_template;
	CK_ATTRIBUTE_PTR  p_pvt_template;

	//	setup the public RSA key template
	CK_ATTRIBUTE pub_template[] = {
	  {CKA_CLASS, 			&pub_class, 	sizeof(pub_class)},
	  {CKA_KEY_TYPE, 		&key_type, 		sizeof(key_type)},
	  {CKA_TOKEN, 			&token, 		sizeof(token)},
	  {CKA_PRIVATE, 		&pub_private, 	sizeof(pub_private)},
	  {CKA_MODIFIABLE, 		&modifiable, 	sizeof(modifiable)},
	  {CKA_ENCRYPT, 		&encrypt, 		sizeof(encrypt)},
	  {CKA_VERIFY, 			&verify, 		sizeof(verify)},
	  {CKA_WRAP, 			&wrap, 			sizeof(wrap)},
	  {CKA_MODULUS_BITS, 	&key_size, 		sizeof(key_size)},
	  {CKA_PUBLIC_EXPONENT, pub_exp, 		pub_exp_len},
	  {CKA_ID, 				&pub_id, 		pub_id_len},
	  {CKA_LABEL, 			pub_label, 		pub_label_len}
	};

	//	setup the private RSA key template
	CK_ATTRIBUTE pvt_template[] = {
	  {CKA_CLASS, 			&pvt_class, 	sizeof(pvt_class)},
	  {CKA_KEY_TYPE, 		&key_type, 		sizeof(key_type)},
	  {CKA_TOKEN, 			&token, 		sizeof(token)},
	  {CKA_SENSITIVE,		&sensitive,   	sizeof(sensitive)},
	  {CKA_PRIVATE, 		&pvt_private,	sizeof(pvt_private)},
	  {CKA_MODIFIABLE, 		&modifiable, 	sizeof(modifiable)},
	  {CKA_EXTRACTABLE, 	&extractable, 	sizeof(extractable)},
	  {CKA_DECRYPT, 		&decrypt, 		sizeof(decrypt)},
	  {CKA_SIGN, 			&sign, 			sizeof(sign)},
	  {CKA_UNWRAP, 			&unwrap, 		sizeof(unwrap)},
	  {CKA_DERIVE, 			&derive, 		sizeof(derive)},
	  {CKA_ID, 				&pvt_id, 		pvt_id_len},
	  {CKA_LABEL, 			pvt_label, 		pvt_label_len}
	};

	// create the pointers and set the size values
	p_pub_template = pub_template;
	pub_template_len = DIM(pub_template);
	p_pvt_template = pvt_template;
	pvt_template_len = DIM(pvt_template);

	// generate the RSA key pair
	rv = _p11->C_GenerateKeyPair(h_session, &mech, p_pub_template, pub_template_len,
			p_pvt_template, pvt_template_len, h_pub, h_pvt);

   return rv;
}

//----------------------------------------------------------------------------------------
// __gen_ec_key_pair()
//	Generates a ECDSA key pair on HSM.  Curve specifics are defined by the ASN.1
//	DER encoded bit string derParams byte array.
//  for private key which instructs the HSM to do all key operations in hardware.
//
//	Parameters:
//		h_session	 		-- a session handle for a logged in session.
//		ec_params	 		-- byte string containing the ASN.1 DER encoded curve parameter data
//		ec_params_len		-- length of derParams
//		pub_label 			-- public key label
//		pub_label_len		-- public key label length
//		pvt_label			-- private key label
//		pvt_label_len		-- private key label length
//		pub_id				-- public key ID value
//		pub_id_len			-- length of public key ID value
//		pvt_id				-- private key ID value
//		pvt_id_len			-- length of private key ID value
//		token				-- 1 to indicate the keys exist on the token and not the session; otherwise 0
//		pub_private 		-- 1 to indicate the public key is marked private and can only be accessed after authentication; otherwise 0
//		pvt_private 		-- 1 to indicate the private key is marked private and can only be accessed after authentication; otherwise 0
//		sensitive	    	-- 1 to indicate the private key is sensitive; otherwise 0
//		modifiable			-- 1 to indicate the keys can be modified; otherwise 0
//		extractable		 	-- 1 to indicate the private key can be extracted; otherwise 0
//		sign				-- 1 to indicate the private key can sign; otherwise 0
//		verify			 	-- 1 to indicate the public key can verify; otherwise 0
//		encrypt			 	-- 1 to indicate the public key can encrypt; otherwise 0
//		decrypt			 	-- 1 to indicate the private key can decrypt; otherwise 0
//		wrap				-- 1 to indicate the public key can wrap; otherwise 0
//		unwrap			 	-- 1 to indicate the private key can unwrap; otherwise 0
//		derive			 	-- 1 to indicate the private key can be used to derive other keys; otherwise 0
//		h_pub_key 			-- handle of the newly created public key
//		h_pvt_key 			-- handle of the newly created private key
//
//	Returns:
//		CK_RV, error code if there is any error.
//
//----------------------------------------------------------------------------------------

CK_RV __gen_ec_key_pair(CK_SESSION_HANDLE h_session, CK_BYTE_PTR ec_params, CK_ULONG ec_params_len,
					 CK_CHAR_PTR pub_label, CK_ULONG pub_label_len, CK_CHAR_PTR pvt_label, CK_ULONG pvt_label_len,
					 CK_BYTE_PTR pub_id, CK_ULONG pub_id_len, CK_BYTE_PTR pvt_id, CK_ULONG pvt_id_len,
					 CK_BBOOL token, CK_BBOOL pub_private, CK_BBOOL pvt_private, CK_BBOOL sensitive, CK_BBOOL modifable, CK_BBOOL extractable, CK_BBOOL sign,
					 CK_BBOOL verify, CK_BBOOL encrypt, CK_BBOOL decrypt, CK_BBOOL wrap, CK_BBOOL unwrap, CK_BBOOL derive,
					 CK_OBJECT_HANDLE_PTR h_pub_key, CK_OBJECT_HANDLE_PTR h_pvt_key)
{
	CK_RV rv = CKR_OK;
	CK_ULONG pub_template_len = 0;
	CK_ULONG pvt_template_len = 0;

	CK_MECHANISM mech = {CKM_ECDSA_KEY_PAIR_GEN, 0, 0};

	CK_ATTRIBUTE_PTR p_pub_template;
	CK_ATTRIBUTE_PTR p_pvt_template;

	// create the EC public key template
	CK_ATTRIBUTE pub_template[] = {
	  {CKA_TOKEN, 			&token, 		sizeof(token)},
	  {CKA_PRIVATE, 		&pub_private, 	sizeof(pub_private)},
	  {CKA_VERIFY, 			&verify, 		sizeof(verify)},
	  {CKA_DERIVE, 			&derive, 		sizeof(derive)},
	  {CKA_MODIFIABLE, 		&modifable, 	sizeof(modifable)},
	  {CKA_ENCRYPT, 		&encrypt, 		sizeof(encrypt)},
	  {CKA_WRAP, 			&wrap, 			sizeof(wrap)},
	  {CKA_EC_PARAMS, 		ec_params, 		ec_params_len},
	  {CKA_ID, 				&pub_id, 		pub_id_len},
	  {CKA_LABEL, 			pub_label, 		pub_label_len}
	};

	// create the EC private key template
	CK_ATTRIBUTE pvt_template[] = {
	  {CKA_TOKEN, 			&token,			sizeof(token)},
	  {CKA_SENSITIVE,		&sensitive,   	sizeof(sensitive)},
	  {CKA_PRIVATE, 		&pvt_private,	sizeof(pvt_private)},
	  {CKA_SIGN, 			&sign, 			sizeof(sign)},
	  {CKA_DERIVE, 			&derive, 		sizeof(derive)},
	  {CKA_EXTRACTABLE, 	&extractable, 	sizeof(extractable)},
	  {CKA_MODIFIABLE, 		&modifable, 	sizeof(modifable)},
	  {CKA_DECRYPT, 		&decrypt, 		sizeof(decrypt)},
	  {CKA_UNWRAP, 			&unwrap, 		sizeof(unwrap)},
	  {CKA_ID, 				&pvt_id, 		pvt_id_len},
	  {CKA_LABEL, 			pvt_label, 		pvt_label_len},
	};

	// create the pointers and set the size values
	p_pub_template = pub_template;
	pub_template_len = DIM(pub_template);
	p_pvt_template = pvt_template;
	pvt_template_len = DIM(pvt_template);

	// call PKCS-11 API to generate the EC key pair on the HSM
	rv = _p11->C_GenerateKeyPair(h_session, &mech, p_pub_template, pub_template_len, p_pvt_template, pvt_template_len,
			h_pub_key, h_pvt_key);

   return rv;
}


//----------------------------------------------------------------------------------------
//  __gen_secret_key()
//	Generates a new secret symmetrical key on HSM.
//  which instructs the HSM to do all key operations in hardware.
//
//	Parameters:
//		h_session		-- a session handle for a logged in session
//		key_label		-- label of the new key
//		key_label_len	-- length of key label
//		key_id			-- id of the new key
//		key_id_len		-- length of key id
//		mech_type	 	-- mechanism type of the key (CKM_DES_KEY_GEN, CKM_AES_KEY_GEN, ect)
//		key_size		-- size of the key to create in bits
//		token			-- 1 to indicate the keys exist on the token and not the session; otherwise 0
//		private			-- 1 to indicate the keys are private and can only be accessed after authentication; otherwise 0
//		sensitive	    -- 1 to indicate the private key is sensitive; otherwise 0
//		modifiable		-- 1 to indicate the keys can be modified; otherwise 0
//		extractable		-- 1 to indicate the private key can be extracted; otherwise 0
//		sign			-- 1 to indicate the private key can sign; otherwise 0
//		verify			-- 1 to indicate the public key can verify; otherwise 0
//		encrypt			-- 1 to indicate the public key can encrypt; otherwise 0
//		decrypt			-- 1 to indicate the private key can decrypt; otherwise 0
//		wrap			-- 1 to indicate the public key can wrap; otherwise 0
//		unwrap			-- 1 to indicate the private key can unwrap; otherwise 0
//		derive			-- 1 to indicate the private key can be used to derive other keys; otherwise 0
//		h_key			-- handle of the newly created key
//
//	Returns:
//		CK_RV, error code if there is any error.
//
//----------------------------------------------------------------------------------------

CK_RV __gen_secret_key(CK_SESSION_HANDLE h_session,
					 CK_CHAR_PTR key_label, CK_ULONG key_label_len, CK_CHAR_PTR key_id, CK_ULONG key_id_len,
					 CK_MECHANISM_TYPE mech_type, CK_ULONG key_size,
					 CK_BBOOL token, CK_BBOOL private_, CK_BBOOL sensitive, CK_BBOOL modifiable, CK_BBOOL extractable, CK_BBOOL sign,
					 CK_BBOOL verify, CK_BBOOL encrypt, CK_BBOOL decrypt, CK_BBOOL wrap, CK_BBOOL unwrap, CK_BBOOL derive,
					 CK_OBJECT_HANDLE_PTR h_key)
{
	CK_RV rv = CKR_OK;
	CK_ULONG template_size = 0;

	CK_MECHANISM mech = {mech_type, 0, 0};

	CK_ATTRIBUTE_PTR p_template;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;

	// convert bits to bytes for the P11 API which expects key size in bytes
	CK_ULONG bytes_key_size = key_size / 8;

	CK_ATTRIBUTE secret_template[] = {
	  {CKA_CLASS,		&key_class,		sizeof(key_class)},
	  {CKA_TOKEN,		&token,			sizeof(token)},
	  {CKA_SENSITIVE,	&sensitive,   	sizeof(sensitive)},
	  {CKA_PRIVATE,		&private_,		sizeof(private_)},
	  {CKA_ENCRYPT,		&encrypt,		sizeof(encrypt)},
	  {CKA_DECRYPT,		&decrypt,		sizeof(decrypt)},
	  {CKA_SIGN,		&sign,			sizeof(sign)},
	  {CKA_VERIFY,		&verify,		sizeof(verify)},
	  {CKA_WRAP,		&wrap,			sizeof(wrap)},
	  {CKA_UNWRAP,		&unwrap,		sizeof(unwrap)},
	  {CKA_DERIVE,		&derive,		sizeof(derive)},
	  {CKA_MODIFIABLE,	&modifiable,	sizeof(modifiable)},
	  {CKA_EXTRACTABLE,	&extractable,	sizeof(extractable)},
	  {CKA_VALUE_LEN,	&bytes_key_size,sizeof(bytes_key_size)},
	  {CKA_ID,			key_id,			key_id_len},
	  {CKA_LABEL,		key_label,		key_label_len}
	};

	// create the pointers and set the size values
	p_template = secret_template;
	template_size = DIM(secret_template);

	// call PKCS-11 API to generate the symmetric key
	rv = _p11->C_GenerateKey(h_session, &mech, p_template, template_size, h_key);

	return rv;
}

void __null_terminated_blank_string(CK_CHAR *buf, const int size)
{
	size_t i;

	if (size > 0)
	{
		i = size - 1;
		while (buf[i] == ' ')
		{
			buf[i] = 0;
			if (i > 0) i--;
		}
	}

	return;
}


//----------------------------------------------------------------------------------------
//	__destroy_object()
//		Destroy object on the HSM.
//
//	Parameters:
//		h_session	-- Session handle
//		hKey		-- handle to the key to destroy on the HSM
//
//----------------------------------------------------------------------------------------
void __destroy_object(CK_SESSION_HANDLE h_session, CK_OBJECT_HANDLE hKey)
{
	if (hKey)
	{
		_p11->C_DestroyObject(h_session, hKey);
	}
}


//----------------------------------------------------------------------------------------
//	__get_modulus()
//
//	Modifies:
//		msg_buf		--	contains any error messages
//
//	Inputs:
//		msg_buf_len	--	byte length of provided error message buffer
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//----------------------------------------------------------------------------------------
CK_RV __get_modulus(CK_SESSION_HANDLE h_session, CK_OBJECT_HANDLE h_key, unsigned char *mod_buf, unsigned long* mod_buf_len)
{

	// setup the attribute template
	CK_ATTRIBUTE attrib_template[] = {
			{CKA_MODULUS, NULL_PTR, 0},
			{CKA_PUBLIC_EXPONENT, NULL_PTR, 0} };

	CK_RV rv = CKR_OK;

	// call the first time with a null pointer in order to get the length of the
	// data we need to extract - this is common in pure C APIs
	rv = _p11->C_GetAttributeValue(h_session, h_key, attrib_template, 2);
	if (rv != CKR_OK)
	{
		return rv;
	}

	// allocate the memory so we can call C_GetAttributeValue again and this time
	// actually get the data.
	CK_BYTE_PTR p_modulus = (CK_BYTE_PTR) malloc(attrib_template[0].ulValueLen);
	attrib_template[0].pValue = p_modulus;

	CK_BYTE_PTR p_exponent = (CK_BYTE_PTR) malloc(attrib_template[1].ulValueLen);
	attrib_template[1].pValue = p_exponent;

	// call C_GetAttributeValue again and this time get our values for modulus and exponent
	rv = _p11->C_GetAttributeValue(h_session, h_key, attrib_template, 2);
	if (rv != CKR_OK)
	{
		// free the memory we allocated
		free(p_modulus);
		free(p_exponent);
		return rv;
	}

	// copy the modulus bytes over
	memcpy(mod_buf, p_modulus, attrib_template[0].ulValueLen);

	// get the length of the modulus
	*mod_buf_len = attrib_template[0].ulValueLen;

	// free the memory we allocated
	free(p_modulus);
	free(p_exponent);

	return rv;
}


//----------------------------------------------------------------------------------------
// get_lib_version()
//  Retrieves string containing the version information for the library.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf				--	contains any error messages
//		version_info		--  contains library version information
//
//	Inputs:
//		msg_buf_len			--	byte length of provided error message buffer
//		version_info_len	--  byte length of versionInfo buffer (minimum 15 bytes)
//----------------------------------------------------------------------------------------
int get_lib_version(char* msg_buf, unsigned long msg_buf_len, char *version_info, unsigned long version_info_len)
{

	if (!version_info)
	{
		snprintf(msg_buf, msg_buf_len, "get_lib_version: version_info variable is null.");
		return FALSE;
	}

	if (version_info_len < HSMLIB_PRODUCT_VERSION_LEN)
	{
		snprintf(msg_buf, msg_buf_len, "get_lib_version: version_info_len is less than 10 .");
		return FALSE;
	}

	snprintf(version_info, version_info_len, "%s", HSMLIB_PRODUCT_VERSION);

	return TRUE;
}

//----------------------------------------------------------------------------------------
// connect()
//	Connect to the PKCS-11 client shared library.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf		--	contains any error messages
//
//	Inputs:
//		msg_buf_len	--	byte length of provided error message buffer
//		lib_path	 --	file path char array to shared HSM vendor
//					 	PKCS#11 shared dynamic library
//		lib_path_len -- length of library path
//
//----------------------------------------------------------------------------------------
int connect(char* msg_buf, unsigned long msg_buf_len, char* lib_path, unsigned long lib_path_len)
{

	if (!lib_path || lib_path_len <= 0)
	{
		snprintf(msg_buf, msg_buf_len, "connect: parameter lib_path must contain a value.");
		return FALSE;
	}

	// build our own null terminated string since this is what the PKCS#11 library will
	// work off of and we can guarantee it will be null terminated for some specified size
	char lib_path_null[lib_path_len+1];
	memset(lib_path_null, 0x00, sizeof(lib_path_null));
	strncpy(lib_path_null, lib_path, lib_path_len);

	// connect to the target PKCS-11 client shared library
	if( __open_P11_library(lib_path_null) == CK_FALSE )
	{
		snprintf(msg_buf, msg_buf_len, "connect: failed to load shared library %s", lib_path_null);
 		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// disconnect()
//  Disconnect from PKCS-11 client shared library.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf		-- contains any error messages
//
//	Inputs:
//		msg_buf_len	-- byte length of provided error message buffer
//----------------------------------------------------------------------------------------
int disconnect(char* msg_buf, unsigned long msg_buf_len)
{
	// connect to the target PKCS-11 client shared library
	if( __close_p11_library() == CK_FALSE )
	{
		snprintf(msg_buf, msg_buf_len, "disconnect: an error occurred while trying to close PKCS-11 client shared library");
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// initialize()
//	Calls PKCS#11 C_Initialize().
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf		--	contains any error messages
//
//	Inputs:
//		msg_buf_len	--	byte length of provided error message buffer
//----------------------------------------------------------------------------------------
int initialize(char* msg_buf, unsigned long msg_buf_len)
{
	CK_RV rv = CKR_OK;

	rv = _p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "initialize: PKCS#11 C_Initialize() reports an error %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// finalize()
//  Calls PKCS#11 C_Finalize.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf		-- contains any error messages
//
//	Inputs:
//		msg_buf_len	-- byte length of provided error message buffer
//----------------------------------------------------------------------------------------
int finalize(char* msg_buf, unsigned long msg_buf_len)
{
	CK_RV rv = CKR_OK;

	// attempt to terminate the connection to the PKCS API
	rv = _p11->C_Finalize(NULL_PTR);
	if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
	{
		snprintf(msg_buf, msg_buf_len, "finalize: PKCS#11 C_Finalize() reports PKCS#11 library 'not initialized'.  Call connect() first.");
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "finalize: PKCS#11 C_Finalize failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// open_session()
//	Scans all the available slots looking for matching serial number.
//	If a slot is found then open a session on the token and returns the session handle
//	and the slot number.  Note: the CKF_SERIAL_SESSION flag is always set.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			-- contains any error messages
//		h_session		-- session handle of HSM device after a session is successfully opened
//
//	Inputs:
//		slot			-- token slot number
//		msg_buf_len		-- byte length of provided error message buffer
//		flags			-- various login flags (typically use is CKF_RW_SESSION | CKF_SERIAL_SESSION)
//							CKF_EXCLUSIVE_SESSION       0x0001	- session is exclusive and no other sessions can be opened
//																  (appears to be a SafeNet specific flag option)
//							CKF_RW_SESSION              0x0002  - session is a read/write session rather than readonly
//							CKF_SERIAL_SESSION          0x0004	- For legacy reasons, the CKF_SERIAL_SESSION bit must always be set;
//			  													  if a call to C_OpenSession does not have this bit set, the P11 call should
//																  return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED
//							CKF_SO_SESSION              0x8000  - security officer session
//																  (appears to be a SafeNet specific flag option)
//																  this flag must be set if the Login CK_USER_TYPE is a CKU_SO
//
//----------------------------------------------------------------------------------------
int open_session(char* msg_buf, unsigned long msg_buf_len, unsigned long slot, unsigned long flags, unsigned long* h_session)
{

	if (slot < 0)
	{
		snprintf(msg_buf, msg_buf_len, "open_session: invalid slot number.");
		return FALSE;
	}

	// always set the CKF_SERIAL_SESSION flag (legacy flag required by all modern HSM P11 APIs)
	flags |= CKF_SERIAL_SESSION;
	CK_SESSION_HANDLE handle = -1;
	CK_RV rv = _p11->C_OpenSession(slot, flags, NULL, NULL, &handle);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "open_session: PKCS#11 C_OpenSession on slot %lu failed with return value %lu.", slot, rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// pass the numeric handle number back to the session handle back to caller
	*h_session = handle;

	return TRUE;
}

//----------------------------------------------------------------------------------------
// close_session()
//  Closes specified session on the HSM.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			-- contains any error messages
//
//	Inputs:
//		msg_buf_len		-- byte length of provided error message buffer
//		h_session		-- session handle to close
//----------------------------------------------------------------------------------------
int close_session(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session)
{
	CK_RV rv = _p11->C_CloseSession(h_session);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "close_session: PKCS#11 C_CloseSession failed with return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

   return TRUE;
}

//----------------------------------------------------------------------------------------
// close_all_sessions()
//  Closes all open sessions on a given HSM slot.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			-- contains any error messages
//
//	Inputs:
//		msg_buf_len		-- byte length of provided error message buffer
//		slotId			-- ID of the slot to close all sessions on
//----------------------------------------------------------------------------------------
int close_all_sessions(char* msg_buf, unsigned long msg_buf_len, unsigned long slot_id)
{
	CK_RV rv = _p11->C_CloseAllSessions(slot_id);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "close_all_sessions: PKCS#11 C_CloseAllSessions failed with return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

   return TRUE;
}

//----------------------------------------------------------------------------------------
// login()
//	Calls PKCS#11 C_Login().
//  Must have an open session to use.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains error messages
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer.
//		h_session		--  handle number of the session to execute a login operation on
//		user_type		--  type of user to login as (Security Officer = 0, User = 1, Crypto Officer = 2)
//		user_pin		--  user PIN number
//      user_pin_len	--  length of user PIN
//----------------------------------------------------------------------------------------
int login(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long user_type, unsigned char* user_pin, unsigned long user_pin_len)
{
	CK_RV rv = 0;

	rv = _p11->C_Login(h_session, user_type, user_pin, user_pin_len);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "login: PKCS#11 C_Login failed; return value %lu.", rv);
   		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// logout()
//	Calls PKCS#11 C_Logout().
//  Logs out of the HSM.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			-- contains any error messages
//
//	Inputs:
//		msg_buf_len		-- byte length of provided error message buffer.
//		h_session		-- active session handle
//----------------------------------------------------------------------------------------
int logout(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session)
{
	CK_RV rv = 0;

	rv = _p11->C_Logout(h_session);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "logout: PKCS#11 C_Logout failed; return value %lu.", rv);
   		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}


//----------------------------------------------------------------------------------------
// set_pin()
//  Sets the PIN for the authenticated session user.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains any error messages
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer.
//		h_session		--  handle number of the session to execute a login operation on
//		old_pin			--  old user PIN
//		old_pin_len		--  old user PIN length
//		new_pin			--  new user PIN
//		new_pin_len		--  new user PIN length
//----------------------------------------------------------------------------------------
int set_pin(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* old_pin, unsigned long old_pin_len, unsigned char* new_pin, unsigned long new_pin_len)
{
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "set_pin: h_session variable is null.");
		return FALSE;
	}

	CK_RV rv = 0;

	rv = _p11->C_SetPIN(h_session, old_pin, old_pin_len, new_pin, new_pin_len);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "set_pin: PKCS#11 C_SetPIN failed; return value %lu.", rv);
   		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// find_objects()
//	Queries the HSM for all objects viewable by the currently logged in session user and
//  returns objects handles as an array of integers.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains error messages
//		h_object_array			--	modified to contain object handles
//		h_object_array_len		--  length of the object array buffer on input
//
//	Inputs:
//		msg_buf_len				--  length of the error message buffer
//		h_session				--	handle of an open session with the HSM.
//
//----------------------------------------------------------------------------------------
int find_objects(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long* h_object_array, unsigned long* h_object_array_len)
{

	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "find_objects: h_session variable is null.");
		return FALSE;
	}

	if (!h_object_array)
	{
		snprintf(msg_buf, msg_buf_len, "find_objects: h_object_array variable is null.");
		return FALSE;
	}

	if (!h_object_array_len)
	{
		snprintf(msg_buf, msg_buf_len, "find_objects: h_object_array variable is 0.");
		return FALSE;
	}

	CK_OBJECT_HANDLE h_object;
	CK_ULONG count = 0;
	CK_RV rv = 0;
	unsigned long idx = 0;

	rv = _p11->C_FindObjectsInit(h_session, NULL_PTR, 0);

	while (1)
	{
		rv = _p11->C_FindObjects(h_session, &h_object, 1, &count);
		if (rv != CKR_OK)
		{
			snprintf(msg_buf, msg_buf_len, "find_objects: PKCS#11 C_FindObjects for h_session %lu failed with return value %lu.", h_session, rv);
			__append_return_code(rv, msg_buf, msg_buf_len);
			_p11->C_FindObjectsFinal(h_session);
			return FALSE;
		}

		if (count == 0)
			break;

		if (idx+1 > *h_object_array_len)
		{
			snprintf(msg_buf, msg_buf_len, "find_objects: number of objects found exceed h_object_array length.");
			_p11->C_FindObjectsFinal(h_session);
			return FALSE;
		}

		// store the object handle in the array passed in by the caller
		h_object_array[idx++] = h_object;
	}

	// set the array length
	*h_object_array_len = idx;

	rv = _p11->C_FindObjectsFinal(h_session);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "find_objects: PKCS#11 C_FindObjectsFinal for h_session %lu failed with return value %lu.", h_session, rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// get_object_handle()
//	Get the handle of an object on the HSM by label name.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf				--	contains error messages
//		h_object			--	to contain handle of first key that matches supplied label,
//								or zero if key not found
//	Inputs:
//		msg_buf_len			--  length of the error message buffer
//		object_label		--	object label
//		object_label_len	--	length of object label
//		h_session			--	handle of an open session with the HSM
//----------------------------------------------------------------------------------------
int get_object_handle(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* object_label, unsigned long object_label_len, unsigned long* h_object)
{

	if (!object_label)
	{
		snprintf(msg_buf, msg_buf_len, "get_object_handle: label variable is null.");
		return FALSE;
	}

	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "get_object_handle: h_session variable is null.");
		return FALSE;
	}

	if ((object_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE) || (object_label_len == 0))
	{
		snprintf(msg_buf, msg_buf_len, "get_object_handle: label variable length is greater than 32 or is 0.");
		return FALSE;
	}

	CK_RV rv = 0;
	CK_CHAR label[50];
	label[object_label_len] = '\0';
	memcpy(label, object_label, object_label_len);
	CK_ATTRIBUTE findTemplate = { CKA_LABEL, label, object_label_len};
	CK_ULONG found_count = 0;
	CK_OBJECT_HANDLE handle[1];
	handle[0] = 0;

	rv = _p11->C_FindObjectsInit(h_session, &findTemplate, 1);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_object_handle: PKCS#11 C_FindObjectsInit for h_session %lu failed.", h_session);
	 	 __append_return_code(rv, msg_buf, msg_buf_len);
		 return FALSE;
	}

	rv = _p11->C_FindObjects(h_session, handle, 1, &found_count );
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_object_handle: PKCS#11 C_FindObjects for h_session %lu failed.", h_session);
	 	 __append_return_code(rv, msg_buf, msg_buf_len);
		 return FALSE;
	}

	rv = _p11->C_FindObjectsFinal(h_session);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_object_handle: PKCS#11 C_FindObjectsFinal for h_session %lu failed.", h_session);
	 	 __append_return_code(rv, msg_buf, msg_buf_len);
		 return FALSE;
	}

	// return the object handle
	*h_object = handle[0];

	return TRUE;
}

//----------------------------------------------------------------------------------------
// sign()
//	Signs data buffer using specified signing key and signing key mechanism (algorithm).
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					 --	contains error messages
//		signatureBuf			 --	buffer to contain signature
//		signatureBufLen			 --	length of signature buffer
//
//	Inputs:
//		msg_buf_len				 -- length of the error message buffer
//		data_buf				 --	buffer containing data to be signed
//		data_buf_len			 --	byte length of data to be signed
//		h_key					 --	handle of key to be used for signing
//		mech_type  				 -- mechanism type of the signing algorithm
//		salt_len				 -- optional salt length value (required for PSS signatures)
//		h_session				 --	handle of an open session with the HSM
//----------------------------------------------------------------------------------------
int sign(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len,
 		 unsigned long h_key, unsigned long mech_type, unsigned long salt_len, unsigned char* sig_buf, unsigned long* sig_buf_len)
{
	CK_RV rv = 0;
    CK_RSA_PKCS_PSS_PARAMS pssParams;
    int use_pss = TRUE;

	if (!sig_buf)
	{
		snprintf(msg_buf, msg_buf_len, "sign: null value not allowed for parameter sig_buf.");
		return FALSE;
	}

	if (!sig_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "sign: value must be greater than zero for sig_buf_len.");
		return FALSE;
	}

    // fill in parameters for PSS signing if necessary
    switch( mech_type )
    {
		case CKM_SHA1_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA_1;
			pssParams.mgf = CKG_MGF1_SHA1;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA256;
			pssParams.mgf = CKG_MGF1_SHA256;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA384;
			pssParams.mgf = CKG_MGF1_SHA384;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA512;
			pssParams.mgf = CKG_MGF1_SHA512;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA224;
			pssParams.mgf = CKG_MGF1_SHA224;
			break;
		default:
			use_pss = FALSE;
			break;
    }

	// define the HSM signing mechanism
	CK_MECHANISM mech = { mech_type, NULL_PTR, 0 };

    if( use_pss == TRUE )
    {
        pssParams.sLen = salt_len;
        mech.pParameter = &pssParams;
        mech.ulParameterLen = sizeof(pssParams);
    }

	// initialize the HSM signing mechanism
	rv = _p11->C_SignInit(h_session, &mech, h_key);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "sign: PKCS#11 C_SignInit failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// On input, sig_buf_len is size of buffer signatureBuf; on output, it is size of content.
	rv = _p11->C_Sign(h_session, data_buf, data_buf_len, sig_buf, sig_buf_len);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "sign: PKCS#11 C_Sign failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// verify()
//	Verifies signed data using specified verification key and key mechanism (algorithm)
//  and supplied signature.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains error messages
//
//	Inputs:
//		msg_buf_len				--  length of the error message buffer
//		h_session				--	handle of an open session with the HSM
//		data_buf				--	buffer containing data to verify
//		data_buf_len			--	byte length of data buffer
//		h_key					--	handle of key to be used for verifying
//		mech_type  				--  mechanism type of the verification algorithm
//		salt_len				--  optional salt length value (required for PSS signatures)
//		sig_buf					--	buffer to contain signature
//		sig_buf_Len				--	byte length of signature buffer
//
//----------------------------------------------------------------------------------------
int verify(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len, unsigned long h_key,
		   unsigned long mech_type, unsigned long salt_len, unsigned char* sig_buf, unsigned long sig_buf_len)
{
	CK_RV rv = 0;
    CK_RSA_PKCS_PSS_PARAMS pssParams;
    int use_pss = TRUE;

    // fill in parameters for PSS signing if necessary
    switch( mech_type )
    {
		case CKM_SHA1_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA_1;
			pssParams.mgf = CKG_MGF1_SHA1;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA256;
			pssParams.mgf = CKG_MGF1_SHA256;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA384;
			pssParams.mgf = CKG_MGF1_SHA384;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA512;
			pssParams.mgf = CKG_MGF1_SHA512;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			pssParams.hashAlg = CKM_SHA224;
			pssParams.mgf = CKG_MGF1_SHA224;
			break;
		default:
			use_pss = FALSE;
			break;
    }

	// define the HSM signing mechanism
	CK_MECHANISM sigMechanism = { mech_type, NULL_PTR, 0 };

    if( use_pss == TRUE )
    {
		pssParams.sLen = salt_len;
        sigMechanism.pParameter = &pssParams;
        sigMechanism.ulParameterLen = sizeof(pssParams);
    }

	// initialize the HSM mechanism (verification algorithm to be used)
	rv = _p11->C_VerifyInit(h_session, &sigMechanism, h_key);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "verify: PKCS#11 C_VerifyInit failed with return code %lu", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// sign the data using the specific key on the HSM and the initialized signing mechanism
	rv = _p11->C_Verify(h_session, data_buf, data_buf_len, sig_buf, sig_buf_len);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "verify: PKCS#11 C_Verify failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// encrypt()
//	Encrypts supplied clear-text using designated HSM encryption key and mechanism and returns
//  cipher-text.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains error messages
//		encrypted_data_buf		--	buffer to contain encrypted data
//		encrypted_data_buf		--	byte length of supplied buffer; on output, byte
//									length of result in enc_data_buf
//	Inputs:
//		msg_buf_len				--  length of the error message buffer
//		h_session				--	handle of an open session with the HSM
//		data_buf				--	buffer containing data to be encrypted
//		data_buf_len			--	byte length of data to be encrypted
//		h_key					--	handle of encryption key to be used to do encryption operation
//		mech_type				--  algorithm to be used to encrypt the data (e.g. CKM_DES_CBC_PAD, CKM_AES_CBC, etc)
//		iv						--  encryption initialization vector
//		iv_len					--  encryption initialization vector length
//----------------------------------------------------------------------------------------
//
int encrypt(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len,
  		    unsigned long h_key, unsigned long mech_type, unsigned char* iv, unsigned long iv_len,
			unsigned char* encrypted_data_buf, unsigned long* encrypted_data_buf_len)
{
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for data buffer
	if (!data_buf)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: data_buf cannot contain a null pointer.");
		return FALSE;
	}

	//	check for valid data buffer length
	if (!data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: data_buf_len much contain a value 1 or greater.");
		return FALSE;
	}

	//	check for valid key handle
	if (!h_key)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: h_key must contain a value.");
		return FALSE;
	}

	//	null pointer check for encrypted data buffer
	if (!encrypted_data_buf)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: encrypted_data_buffer null pointer unexpected.");
		return FALSE;
	}

	//	check for valid encrypted data buffer length
	if (!encrypted_data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: encrypted_data_buffer_len zero value unexpected.");
		return FALSE;
	}

	// create the encryption mechanism
	CK_MECHANISM mech = { mech_type, iv, iv_len };

	CK_RSA_PKCS_OAEP_PARAMS oaep;
	memset(&oaep, 0, sizeof(oaep));

	// check to see if the mech type is RSA OAEP and if so set the OAEP parameters
	if (mech_type == CKM_RSA_PKCS_OAEP)
	{
		oaep.hashAlg = CKM_SHA_1;		// hard-code to SHA-1 for wide spread support among HSM vendors
		oaep.mgf = CKG_MGF1_SHA1;
		oaep.source = CKZ_DATA_SPECIFIED;
		oaep.pSourceData = 0;
		oaep.ulSourceDataLen = 0;
		// set the oaep parameters to the mechanism
		mech.pParameter = &oaep;
		mech.ulParameterLen = sizeof(oaep);
	}

	// initialize the HSM encryption mechanism
	rv = _p11->C_EncryptInit(h_session, &mech, h_key);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: PKCS#11 C_EncryptInit failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// on input, encrypted_data_buf_len is size of buffer encrypted_data_buf; on output, it is size of content.
	rv = _p11->C_Encrypt(h_session, data_buf, data_buf_len, encrypted_data_buf, encrypted_data_buf_len);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "encrypt: PKCS#11 C_Encrypt failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// decrypt()
//	Decrypts supplied cipher-text using designated HSM encryption key and mechanism and returns
//  clear-text.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains error messages
//		decrypted_data_buf		--	buffer to contain decrypted data
//		decrypted_data_buf_len	--	byte length of supplied buffer; on output, byte
//									length of result in decryptedData
//	Inputs:
//		msg_buf_len				--  length of the error message buffer
//		h_session				--	handle of an open session with the HSM.
//		data_buf				--	buffer containing data to be decrypted.
//		data_buf_len			--	byte length of data to be decrypted.
//		h_decrypt_key			--	handle of key to be used to do decrypt operation
//		mech_type				--  algorithm to be used to decrypt the data (e.g. CKM_DES_CBC_PAD, CKM_AES_CBC, etc)
//		iv						--  initialization vector
//		iv_len					--  initialization vector length
//----------------------------------------------------------------------------------------
//
int decrypt(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned char* data_buf, unsigned long data_buf_len, unsigned long h_key,
		unsigned long mech_type, unsigned char* iv, unsigned long iv_len,
		unsigned char* decrypted_data_buf, unsigned long* decrypted_data_buf_len)
{
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for data buffer
	if (!data_buf)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: data_buf null pointer unexpected.");
		return FALSE;
	}

	//	check for valid data length
	if (!data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: data_buf_len zero value unexpected.");
		return FALSE;
	}

	//	check for key handle
	if (!h_key)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: h_decrypt_key zero value unexpected.");
		return FALSE;
	}

	//	null pointer check for decrypted data buffer
	if (!decrypted_data_buf)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: decrypted_data_buf null pointer unexpected.");
		return FALSE;
	}

	//	check for valid encrypted data buffer length
	if (!decrypted_data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: decrypted_data_buf_len zero value unexpected.");
		return FALSE;
	}

	// create the decryption mechanism
	CK_MECHANISM mech = { mech_type, iv, iv_len };

	CK_RSA_PKCS_OAEP_PARAMS oaep;
	memset(&oaep, 0, sizeof(oaep));

	// check to see if the mech type is RSA OAEP and if so set the OAEP parameters
	if (mech_type == CKM_RSA_PKCS_OAEP)
	{
		oaep.hashAlg = CKM_SHA_1;		// hard-code to SHA-1 for wide spread support among HSM vendors
		oaep.mgf = CKG_MGF1_SHA1;
		oaep.source = CKZ_DATA_SPECIFIED;
		oaep.pSourceData = 0;
		oaep.ulSourceDataLen = 0;
		// set the oaep parameters to the mechanism
		mech.pParameter = &oaep;
		mech.ulParameterLen = sizeof(oaep);
	}

	// initialize the HSM decryption mechanism
	rv = _p11->C_DecryptInit(h_session, &mech, h_key);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: PKCS#11 C_DecryptInit failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// on input, decrypted_data_buf_len is size of buffer decrypted_data_buf; on output, it is size of content.
	rv = _p11->C_Decrypt(h_session, data_buf, data_buf_len, decrypted_data_buf, decrypted_data_buf_len);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "decrypt: PKCS#11 C_Decrypt failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------
// digest()
//	Creates a Digest (Hash) of supplied data using the specific mechanism (hashing algorithm)
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains error messages
//		data_buf				--	buffer to contain digest (hashed) data
//		data_buf_len			--	byte length of supplied buffer; on output, byte
//									length of result in digest_data_buf
//	Inputs:
//		msg_buf_len				--  length of the error message buffer
//		h_session				--	handle of an open session with the HSM.
//		digest_data_buf			--	buffer containing data to be hashed.
//		digest_data_buf_len		--	byte length of data to be hashed.
//		mech_type				--  algorithm to be used to digest the data (e.g. CKM_SHA256, CKM_SHA512, etc)
//----------------------------------------------------------------------------------------
//
int digest(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* data_buf, unsigned long data_buf_len,
		unsigned long mech_type, unsigned char* digest_data_buf, unsigned long* digest_data_buf_len)
{
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "digest: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for data buffer
	if (!data_buf)
	{
		snprintf(msg_buf, msg_buf_len, "digest: data_buf null pointer unexpected.");
		return FALSE;
	}

	//	check for valid data buffer length
	if (!data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "digest: data_buf_len zero value unexpected.");
		return FALSE;
	}

	//	null pointer check for digest data buffer
	if (!digest_data_buf)
	{
		snprintf(msg_buf, msg_buf_len, "digest: digest_data_buf null pointer unexpected.");
		return FALSE;
	}

	//	check for valid digest data buffer length
	if (!digest_data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "digest: digest_data_buf_len zero value unexpected.");
		return FALSE;
	}

	// create the Digestion mechanism
	CK_MECHANISM mech = { mech_type, NULL_PTR, 0 };

	// initialize the HSM digest mechanism
	rv = _p11->C_DigestInit(h_session, &mech);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "digest: PKCS#11 C_DigestInit failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// on input, digest_data_buf_len is size of buffer digest_data_buf; on output, it is size of content.
	rv = _p11->C_Digest(h_session, data_buf, data_buf_len, digest_data_buf, digest_data_buf_len);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "Digest: PKCS#11 C_Digest failed with return code %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}

	// CK_BBOOL pub_private, CK_BBOOL pvt_private, CK_BBOOL sensitive

//----------------------------------------------------------------------------------------
// create_rsa_key_pair()
//	Generates RSA public and private keys on the HSM.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf						-- contains error messages
//		h_pub_key					-- new public key handle
//		h_pvt_key					-- new private key handle
//
//	Inputs:
//		msg_buf_len					-- length of the error message buffer
//		h_session					-- handle of an open session with the HSM.
//		key_size					-- bit length of requested public modulus (2048, 4096, 8192).
//		pub_key_label				-- label for the public key
//		pub_key_label_len			-- length of public key label
//		pvt_key_label				-- label for the private key
//		pvt_key_label_len			-- length of private key label
//		pub_key_id					-- id for the public key
//		pub_key_id_len				-- length of public key id
//		pvt_key_id					-- id for the private key
//		pvt_key_id_len				-- length of private key id
//		mech_type				    -- mechanism type (usually CKM_RSA_X9_31_KEY_PAIR_GEN or CKM_RSA_PKCS_KEY_PAIR_GEN)
// 						  		 	   Note: CKM_RSA_X9_31_KEY_PAIR_GEN is functionally identical to CKM_RSA_PKCS_KEY_PAIR_GEN
//						   			   but provides stronger guarantee of p and q values as defined in X9.31
// 									   Cavium HSMs only support the CKM_RSA_X9_31_KEY_PAIR_GEN mechanism
//		pub_exp						-- byte array containing public exponent value
//      pub_exp_len					-- length of the publicExp byte array
//		token						-- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//		pub_private 				-- 1 to indicate the public key is marked private and can only be accessed after authentication; otherwise 0
//		pvt_private 				-- 1 to indicate the private key is marked private and can only be accessed after authentication; otherwise 0
//		sensitive	    			-- 1 to indicate the private key is sensitive; otherwise 0
//	    modifiable					-- 1 to indicate the keys can be modified; otherwise 0
//		extractable					-- 1 to indicate the private key can be extracted; otherwise 0
//		sign						-- 1 to indicate the private key can sign; otherwise 0
//		verify						-- 1 to indicate the public key can verify; otherwise 0
//		encrypt						-- 1 to indicate the public key can encrypt; otherwise 0
//		decrypt						-- 1 to indicate the private key can decrypt; otherwise 0
//		wrap						-- 1 to indicate the public key can wrap; otherwise 0
//		unwrap						-- 1 to indicate the private key can unwrap; otherwise 0
//		derive						-- 1 to indicate the private key can be used to drive other keys; otherwise 0
//		overwrite					-- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//
//----------------------------------------------------------------------------------------
int create_rsa_key_pair(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long key_size,
		unsigned char* pub_key_label, unsigned long pub_key_label_len, unsigned char* pvt_key_label, unsigned long pvt_key_label_len,
		unsigned char* pub_key_id, unsigned long pub_key_id_len, unsigned char* pvt_key_id, unsigned long pvt_key_id_len,
		unsigned long mech_type, unsigned char* pub_exp, unsigned long pub_exp_len, unsigned long token, unsigned long pub_private, unsigned long pvt_private, unsigned long sensitive,
		unsigned long modifiable, unsigned long extractable, unsigned long sign, unsigned long verify, unsigned long encrypt, unsigned long decrypt,
		unsigned long wrap, unsigned long unwrap, unsigned long derive, unsigned long overwrite, unsigned long* h_pub_key, unsigned long* h_pvt_key)
{
	CK_OBJECT_HANDLE h_pub = 0;
	CK_OBJECT_HANDLE h_pvt = 0;
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for public exponent value
	if (!pub_exp)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pub_exp null pointer unexpected.");
		return FALSE;
	}

	if (pub_exp_len <=0)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pub_exp_len must be greater than 0.");
		return FALSE;
	}

	//	null pointer check for public key label
	if (!pub_key_label)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pub_key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (pub_key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pub_key_label parameter too long.");
		return FALSE;
	}

	// check to make sure the public key label is not empty
	if (pub_key_label_len == 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pub_key_label parameter is empty.");
		return FALSE;
	}

	//	null pointer check for private key label
	if (!pvt_key_label)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pvt_key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the private key label is not too long
	if (pvt_key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pvt_key_label parameter too long.");
		return FALSE;
	}

	// check to make sure the private key label is not empty
	if (pvt_key_label_len == 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: pvt_key_label parameter is empty.");
		return FALSE;
	}

	// make sure that the public key label does not already exist on the HSM
	// it will return a T/F depending on error conditions
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, pub_key_label, pub_key_label_len, &h_pub);
	if (rv == FALSE)
	{
		return FALSE;
	}

	// if the public key label object exists on the HSM then destroy it or report error.
	if (h_pub)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_pub);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: PKCS#11 C_DestroyObject failed.");
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: public key label already exists.");
			return FALSE;
		}
	}

	// make sure that the private key label does not already exist on the HSM
	// it will return a T/F depending on error conditions
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, pvt_key_label, pvt_key_label_len, &h_pvt);
	if (rv == FALSE)
	{
		return FALSE;
	}

	// if the public key label object exists on the HSM then destroy it or report error.
	if (h_pvt)
	{
		if (overwrite)
		{
			// destroy existing private key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_pvt);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: PKCS#11 C_DestroyObject failed.");
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: private key label already exists.");
			return FALSE;
		}
	}

	CK_OBJECT_HANDLE h_new_pub = 0;
	CK_OBJECT_HANDLE h_new_pvt = 0;

	rv = __gen_rsa_key_pair(h_session,
						    key_size,
						    pub_exp,
						    pub_exp_len,
						    pub_key_label,
						    pub_key_label_len,
						    pvt_key_label,
						    pvt_key_label_len,
							pub_key_id,
							pub_key_id_len,
							pvt_key_id,
							pvt_key_id_len,
							mech_type,
						    token,
						    pub_private,
							pvt_private,
							sensitive,
						    modifiable,
						    extractable,
						    sign,
						    verify,
						    encrypt,
						    decrypt,
						    wrap,
						    unwrap,
						    derive,
						    &h_new_pub,
						    &h_new_pvt);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "create_rsa_key_pair: __gen_rsa_key_pair failed with the return value %lu.", rv);
   		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// return the newly created handles
	*h_pub_key = h_new_pub;
	*h_pvt_key = h_new_pvt;

    return TRUE;
}

//----------------------------------------------------------------------------------------
// create_ec_key_pair()
//	Generates EC public and private keys on the HSM.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf						-- contains error messages
//		h_pub_key					-- new public key handle
//		h_pvt_key					-- new private key handle
//
//	Inputs:
//		msg_buf_len					-- length of the error message buffer
//		h_session					-- handle of an open session with the HSM.
//		ec_params					-- byte string containing the ASN.1 DER encoded curve parameter or OID data
//		ec_params_len				-- length of derParams
//		pub_key_label				-- label for the public key
//		pub_key_label_len			-- length of public key label
//		pvt_key_label				-- label for the private key
//		pvt_key_label_len			-- length of private key label
//		pub_key_id					-- id for the public key
//		pub_key_id_len				-- length of public key id
//		pvt_key_id					-- id for the private key
//		pvt_key_id_len				-- length of private key id
//		token						-- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//		pub_private 				-- 1 to indicate the public key is marked private and can only be accessed after authentication; otherwise 0
//		pvt_private 				-- 1 to indicate the private key is marked private and can only be accessed after authentication; otherwise 0
//		sensitive	    			-- 1 to indicate the private key is sensitive; otherwise 0
//	    modifiable					-- 1 to indicate the keys can be modified; otherwise 0
//		extractable					-- 1 to indicate the private key can be extracted; otherwise 0
//		sign						-- 1 to indicate the private key can sign; otherwise 0
//		verify						-- 1 to indicate the public key can verify; otherwise 0
//		encrypt						-- 1 to indicate the public key can encrypt; otherwise 0
//		decrypt						-- 1 to indicate the private key can decrypt; otherwise 0
//		wrap						-- 1 to indicate the public key can wrap; otherwise 0
//		unwrap						-- 1 to indicate the private key can unwrap; otherwise 0
//		derive						-- 1 to indicate the private key can be used to drive other keys; otherwise 0
//		overwrite					-- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//
//----------------------------------------------------------------------------------------
int create_ec_key_pair(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned char* ec_params, unsigned long ec_params_len,
		unsigned char* pub_key_label, unsigned long pub_key_label_len, unsigned char* pvt_key_label, unsigned long pvt_key_label_len,
		unsigned char* pub_key_id, unsigned long pub_key_id_len, unsigned char* pvt_key_id, unsigned long pvt_key_id_len,
		unsigned long token, unsigned long pub_private, unsigned long pvt_private, unsigned long sensitive,
		unsigned long modifiable, unsigned long extractable, unsigned long sign, unsigned long verify,
		unsigned long encrypt, unsigned long decrypt, unsigned long wrap, unsigned long unwrap, unsigned long derive,
		unsigned long overwrite, unsigned long* h_pub_key, unsigned long* h_pvt_key)
{
	CK_OBJECT_HANDLE h_pub = 0;
	CK_OBJECT_HANDLE h_pvt = 0;
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for DER encoded ASN.1 ECC curve parameters
	if (!ec_params)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: ec_params null pointer unexpected.");
		return FALSE;
	}

	//	null pointer check for DER encoded ASN.1 ECC curve parameters
	if (!ec_params_len)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: ec_params_len must be greater than zero.");
		return FALSE;
	}

	//	null pointer check for public key label
	if (!pub_key_label)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: pub_key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (pub_key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: pub_key_label parameter too long.");
		return FALSE;
	}

	// check to make sure the public key label is not empty
	if (pub_key_label_len == 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: pub_key_label parameter is empty.");
		return FALSE;
	}

	//	null pointer check for private key label
	if (!pvt_key_label)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: pvt_key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the private key label is not too long
	if (pvt_key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: pvt_key_label parameter too long.");
		return FALSE;
	}

	// check to make sure the private key label is not empty
	if (pvt_key_label_len == 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: pvt_key_label parameter is empty.");
		return FALSE;
	}

	// make sure that the public key label does not already exist on the HSM
	// it will return a T/F depending on error conditions
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, pub_key_label, pub_key_label_len, &h_pub);
	if (rv == FALSE)
	{
		return FALSE;
	}

	// if the public key label object exists on the HSM then destroy it or report error.
	if (h_pub)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_pub);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: PKCS#11 C_DestroyObject failed.");
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: public key label already exists.");
			return FALSE;
		}
	}

	// make sure that the private key label does not already exist on the HSM
	// it will return a T/F depending on error conditions
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, pvt_key_label, pvt_key_label_len, &h_pvt);
	if (rv == FALSE)
	{
		return FALSE;
	}

	// if the public key label object exists on the HSM then destroy it or report error.
	if (h_pvt)
	{
		if (overwrite)
		{
			// destroy existing private key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_pvt);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: PKCS#11 C_DestroyObject failed for private key label.");
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: private key label already exists.");
			return FALSE;
		}
	}

	CK_OBJECT_HANDLE h_new_pub = 0;
	CK_OBJECT_HANDLE h_new_pvt = 0;

	// setup templates and create the EC key pair on the HSM
	rv = __gen_ec_key_pair(h_session,
						   ec_params,
						   ec_params_len,
						   pub_key_label,
						   pub_key_label_len,
						   pvt_key_label,
						   pvt_key_label_len,
						   pub_key_id,
						   pub_key_id_len,
						   pvt_key_id,
						   pvt_key_id_len,
						   token,
						   pub_private,
						   pvt_private,
						   sensitive,
						   modifiable,
						   extractable,
						   sign,
						   verify,
						   encrypt,
						   decrypt,
						   wrap,
						   unwrap,
						   derive,
						   &h_new_pub,
						   &h_new_pvt);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "create_ec_key_pair: __gen_ec_key_pair failed with the return value %lu.", rv);
   		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// return the newly created handles
	*h_pub_key = h_new_pub;
	*h_pvt_key = h_new_pvt;

	return TRUE;
}


//----------------------------------------------------------------------------------------
// create_secret_key()
//	Generates a new secret symmetric key directly on the HSM.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf						-- contains error messages
//		h_secret_key				-- newly created secret key handle
//
//	Inputs:
//		msg_buf_len					-- length of the error message buffer
//		h_session					-- handle of an open session with the HSM.
//		key_label					-- label for the key
//		key_label_len				-- length of key label
//		key_id						-- id for the key
//		key_id_len					-- length of key id
//		key_size					-- size of the key in bits
//		mech_type 					-- type of key mechanism to create
//		token						-- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//		private_					-- 1 to indicate the keys are private to the HSM and require an auth session; otherwise 0
//		sensitive	    			-- 1 to indicate the private key is sensitive; otherwise 0
//	    modifiable					-- 1 to indicate the keys can be modified; otherwise 0
//		extractable					-- 1 to indicate the private key can be extracted; otherwise 0
//		sign						-- 1 to indicate the private key can sign; otherwise 0
//		verify						-- 1 to indicate the public key can verify; otherwise 0
//		encrypt						-- 1 to indicate the public key can encrypt; otherwise 0
//		decrypt						-- 1 to indicate the private key can decrypt; otherwise 0
//		wrap						-- 1 to indicate the public key can wrap; otherwise 0
//		unwrap						-- 1 to indicate the private key can unwrap; otherwise 0
//		derive						-- 1 to indicate the private key can be used to drive other keys; otherwise 0
//		overwrite					-- 1 to indicate the an existing key pair with the same label name can be overwriten; otherwise 0
//
//----------------------------------------------------------------------------------------
int create_secret_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
		unsigned long mech_type, unsigned long key_size,
		unsigned long token, unsigned long private_, unsigned long sensitive, unsigned long modifiable,
		unsigned long extractable, unsigned long sign, unsigned long verify, unsigned long encrypt, unsigned long decrypt,
		unsigned long wrap, unsigned long unwrap, unsigned long derive, unsigned long overwrite,
		unsigned long* h_secret_key)
{
	CK_OBJECT_HANDLE h_key = 0;
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for key label
	if (!key_label)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the key label is not too long
	if (key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: key_label parameter too long.");
		return FALSE;
	}

	// check to make sure the key label is not empty
	if (key_label_len == 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: key_label parameter is empty.");
		return FALSE;
	}

	// key type check
	if (key_size < 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: key_size invalid.");
		return FALSE;
	}

	// key mech type check
	if (mech_type < 0)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: mech_type invalid.");
		return FALSE;
	}

	// make sure that the key label does not already exist on the HSM
	// it will return a T/F depending on error conditions
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, key_label, key_label_len, &h_key);
	if (rv == FALSE)
	{
		return FALSE;
	}

	// if the public key label object exists on the HSM then destroy it or report error.
	if (h_key)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_key);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "create_secret_key: PKCS#11 C_DestroyObject failed for secret key label.");
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "create_secret_key: secret key label already exists.");
			return FALSE;
		}
	}

	CK_OBJECT_HANDLE h_new_key = 0;

	// setup templates and create the symmetrical key on the HSM
	rv = __gen_secret_key(h_session,
						  key_label,
						  key_label_len,
						  key_id,
						  key_id_len,
						  mech_type,
						  key_size,
						  token,
						  private_,
						  sensitive,
						  modifiable,
						  extractable,
						  sign,
						  verify,
						  encrypt,
						  decrypt,
						  wrap,
						  unwrap,
						  derive,
						  &h_new_key);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "create_secret_key: __gen_secret_key failed with the return value %lu.", rv);
   		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// return the newly created handle
	*h_secret_key = h_new_key;

	return TRUE;
}

//----------------------------------------------------------------------------------------
// get_slot_count()
//	Uses C_GetSlotList() to count slots.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf		-- contains any error messages
//		slot_count  -- number of slots on the machine
//
//	Inputs:
//		msg_buf_len	--	byte length of provided buffer
//
//----------------------------------------------------------------------------------------
int get_slot_count(char* msg_buf, unsigned long msg_buf_len, unsigned long* slot_count)
{
	CK_ULONG cnt = 0;
	CK_RV rv = 0;
	CK_BBOOL token_present = FALSE;
	CK_SLOT_ID *slot_list = NULL_PTR;

	// Get the qty of slots including empty ones.
	rv = _p11->C_GetSlotList(token_present, slot_list, &cnt);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_slot_count: Unexpected return value %lu from PKCS#11 C_GetSlotList() while trying to count slots.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*slot_count = cnt;

	return TRUE;
}


//----------------------------------------------------------------------------------------
// get_token_count()
//	Returns the number of tokens on the machine.
//
//	Operation:
//		Uses C_GetSlotList() to count slots that have tokens present.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf		-- contains error messages
//		token_count	-- number of tokens on the machine
//
//	Inputs:
//		msg_buf_len	--	byte length of provided buffer
//
//----------------------------------------------------------------------------------------
int get_token_count(char* msg_buf, unsigned long msg_buf_len, unsigned long* token_count)
{
	CK_ULONG cnt = 0;
	CK_RV rv = 0;
	CK_BBOOL token_present = TRUE;
	CK_SLOT_ID *slot_list = NULL_PTR;

	// Count the installed tokens.
	rv = _p11->C_GetSlotList(token_present, slot_list, &cnt);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_token_count: Unexpected return value %lu from PKCS#11 C_GetSlotList() while trying to count tokens.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*token_count = cnt;

	return TRUE;
}


//----------------------------------------------------------------------------------------
// get_slot_info()
//	Compiles and returns information about all the slots on the machine that have a
//  token present.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			-- contains error messages
//		data_buf		--	to contain info with newline separating records and commas
//							separating fields.
//							Each record has:
//								* slot ID
//								* token label
//								* manufacturer ID
//								* model
//								* serial number
//								* count of open sessions
//	 	data_buf_len	-- modifies to the size allocated
//		slot_count		-- number of slots on the machine
//
//	Inputs:
//		msg_buf_len		--	byte length of provided buffer
//		data_buf_len	--	byte length of provided buffer
//
//----------------------------------------------------------------------------------------
int get_slot_info(char* msg_buf, unsigned long msg_buf_len, char* data_buf, unsigned long* data_buf_len, unsigned long* token_count)
{
	CK_RV rv = 0;
	CK_ULONG slot_cnt_1 = 0;
	CK_ULONG MAX_RECORD_SIZE_BYTES = 122;
	CK_SLOT_ID slot_list[MAX_SLOT_COUNT];

	// get the number of slots with a token present
	rv = _p11->C_GetSlotList(TRUE, NULL_PTR, &slot_cnt_1);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_slot_info: Unexpected return value %lu from PKCS#11 C_GetSlotList() while trying to get slot count.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// if the number of slots is less than 1 then exit
	if (slot_cnt_1 < 1)
	{
		*token_count = slot_cnt_1;
		*data_buf_len = 0;
		return TRUE;
	}

	// call get slot list again and this time fill up the list data structure
	CK_ULONG slot_cnt_2 = MAX_SLOT_COUNT;
	rv = _p11->C_GetSlotList(TRUE, slot_list, &slot_cnt_2);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_slot_info: Unexpected return value %lu from PKCS#11 C_GetSlotList() while trying to fill slot info data structure.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// if the number of slots is less than 1 then exit
	if (slot_cnt_2 < 1)
	{
		*token_count = slot_cnt_2;
		*data_buf_len = 0;
		return TRUE;
	}

	// determine if the buffer is large enough
	if (MAX_RECORD_SIZE_BYTES * slot_cnt_2 + 1 > *data_buf_len)
	{
		snprintf(msg_buf, msg_buf_len, "get_slot_info: data_buf_len %lu is too small", *data_buf_len);
		return FALSE;
	}

	// return an error if the number of slot exceeds what the library supports
	if (slot_cnt_2 > MAX_SLOT_COUNT)
	{
		snprintf(msg_buf, msg_buf_len, "get_slot_info: more slots detected than supported by library");
		return FALSE;
	}

	CK_TOKEN_INFO token_info;
	long offset = 0;

	for (CK_ULONG i = 0; i < slot_cnt_2; i++)
	{
		rv = _p11->C_GetTokenInfo(slot_list[i], &token_info);
		if (rv != CKR_OK)
		{
			snprintf(msg_buf, msg_buf_len, "get_slot_info: Unexpected return value %lu from PKCS#11 C_GetTokenInfo() while trying to get token data.", rv);
			__append_return_code(rv, msg_buf, msg_buf_len);
			return FALSE;
		}

		// SafeNet puts blanks in for the string instead of null characters so before
		// we print out the strings we need to null them
		CK_CHAR label[33];
		CK_CHAR manufId[33];
		CK_CHAR model[17];

		__copy_fixed_padded_str_to_null_str(label, token_info.label, 32);
		__copy_fixed_padded_str_to_null_str(manufId, token_info.manufacturerID, 32);
		__copy_fixed_padded_str_to_null_str(model, token_info.model, 16);

		// null terminate the serial number since copy fixed padded string function
		// does not work for this particular value
		token_info.serialNumber[15] = '\0';

		// -----------------------------------
		// slotId[10]|label[32]|mfr[32]|model[6]|serial[16]|slot_count[10]<lf>
		//	10 + 1 + 32 + 1 + 32 + 1 + 16 + 1 + 16 + 1 + 10 + 1 = 122 bytes required per record
		// -------------------------------------

		// update the data buffer with the token information
		offset += snprintf(data_buf+offset, *data_buf_len - offset,
												"%lu|%s|%s|%s|%s|%lu|%u.%u|%u.%u\n",
												slot_list[i],
												label,
												manufId,
												model,
												token_info.serialNumber,
												token_info.ulSessionCount,
												token_info.hardwareVersion.major,
												token_info.hardwareVersion.minor,
												token_info.firmwareVersion.major,
												token_info.firmwareVersion.minor);

	}

	// remove the last LF
	offset--;

	// update the number of slots detected
	*token_count = slot_cnt_2;
	// update the data buffer length return value
	*data_buf_len = offset;
	// return
	return TRUE;
}


//----------------------------------------------------------------------------------------
// get_attribute_value()
//	Gets the attribute value of an object on the HSM.
//
//	Operation:
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains any error messages
//		attribute_value			--	contains array of bytes containing attribute value
//		attribute_value_len		--  attribute value length
//
//	Inputs:
//		msg_buf_len				--	byte length of provided error message buffer
//		h_session				--  session handle
//		h_object				--  handle to the object that is to be queried for attribute value
//		attribute_type			--  valid attribute type such as CKA_PRIME_1, CKA_PRIME_2, etc
//----------------------------------------------------------------------------------------
int get_attribute_value(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_object,
		unsigned long attribute_type, unsigned char *attribute_value, unsigned long* attribute_value_len)
{

	// setup the attribute template
	CK_ATTRIBUTE attrib_template[] = { {attribute_type, NULL_PTR, 0} };

	CK_RV rv = 0;

	//  call the first time with a null pointer for the second field in the attribute template
	//	in order to get the length of the data we need to extract
	//  this is a really weird design but common in PKCS due to the C style API calls
	rv = _p11->C_GetAttributeValue(h_session, h_object, attrib_template, 1);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_attribute_value: PKCS#11 C_GetAttributeValue() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// test to make sure the buffer passed in is not too small
	if (*attribute_value_len < attrib_template[0].ulValueLen)
	{
		snprintf(msg_buf, msg_buf_len, "get_attribute_value: attributeValue buffer is too small to return attribute data return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// allocate the memory so we can call C_GetAttributeValue again and this time
	// actually get the data in a buffer of the correct size
	CK_BYTE_PTR p_data = (CK_BYTE_PTR) malloc(attrib_template[0].ulValueLen);

	// set the attribute template to point to our newly created data value buffer
	attrib_template[0].pValue = p_data;

	// call C_GetAttributeValue again and this time actually retrieve our data value
	rv = _p11->C_GetAttributeValue(h_session, h_object, attrib_template, 1);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_attribute_value: PKCS#11 C_GetAttributeValue() executed with errors when retrieving attribute data; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		// free the memory we allocated
		free(p_data);
		return FALSE;
	}

	// copy the data over to the parameter passed in so we can return that back to the caller
	memcpy(attribute_value, p_data, attrib_template[0].ulValueLen);

	// return the length of the data back to the caller
	*attribute_value_len = attrib_template[0].ulValueLen;

	// free the memory we allocated
	free(p_data);

	return TRUE;
}


//----------------------------------------------------------------------------------------
// set_attribute_value()
//	Sets an attribute value for an object on the HSM (if allowable).
//
//	Operation:
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains any error messages
//		attribute_value			--	contains array of bytes containing attribute value
//		attribute_value_length	--  attribute value length
//
//	Inputs:
//		msg_buf_len				--	byte length of provided error message buffer
//		h_session				--  session handle
//		h_object				--  handle to the object to update the attribute
//		attribute_type			--  valid attribute type such as CKA_PRIME_1, CKA_PRIME_2, etc
//----------------------------------------------------------------------------------------
int set_attribute_value(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_object,
		unsigned long attribute_type, unsigned char *attribute_value, unsigned long attribute_value_len)
{

	// setup the attribute template
	CK_ATTRIBUTE attrib_template[] = { {attribute_type, attribute_value, attribute_value_len} };

	CK_ATTRIBUTE_PTR p_attrib_template = attrib_template;

	//  call the first time with a null pointer for the second field in the attribute template
	CK_RV rv = _p11->C_SetAttributeValue(h_session, h_object, p_attrib_template, 1);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "set_attribute_value: PKCS#11 C_SetAttributeValue() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}



//----------------------------------------------------------------------------------------
// generate_random()
//	Generate and return random byte string.  Random data is generated using the HSM
//	PRNG.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains any error messages
//		random_data				--	contains array of bytes to stuff random numbers into
//		random_data_len			--  length of random data array
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer
//		h_session		--  session handle
//----------------------------------------------------------------------------------------
int generate_random(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* random_data, unsigned long random_data_len)
{
	CK_RV rv = CKR_OK;

	rv = _p11->C_GenerateRandom(h_session, random_data, random_data_len);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "generate_random: PKCS#11 C_GenerateRandom() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}


//----------------------------------------------------------------------------------------
// seed_random()
//	See the HSM PRNG with a user supplied value.
//
//	Operation:
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf					--	contains any error messages
//		seed_data				--	contains array of bytes to stuff random numbers into
//		seed_data_len			--  length of random data array
//
//	Inputs:
//		msg_buf_len				--	byte length of provided error message buffer
//		h_session				--  session handle
//----------------------------------------------------------------------------------------
int seed_random(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned char* seed_data, unsigned long seed_data_len)
{
	CK_RV rv = CKR_OK;

	rv = _p11->C_SeedRandom(h_session, seed_data, seed_data_len);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "seed_random: PKCS#11 C_SeedRandom() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}


//----------------------------------------------------------------------------------------
// destroy_object()
//	Destroys an object on the HSM.  The operation is not reversible and is destructive.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains any error messages
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer
//		h_session		--  session handle
//		h_object		--  handle of object to destroy
//
//----------------------------------------------------------------------------------------
int destroy_object(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_object)
{
	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "destroy_object: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for object handle
	if (!h_object)
	{
		snprintf(msg_buf, msg_buf_len, "destroy_object: hObject null pointer unexpected.");
		return FALSE;
	}

	//  destory the object
	CK_RV rv = _p11->C_DestroyObject(h_session, h_object);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "destroy_object: PKCS#11 C_DestroyObject() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	return TRUE;
}


//----------------------------------------------------------------------------------------
// import_data_object()
//	Imports a binary data object on the HSM.  Data value is supplied as a parameter.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains any error messages
//
//	Inputs:
//		msg_buf_len		-- byte length of provided error message buffer
//		h_session		-- session handle
//		data_label		-- label of the data object on the HSM
//		data_label_len	-- length of data object label
//		data_id			-- id of the data object on the HSM
//		data_id_len		-- length of data object id
//		value			-- binary array containing the data in clear
//		value_len		-- length of the data value array
//		token			-- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//		overwrite		-- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//
//	Outputs:
//		h_object			-- object handle
//
//----------------------------------------------------------------------------------------
int import_data_object(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned char* data_label, unsigned long data_label_len, unsigned char* data_id, unsigned long data_id_len,
		unsigned char* value, unsigned long value_len, unsigned long token, unsigned long overwrite, unsigned long* h_object)
{
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "import_data_object: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for data label
	if (!data_label)
	{
		snprintf(msg_buf, msg_buf_len, "import_data_object: data_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (data_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "import_data_object: data_label parameter too long.");
		return FALSE;
	}

	// make sure that the key label does not already exist on the HSM
	CK_OBJECT_HANDLE h_test = 0;
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, data_label, data_label_len, &h_test);
	if (rv == FALSE)
	{
		snprintf(msg_buf, msg_buf_len, "import_data_object: get_object_handle() failed.");
		return FALSE;
	}

	if (h_test)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_test);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "import_data_object: PKCS#11 C_DestroyObject failed for object label '%s' with the return value %lu.", data_label, rv);
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "import_data_object: object label '%s' already exists.", data_label);
			return FALSE;
		}
	}

	CK_OBJECT_HANDLE h_data;
	CK_BBOOL bToken = token;
	CK_OBJECT_CLASS data_class = CKO_DATA;

	CK_ATTRIBUTE dataTemplate[] = {
	  {CKA_CLASS, 	&data_class, 	sizeof(data_class)},
	  {CKA_TOKEN, 	&bToken, 		sizeof(bToken)},
	  {CKA_LABEL, 	data_label, 	data_label_len},
	  {CKA_ID, 	  	data_id, 		data_id_len},
	  {CKA_VALUE, 	value, 			value_len}
	};

	rv = _p11->C_CreateObject(h_session, dataTemplate, 4, &h_data);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "import_data_object: PKCS#11 C_CreateObject() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*h_object = h_data;

	return TRUE;
}

//----------------------------------------------------------------------------------------
// import_rsa_public_key()
//	Imports clear-text RSA public key data object on the HSM.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf				-- contains any error messages
//		h_pub_key 			-- public key object handle
//
//	Inputs:
//		msg_buf_len			-- byte length of provided error message buffer
//		h_session			-- session handle
//		key_label	  		-- label of the RSA public key object on the HSM
//		key_label_len		-- public key label length
//		key_id				-- id for the public key
//		key_id_len			-- length of public key id
//		exp					-- binary array containing the RSA key public exponent
//		exp_len				-- length of the public exponent array
//		mod					-- binary array containing the RSA key public modulus
//		mod_len				-- length of the public modulus array
//		token				-- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//		private_			-- 1 to indicate the keys are private to the HSM and require an authenticated session; otherwise 0
//	    modifiable			-- 1 to indicate the keys can be modified; otherwise 0
//		verify				-- 1 to indicate the public key can verify; otherwise 0
//		encrypt				-- 1 to indicate the public key can encrypt; otherwise 0
//		wrap				-- 1 to indicate the public key can wrap; otherwise 0
//		overwrite			-- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//----------------------------------------------------------------------------------------
int import_rsa_public_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
		unsigned char* exp, unsigned long exp_len, unsigned char* mod, unsigned long mod_len,
		unsigned long token, unsigned long _private, unsigned long modifiable, unsigned long verify, unsigned long encrypt, unsigned long wrap, unsigned long overwrite, unsigned long* h_pub_key)
{
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for key label
	if (!key_label)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: key_label parameter too long.");
		return FALSE;
	}

	//	null pointer check for public exponent
	if (!exp)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: exp null pointer unexpected.");
		return FALSE;
	}

	//	null pointer check for public modulus
	if (!mod)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: mod null pointer unexpected.");
		return FALSE;
	}

	// make sure that the key label does not already exist on the HSM
	CK_OBJECT_HANDLE h_test = 0;
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, key_label, key_label_len, &h_test);
	if (rv == FALSE)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: get_object_handle() failed.");
		return FALSE;
	}

	if (h_test)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_test);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: PKCS#11 C_DestroyObject failed for object label '%s' with the return value %lu.", key_label, rv);
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: object label '%s' already exists.", key_label);
			return FALSE;
		}
	}

	CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE rsa_type = CKK_RSA;
	CK_BBOOL b_token = token;
	CK_BBOOL b_private = _private;
	CK_BBOOL b_modifiable = modifiable;
	CK_BBOOL b_encrypt = encrypt;
	CK_BBOOL b_verify = verify;
	CK_BBOOL b_wrap = wrap;

	CK_ATTRIBUTE pub_template[] = {
	  {CKA_CLASS, &pub_class, sizeof(pub_class)},
	  {CKA_KEY_TYPE, &rsa_type, sizeof(rsa_type)},
	  {CKA_TOKEN, &b_token, sizeof(b_token)},
	  {CKA_PRIVATE, &b_private, sizeof(b_private)},
	  {CKA_MODIFIABLE, &b_modifiable, sizeof(b_modifiable)},
	  {CKA_ENCRYPT, &b_encrypt, sizeof(b_encrypt)},
	  {CKA_VERIFY, &b_verify, sizeof(b_verify)},
	  {CKA_WRAP, &b_wrap, sizeof(b_wrap)},
	  {CKA_MODULUS, mod, mod_len},
	  {CKA_PUBLIC_EXPONENT, exp, exp_len},
	  {CKA_ID, key_id, key_id_len},
	  {CKA_LABEL, key_label, key_label_len}
	};

	CK_OBJECT_HANDLE h_pub;
	CK_ATTRIBUTE* p_attrib = pub_template;
	CK_ULONG pub_template_len = DIM(pub_template);

	rv = _p11->C_CreateObject(h_session, p_attrib, pub_template_len, &h_pub);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "import_rsa_public_key: PKCS#11 C_CreateObject() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*h_pub_key = h_pub;

	return TRUE;
}

//----------------------------------------------------------------------------------------
// import_ec_public_key()
//	Imports clear-text EC public key data object on the HSM.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf				-- contains any error messages
//		h_pub_key 			-- public key object handle
//
//	Inputs:
//		msg_buf_len			-- byte length of provided error message buffer
//		h_session			-- session handle
//		key_label	  		-- label of the EC public key object on the HSM
//		key_label_len		-- public key label length
//		key_id				-- id for the public key
//		key_id_len			-- length of public key id
//		ec_params			-- binary array containing the EC parameters curve definition or OID
//		ec_params_len		-- length of the EC parameters curve definition or OID
//		ec_point			-- binary array containing the unique EC point
//		ec_point_len		-- length of the EC point definition array
//		token				-- 1 to indicate the keys exist on the HSM token; otherwise 0 to indicate keys exist for life of session
//		private_			-- 1 to indicate the keys are private to the HSM and require an authenticated session; otherwise 0
//	    modifiable			-- 1 to indicate the keys can be modified; otherwise 0
//		verify				-- 1 to indicate the public key can verify; otherwise 0
//		encrypt				-- 1 to indicate the public key can encrypt; otherwise 0
//		wrap				-- 1 to indicate the public key can wrap; otherwise 0
//		overwrite			-- 1 to indicate the an existing key pair with the same label name can be overwritten; otherwise 0
//----------------------------------------------------------------------------------------
int import_ec_public_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
		unsigned char* ec_params, unsigned long ec_params_len, unsigned char* ec_point, unsigned long ec_point_len,
		unsigned long token, unsigned long _private, unsigned long modifiable, unsigned long verify, unsigned long encrypt, unsigned long wrap, unsigned long overwrite, unsigned long* h_pub_key)
{
	CK_RV rv = 0;

	//	null pointer check for session handle
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for key label
	if (!key_label)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: key_label null pointer unexpected.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: key_label parameter too long.");
		return FALSE;
	}

	//	null pointer check for EC curve parameters
	if (!ec_params)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: ec_params null pointer unexpected.");
		return FALSE;
	}

	//	null pointer check for EC point
	if (!ec_point)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: ec_point null pointer unexpected.");
		return FALSE;
	}

	// make sure that the key label does not already exist on the HSM
	CK_OBJECT_HANDLE h_test = 0;
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, key_label, key_label_len, &h_test);
	if (rv == FALSE)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: get_object_handle() failed.");
		return FALSE;
	}

	if (h_test)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_test);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "import_ec_public_key: PKCS#11 C_DestroyObject failed for object label '%s' with the return value %lu.", key_label, rv);
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "import_ec_public_key: object label '%s' already exists.", key_label);
			return FALSE;
		}
	}

	CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE ec_type = CKK_EC;
	CK_BBOOL b_token = token;
	CK_BBOOL b_private = _private;
	CK_BBOOL b_modifiable = modifiable;
	CK_BBOOL b_encrypt = encrypt;
	CK_BBOOL b_verify = verify;
	CK_BBOOL b_wrap = wrap;

	CK_ATTRIBUTE pub_template[] = {
	  {CKA_CLASS, &pub_class, sizeof(pub_class)},
	  {CKA_KEY_TYPE, &ec_type, sizeof(ec_type)},
	  {CKA_TOKEN, &b_token, sizeof(b_token)},
	  {CKA_PRIVATE, &b_private, sizeof(b_private)},
	  {CKA_MODIFIABLE, &b_modifiable, sizeof(b_modifiable)},
	  {CKA_ENCRYPT, &b_encrypt, sizeof(b_encrypt)},
	  {CKA_VERIFY, &b_verify, sizeof(b_verify)},
	  {CKA_WRAP, &b_wrap, sizeof(b_wrap)},
	  {CKA_EC_PARAMS, ec_params, ec_params_len},
	  {CKA_EC_POINT, ec_point, ec_point_len},
	  {CKA_ID, key_id, key_id_len},
	  {CKA_LABEL, key_label, key_label_len}
	};

	CK_OBJECT_HANDLE h_pub;
	CK_ATTRIBUTE* p_attrib = pub_template;
	CK_ULONG pub_template_len = DIM(pub_template);

	rv = _p11->C_CreateObject(h_session, p_attrib, pub_template_len, &h_pub);

	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "import_ec_public_key: PKCS#11 C_CreateObject() executed with errors; return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*h_pub_key = h_pub;

	return TRUE;
}


//----------------------------------------------------------------------------------------
// wrap_key()
//	Wraps a key off the HSM using a designated symmetric or asymmetric wrapping key.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains any error messages
//		key_buf			--  binary array containing the wrapped (encrypted) key
//		key_buf_len		--  length of the keyBuffer
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer
//		h_session		--  session handle
//		key_label		--  label of the target key to wrap off the HSM
//		h_wrap_key		--  handle to the wrapping key on the HSM to use
//		iv			    --  optional IV value to use with the wrapping key (can be null)
//		iv_len			--  optional IV value length (can be 0)
//		mech_type		--  wrapping key mechanism to use (3DES-CBC, AES-128-CBC, etc)
//
//----------------------------------------------------------------------------------------
int wrap_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session, unsigned long h_key,
		unsigned long h_wrap_key, unsigned char* iv, unsigned long iv_len, unsigned long mech_type,
		unsigned char *key_buf, unsigned long* key_buf_len)
{
	//	value check
	if (h_session <= 0)
	{
		snprintf(msg_buf, msg_buf_len, "wrap_key: h_session value must be greater than zero.");
		return FALSE;
	}

	// value check
	if (h_key <= 0)
	{
		snprintf(msg_buf, msg_buf_len, "wrap_key: h_key value must be greater than zero..");
		return FALSE;
	}

	// value check
	if (h_wrap_key <=0)
	{
		snprintf(msg_buf, msg_buf_len, "wrap_key: h_wrap_key value must be greater than zero.");
		return FALSE;
	}

	// value check
	if (mech_type <=0)
	{
		snprintf(msg_buf, msg_buf_len, "wrap_key: mech_type value must be greater than zero.");
		return FALSE;
	}

	// value check
	if (!key_buf)
	{
		snprintf(msg_buf, msg_buf_len, "wrap_key: key_buf cannot be null.");
		return FALSE;
	}

	// value check
	if (key_buf_len <=0)
	{
		snprintf(msg_buf, msg_buf_len, "wrap_key: key_buf_len value must be greater than zero.");
		return FALSE;
	}

	// wrap the private key and get back the wrapped key length and data in the keyBuffer field
	CK_RV rv = __wrap_key(h_session, key_buf, key_buf_len, h_wrap_key, h_key, mech_type, iv, iv_len);

	// evaluate return code
	if (rv != CKR_OK)
    {
		snprintf(msg_buf, msg_buf_len, "wrap_key: __wrap_key() failed to wrap target key; return value %lu", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// returns wrapped key in the keyBuffer byte array
	return TRUE;
}


//----------------------------------------------------------------------------------------
// unwrap_private_key()
//	Unwraps a private asymmetric key onto the HSM using a designated symmetric or asymmetric wrapping key.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains any error messages
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer
//		h_session		--  session handle
//		h_wrap_key		--  handle to the wrapping key on the HSM to use
//		iv			    --  optional IV value to use with the wrapping key (can be null)
//		iv_len			--  optional IV value length (can be 0)
//		mech_type		--  wrapping key mechanism to use (3DES-CBC, AES-128-CBC, etc)
//		key_label		--  key label of new private key
//		key_label_len	--  key label length
//		key_id			--  key id of new private key
//		key_id_len		--  key id length
//		key_buf		    --  wrapped private key bytes
//		key_buf_len		--  length of the wrapped private key bytes
//		key_type		--	type of private key (DES, DES2, DES3, AES, etc)
//		token			--	1 to indicate the private key exists on the token and not the session; otherwise 0
//		private_		--	1 to indicate the private key is private and can only be accessed after authentication; otherwise 0
//		sensitive	    --  1 to indicate the private key is sensitive; otherwise 0
//		modifiable		--	1 to indicate the private key can be modified; otherwise 0
//		extractable		--	1 to indicate the private key can be extracted; otherwise 0
//		sign			--	1 to indicate the private key can sign; otherwise 0
//		decrypt			--	1 to indicate the private key can decrypt; otherwise 0
//		unwrap			--	1 to indicate the private key can unwrap; otherwise 0
//		overwrite		--  1 to indicate the existing private key pair with the same label name can be overwritten; otherwise 0
//		derive			--	1 to indicate the private key can be used to derive other keys; otherwise 0
//
//	Outputs:
//		h_pvt_key		-- object handle
//----------------------------------------------------------------------------------------
int unwrap_private_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned long h_wrap_key, unsigned char* iv, unsigned long iv_len, unsigned long mech_type,
		unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
		unsigned char* key_buf, unsigned long key_buf_len, unsigned long key_type,
		unsigned long token, unsigned long private_, unsigned long sensitive, unsigned long modifiable, unsigned long extractable,
		unsigned long sign, unsigned long decrypt, unsigned long unwrap, unsigned long derive, unsigned long overwrite,
		unsigned long* h_pvt_key)
{
	CK_RV rv;

	//	null pointer check for private key info buffer length
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for public key label
	if (!key_label)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: key_label null pointer unexpected.");
		return FALSE;
	}

	//	check wrapping key handle
	if (h_wrap_key < 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: h_wrap_key invalid value.");
		return FALSE;
	}

	//	check key buffer
	if (!key_buf)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: key_buf invalid value.");
		return FALSE;
	}

	//	check key buffer length
	if (key_buf_len <= 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: key_buf_len invalid value.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: key_label parameter too long.");
		return FALSE;
	}

	// key type check
	if (key_type < 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: key_type invalid.");
		return FALSE;
	}

	// make sure that the key label does not already exist on the HSM
	CK_OBJECT_HANDLE h_test = 0;
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, key_label, key_label_len, &h_test);
	if (rv == FALSE)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: get_object_handle failed.");
		return FALSE;
	}

	if (h_test)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_test);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "unwrap_private_key: PKCS#11 C_DestroyObject failed for private key label '%s' with the return value %lu.", key_label, rv);
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "unwrap_private_key: private key label '%s' already exists.", key_label);
			return FALSE;
		}
	}

	CK_OBJECT_HANDLE h_new_key = 0;

	rv = __unwrap_private_key(h_session,
							  h_wrap_key,
							  iv,
							  iv_len,
							  mech_type,
							  key_label,
							  key_label_len,
							  key_id,
							  key_id_len,
							  key_buf,
							  key_buf_len,
							  key_type,
							  token,
							  private_,
							  sensitive,
							  modifiable,
							  extractable,
							  sign,
							  decrypt,
							  unwrap,
							  derive,
							  &h_new_key);

	// evaluate return code
	if (rv != CKR_OK)
    {
		snprintf(msg_buf, msg_buf_len, "unwrap_private_key: __unwrap_private_key() failed; return value %lu", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*h_pvt_key = h_new_key;

	return TRUE;
}

//----------------------------------------------------------------------------------------
// unwrap_secret_key()
//	Unwraps a secret symmetric key onto the HSM using a designated symmetric or asymmetric wrapping key.
//
//	Returns:
//		FALSE if an error occurs; otherwise TRUE
//
//	Modifies:
//		msg_buf			--	contains any error messages
//		h_secret_key    --  newly created secret key handle
//
//	Inputs:
//		msg_buf_len		--	byte length of provided error message buffer
//		h_session		--  session handle
//		h_wrap_key		--  handle to the wrapping key on the HSM to use
//		iv			    --  optional IV value to use with the wrapping key (can be null)
//		iv_len			--  optional IV value length (can be 0)
//		mech_type		--  wrapping key mechanism to use (3DES-CBC, AES-128-CBC, etc)
//		key_label		--  key label for new secret key
//      key_label_len	--	length of key label
//		key_id			--  key id for new secret key
//      key_id_len		--	length of key id
//		key_buf		    --  wrapped secret key bytes
//		key_buf_len		--  length of the wrapped secret key bytes
//		key_type		--	type of secret key (DES, DES2, DES3, AES, etc)
//		key_size		--	size of the key in bits (112, 128, 192, 256, etc)
//		token			--	1 to indicate the secret key exists on the token and not the session; otherwise 0
//		private_		--	1 to indicate the secret key is private and can only be accessed after authentication; otherwise 0
//		sensitive	   	--  1 to indicate the private key is sensitive; otherwise 0
//		modifiable		--	1 to indicate the secret key can be modified; otherwise 0
//		extractable		--	1 to indicate the secret key can be extracted; otherwise 0
//		sign			--	1 to indicate the secret key can sign; otherwise 0
//		verify			--	1 to indicate the secret key can verify; otherwise 0
//		encrypt			--	1 to indicate the secret key can encrypt; otherwise 0
//		decrypt			--	1 to indicate the secret key can decrypt; otherwise 0
//		wrap			--	1 to indicate the secret key can wrap; otherwise 0
//		unwrap			--	1 to indicate the secret key can unwrap; otherwise 0
//		overwrite		--  1 to indicate the existing secret key with the same label name can be overwritten; otherwise 0
//		derive			--	1 to indicate the secret key can be used to derive other keys; otherwise 0
//
//----------------------------------------------------------------------------------------
int unwrap_secret_key(char* msg_buf, unsigned long msg_buf_len, unsigned long h_session,
		unsigned long h_wrap_key, unsigned char* iv, unsigned long iv_len, unsigned long mech_type,
		unsigned char* key_label, unsigned long key_label_len, unsigned char* key_id, unsigned long key_id_len,
		unsigned char* key_buf, unsigned long key_buf_len,
		unsigned long key_type, unsigned long key_size,	unsigned long token, unsigned long private_,
		unsigned long sensitive, unsigned long modifiable, unsigned long extractable, unsigned long sign,
		unsigned long verify, unsigned long encrypt, unsigned long decrypt, unsigned long wrap, unsigned long unwrap,
		unsigned long derive, unsigned long overwrite, unsigned long* h_secret_key)
{
	CK_RV rv;

	//	null pointer check for private key info buffer length
	if (!h_session)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: h_session invalid value.");
		return FALSE;
	}

	//	null pointer check for public key label
	if (!key_label)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: key_label null pointer unexpected.");
		return FALSE;
	}

	//	check wrapping key handle
	if (h_wrap_key < 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: h_wrap_key invalid value.");
		return FALSE;
	}

	//	check key buffer
	if (!key_buf)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: key_buf invalid value.");
		return FALSE;
	}

	//	check key buffer length
	if (key_buf_len <= 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: key_buf_len invalid value.");
		return FALSE;
	}

	// check to make sure the public key label is not too long
	if (key_label_len > MAX_TOKEN_OBJECT_LABEL_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: key_label parameter too long.");
		return FALSE;
	}

	// key type check
	if (key_type < 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: key_type invalid.");
		return FALSE;
	}

	// key type check
	if (key_size < 0)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: key_size invalid.");
		return FALSE;
	}

	// make sure that the key label does not already exist on the HSM
	CK_OBJECT_HANDLE h_test = 0;
	rv = get_object_handle(msg_buf, msg_buf_len, h_session, key_label, key_label_len, &h_test);
	if (rv == FALSE)
	{
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: get_object_handle failed.");
		return FALSE;
	}

	if (h_test)
	{
		if (overwrite)
		{
			// destroy existing public key label object on the HSM
			rv = _p11->C_DestroyObject(h_session, h_test);
			if (rv != CKR_OK)
			{
				snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: PKCS#11 C_DestroyObject failed for secret key label '%s' with the return value %lu.", key_label, rv);
	   			__append_return_code(rv, msg_buf, msg_buf_len);
				return FALSE;
			}
		}
		else
		{
			snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: secret key label '%s' already exists.", key_label);
			return FALSE;
		}
	}

	CK_OBJECT_HANDLE h_new_key = 0;

	rv = __unwrap_secret_key(h_session,
							 h_wrap_key,
							 iv,
							 iv_len,
							 mech_type,
							 key_label,
							 key_label_len,
							 key_id,
							 key_id_len,
							 key_buf,
							 key_buf_len,
							 key_type,
							 key_size,
							 token,
							 private_,
							 sensitive,
							 modifiable,
							 extractable,
							 sign,
							 verify,
							 encrypt,
							 decrypt,
							 wrap,
							 unwrap,
							 derive,
							 &h_new_key);

	// evaluate return code
	if (rv != CKR_OK)
    {
		snprintf(msg_buf, msg_buf_len, "unwrap_secret_key: __unwrap_secret_key() failed; return value %lu", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	*h_secret_key = h_new_key;

	return TRUE;
}


//----------------------------------------------------------------------------------------
// get_mechanism_info()
//	Queries the slot and returns information supported PKCS#11 support mechanism info.
//
//	Returns:
//		FALSE if an error occurs otherwise TRUE
//
//	Modifies:
//		msg_buf			--  contains error messages
//		data_buf		--	to contain info with newline separating records and commas
//							separating fields.
//							Each record has:
//								* mechanism name
//								* mechanism value in base16 (hex)
//								* min key size
//								* max key size
//								* flags
//	 	data_buf_len	--  modifies to the size allocated
//		mech_count		--  modified to the number of mechanisms reported
//
//	Inputs:
//		msg_buf_len		--	byte length of provided buffer
//		slot			--  slot number
//		data_buf_len	--	byte length of provided buffer
//
//----------------------------------------------------------------------------------------
int get_mechanism_info(char* msg_buf, unsigned long msg_buf_len, unsigned long slot, char* data_buf, unsigned long* data_buf_len, unsigned long* mech_count)
{
	CK_RV rv;
	CK_ULONG mech_count_1 = 0;

	// first call to with NULL parameter gets the mech list count so we
	// can allocate storage space to fill with the 2nd call
	rv = _p11->C_GetMechanismList(slot, NULL, &mech_count_1);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_mechanism_list: PKCS#11 C_GetMechanismList failed with the return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// if the number of slots is less than 1 then exit
	if (mech_count_1 < 1)
	{
		*data_buf_len = 0;
		return TRUE;
	}

	// allocate memory buffer to fixed size on the stack so we don't have to worry with memory allocation/cleanup
	CK_ULONG MAX_MECH_TYPES = 500;
	CK_MECHANISM_TYPE pMechanismList[MAX_MECH_TYPES];

	// return an error if the number of mechs exceeds what the library supports
	if (mech_count_1 > MAX_MECH_TYPES)
	{
		snprintf(msg_buf, msg_buf_len, "get_mechanism_list: more mechanisms detected than supported by library mech_count=%lu MAX_MECH_TYPES=%lu", mech_count_1, MAX_MECH_TYPES);
		return FALSE;
	}

	CK_ULONG mech_count_2 = mech_count_1;

	// make 2nd call to fill the buffer
	rv = _p11->C_GetMechanismList(slot, pMechanismList, &mech_count_2);
	if (rv != CKR_OK)
	{
		snprintf(msg_buf, msg_buf_len, "get_mechanism_list: PKCS#11 C_GetMechanismList failed with the return value %lu.", rv);
		__append_return_code(rv, msg_buf, msg_buf_len);
		return FALSE;
	}

	// determine if the buffer is large enough
	CK_ULONG MAX_RECORD_SIZE_BYTES = 200;
	CK_ULONG MIN_DATA_BUF_SIZE = MAX_RECORD_SIZE_BYTES * mech_count_2 + 1;
	if (*data_buf_len < MIN_DATA_BUF_SIZE)
	{
		snprintf(msg_buf, msg_buf_len, "get_mechanism_list: data_buf %lu is too small minimum size is %lu", *data_buf_len, MIN_DATA_BUF_SIZE);
		return FALSE;
	}

    CK_MECHANISM_INFO mech_info;
	long offset = 0;
    for (CK_ULONG i = 0; i < mech_count_2; i++)
	{
    	CK_MECHANISM_TYPE mech_type = pMechanismList[i];
    	// retrieve additional mech info
    	rv = _p11->C_GetMechanismInfo(slot, mech_type, &mech_info);
    	if (rv != CKR_OK)
    	{
    		snprintf(msg_buf, msg_buf_len, "get_mechanism_list: PKCS#11 C_GetMechanismInfo failed with the return value %lu.", rv);
    		__append_return_code(rv, msg_buf, msg_buf_len);
    		return FALSE;
    	}

		// update the data buffer with the mech information
		offset += snprintf(data_buf+offset, *data_buf_len - offset,
						   "%s|0x%08lx|%lu|%lu|0x%08lx\n",
						   __mechanism_type_to_str(mech_type),
						   mech_type,
						   mech_info.ulMinKeySize,
						   mech_info.ulMaxKeySize,
						   mech_info.flags);

	}

	// remove the last LF
	offset--;
	// update the data buffer length return value
	*data_buf_len = offset;
	*mech_count = mech_count_2;

	return TRUE;
}


void __append_return_code(CK_RV code, char* text, unsigned long text_len)
{
	switch(code)
	{
		case CKR_OK:
			strncat(text, " CKR_OK ", text_len);
			break;
		case CKR_CANCEL:
			strncat(text, " CKR_CANCEL ", text_len);
			break;
		case CKR_HOST_MEMORY:
			strncat(text, " CKR_HOST_MEMORY ", text_len);
			break;
		case CKR_SLOT_ID_INVALID:
			strncat(text, " CKR_SLOT_ID_INVALID ", text_len);
			break;
		case CKR_GENERAL_ERROR:
			strncat(text, " CKR_GENERAL_ERROR ", text_len);
			break;
		case CKR_FUNCTION_FAILED:
			strncat(text, " CKR_FUNCTION_FAILED ", text_len);
			break;
		case CKR_ARGUMENTS_BAD:
			strncat(text, " CKR_ARGUMENTS_BAD ", text_len);
			break;
		case CKR_NO_EVENT:
			strncat(text, " CKR_NO_EVENT ", text_len);
			break;
		case CKR_NEED_TO_CREATE_THREADS:
			strncat(text, " CKR_NEED_TO_CREATE_THREADS ", text_len);
			break;
		case CKR_CANT_LOCK:
			strncat(text, " CKR_CANT_LOCK ", text_len);
			break;
		case CKR_ATTRIBUTE_READ_ONLY:
			strncat(text, " CKR_ATTRIBUTE_READ_ONLY ", text_len);
			break;
		case CKR_ATTRIBUTE_SENSITIVE:
			strncat(text, " CKR_ATTRIBUTE_SENSITIVE ", text_len);
			break;
		case CKR_ATTRIBUTE_TYPE_INVALID:
			strncat(text, " CKR_ATTRIBUTE_TYPE_INVALID ", text_len);
			break;
		case CKR_ATTRIBUTE_VALUE_INVALID:
			strncat(text, " CKR_ATTRIBUTE_VALUE_INVALID ", text_len);
			break;
		case CKR_DATA_INVALID:
			strncat(text, " CKR_DATA_INVALID ", text_len);
			break;
		case CKR_DATA_LEN_RANGE:
			strncat(text, " CKR_DATA_LEN_RANGE ", text_len);
			break;
		case CKR_DEVICE_ERROR:
			strncat(text, " CKR_DEVICE_ERROR ", text_len);
			break;
		case CKR_DEVICE_MEMORY:
			strncat(text, " CKR_DEVICE_MEMORY ", text_len);
			break;
		case CKR_DEVICE_REMOVED:
			strncat(text, " CKR_DEVICE_REMOVED ", text_len);
			break;
		case CKR_ENCRYPTED_DATA_INVALID:
			strncat(text, " CKR_ENCRYPTED_DATA_INVALID ", text_len);
			break;
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
			strncat(text, " CKR_ENCRYPTED_DATA_LEN_RANGE ", text_len);
			break;
		case CKR_FUNCTION_CANCELED:
			strncat(text, " CKR_FUNCTION_CANCELED ", text_len);
			break;
		case CKR_FUNCTION_NOT_PARALLEL:
			strncat(text, " CKR_FUNCTION_NOT_PARALLEL ", text_len);
			break;
		case CKR_FUNCTION_NOT_SUPPORTED:
			strncat(text, " CKR_FUNCTION_NOT_SUPPORTED ", text_len);
			break;
		case CKR_KEY_HANDLE_INVALID:
			strncat(text, " CKR_KEY_HANDLE_INVALID ", text_len);
			break;
		case CKR_KEY_SIZE_RANGE:
			strncat(text, " CKR_KEY_SIZE_RANGE ", text_len);
			break;
		case CKR_KEY_TYPE_INCONSISTENT:
			strncat(text, " CKR_KEY_TYPE_INCONSISTENT ", text_len);
			break;
		case CKR_KEY_UNEXTRACTABLE:
			strncat(text, " CKR_KEY_UNEXTRACTABLE ", text_len);
			break;
		case CKR_KEY_NOT_NEEDED:
			strncat(text, " CKR_KEY_NOT_NEEDED ", text_len);
			break;
		case CKR_KEY_CHANGED:
			strncat(text, " CKR_KEY_CHANGED ", text_len);
			break;
		case CKR_KEY_NEEDED:
			strncat(text, " CKR_KEY_NEEDED ", text_len);
			break;
		case CKR_KEY_INDIGESTIBLE:
			strncat(text, " CKR_KEY_INDIGESTIBLE ", text_len);
			break;
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			strncat(text, " CKR_KEY_FUNCTION_NOT_PERMITTED ", text_len);
			break;
		case CKR_KEY_NOT_WRAPPABLE:
			strncat(text, " CKR_KEY_NOT_WRAPPABLE ", text_len);
			break;
		case CKR_MECHANISM_INVALID:
			strncat(text, " CKR_MECHANISM_INVALID ", text_len);
			break;
		case CKR_MECHANISM_PARAM_INVALID:
			strncat(text, " CKR_MECHANISM_PARAM_INVALID ", text_len);
			break;
		case CKR_OBJECT_HANDLE_INVALID:
			strncat(text, " CKR_OBJECT_HANDLE_INVALID ", text_len);
			break;
		case CKR_OPERATION_ACTIVE:
			strncat(text, " CKR_OPERATION_ACTIVE ", text_len);
			break;
		case CKR_OPERATION_NOT_INITIALIZED:
			strncat(text, " CKR_OPERATION_NOT_INITIALIZED ", text_len);
			break;
		case CKR_PIN_INCORRECT:
			strncat(text, " CKR_PIN_INCORRECT ", text_len);
			break;
		case CKR_PIN_INVALID:
			strncat(text, " CKR_PIN_INVALID ", text_len);
			break;
		case CKR_PIN_LEN_RANGE:
			strncat(text, " CKR_PIN_LEN_RANGE ", text_len);
			break;
		case CKR_PIN_EXPIRED:
			strncat(text, " CKR_PIN_EXPIRED ", text_len);
			break;
		case CKR_PIN_LOCKED:
			strncat(text, " CKR_PIN_LOCKED ", text_len);
			break;
		case CKR_SESSION_CLOSED:
			strncat(text, " CKR_SESSION_CLOSED ", text_len);
			break;
		case CKR_SESSION_COUNT:
			strncat(text, " CKR_SESSION_COUNT ", text_len);
			break;
		case CKR_SESSION_HANDLE_INVALID:
			strncat(text, " CKR_SESSION_HANDLE_INVALID ", text_len);
			break;
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			strncat(text, " CKR_SESSION_PARALLEL_NOT_SUPPORTED ", text_len);
			break;
		case CKR_SESSION_READ_ONLY:
			strncat(text, " CKR_SESSION_READ_ONLY ", text_len);
			break;
		case CKR_SESSION_EXISTS:
			strncat(text, " CKR_SESSION_EXISTS ", text_len);
			break;
		case CKR_SESSION_READ_ONLY_EXISTS:
			strncat(text, " CKR_SESSION_READ_ONLY_EXISTS ", text_len);
			break;
		case CKR_SESSION_READ_WRITE_SO_EXISTS:
			strncat(text, " CKR_SESSION_READ_WRITE_SO_EXISTS ", text_len);
			break;
		case CKR_SIGNATURE_INVALID:
			strncat(text, " CKR_SIGNATURE_INVALID ", text_len);
			break;
		case CKR_SIGNATURE_LEN_RANGE:
			strncat(text, " CKR_SIGNATURE_LEN_RANGE ", text_len);
			break;
		case CKR_TEMPLATE_INCOMPLETE:
			strncat(text, " CKR_TEMPLATE_INCOMPLETE ", text_len);
			break;
		case CKR_TEMPLATE_INCONSISTENT:
			strncat(text, " CKR_TEMPLATE_INCONSISTENT ", text_len);
			break;
		case CKR_TOKEN_NOT_PRESENT:
			strncat(text, " CKR_TOKEN_NOT_PRESENT ", text_len);
			break;
		case CKR_TOKEN_NOT_RECOGNIZED:
			strncat(text, " CKR_TOKEN_NOT_RECOGNIZED ", text_len);
			break;
		case CKR_TOKEN_WRITE_PROTECTED:
			strncat(text, " CKR_TOKEN_WRITE_PROTECTED ", text_len);
			break;
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			strncat(text, " CKR_UNWRAPPING_KEY_HANDLE_INVALID ", text_len);
			break;
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			strncat(text, " CKR_UNWRAPPING_KEY_SIZE_RANGE ", text_len);
			break;
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			strncat(text, " CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT ", text_len);
			break;
		case CKR_USER_ALREADY_LOGGED_IN:
			strncat(text, " CKR_USER_ALREADY_LOGGED_IN ", text_len);
			break;
		case CKR_USER_NOT_LOGGED_IN:
			strncat(text, " CKR_USER_NOT_LOGGED_IN ", text_len);
			break;
		case CKR_USER_PIN_NOT_INITIALIZED:
			strncat(text, " CKR_USER_PIN_NOT_INITIALIZED ", text_len);
			break;
		case CKR_USER_TYPE_INVALID:
			strncat(text, " CKR_USER_TYPE_INVALID ", text_len);
			break;
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			strncat(text, " CKR_USER_ANOTHER_ALREADY_LOGGED_IN ", text_len);
			break;
		case CKR_USER_TOO_MANY_TYPES:
			strncat(text, " CKR_USER_TOO_MANY_TYPES ", text_len);
			break;
		case CKR_WRAPPED_KEY_INVALID:
			strncat(text, " CKR_WRAPPED_KEY_INVALID ", text_len);
			break;
		case CKR_WRAPPED_KEY_LEN_RANGE:
			strncat(text, " CKR_WRAPPED_KEY_LEN_RANGE ", text_len);
			break;
		case CKR_WRAPPING_KEY_HANDLE_INVALID:
			strncat(text, " CKR_WRAPPING_KEY_HANDLE_INVALID ", text_len);
			break;
		case CKR_WRAPPING_KEY_SIZE_RANGE:
			strncat(text, " CKR_WRAPPING_KEY_SIZE_RANGE ", text_len);
			break;
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			strncat(text, " CKR_WRAPPING_KEY_TYPE_INCONSISTENT ", text_len);
			break;
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			strncat(text, " CKR_RANDOM_SEED_NOT_SUPPORTED ", text_len);
			break;
		case CKR_RANDOM_NO_RNG:
			strncat(text, " CKR_RANDOM_NO_RNG ", text_len);
			break;
		case CKR_BUFFER_TOO_SMALL:
			strncat(text, " CKR_BUFFER_TOO_SMALL ", text_len);
			break;
		case CKR_SAVED_STATE_INVALID:
			strncat(text, " CKR_SAVED_STATE_INVALID ", text_len);
			break;
		case CKR_INFORMATION_SENSITIVE:
			strncat(text, " CKR_INFORMATION_SENSITIVE ", text_len);
			break;
		case CKR_STATE_UNSAVEABLE:
			strncat(text, " CKR_STATE_UNSAVEABLE ", text_len);
			break;
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			strncat(text, " CKR_CRYPTOKI_NOT_INITIALIZED ", text_len);
			break;
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			strncat(text, " CKR_CRYPTOKI_ALREADY_INITIALIZED ", text_len);
			break;
		case CKR_MUTEX_BAD:
			strncat(text, " CKR_MUTEX_BAD ", text_len);
			break;
		case CKR_MUTEX_NOT_LOCKED:
			strncat(text, " CKR_MUTEX_NOT_LOCKED ", text_len);
			break;
		default:
			strncat(text, " Unknown CKR_ code! ", text_len);
			break;
	}
	// attach the CKR code value as hex to the message text string
	char code_buf[20];
	int cx = snprintf(code_buf, 20, "(0x%08lx) ", code);
	if (cx >= 0 && cx < 100)
		strncat(text, code_buf, text_len);

}











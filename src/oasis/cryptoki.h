/* cryptoki.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

/* License to copy and use this software is granted provided that it is
* identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
* (Cryptoki)" in all material mentioning or referencing this software.

* License is also granted to make and use derivative works provided that
* such works are identified as "derived from the RSA Security Inc. PKCS #11
* Cryptographic Token Interface (Cryptoki)" in all material mentioning or
* referencing the derived work.

* RSA Security Inc. makes no representations concerning either the
* merchantability of this software or the suitability of this software for
* any particular purpose. It is provided "as is" without express or implied
* warranty of any kind.
*/

/* This is a sample file containing the top level include directives
* for building Win32 Cryptoki libraries and applications.
*/

#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************\
*                                                                            *
* Operating System/Platform linking constructs                               *
*                                                                            *
\****************************************************************************/
#if defined(OS_WIN)
   #define CK_ENTRY           __declspec( dllexport )
   #define CK_POINTER         *

   #define CK_DEFINE_FUNCTION(returnType, name) \
	returnType __declspec(dllexport) name

   #define CK_DECLARE_FUNCTION(returnType, name) \
	returnType __declspec(dllexport) name

   #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType __declspec(dllexport) (* name)

   #define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

   #pragma pack(push, cryptoki, 1)

#elif defined(OS_UNIX) || defined(OS_LINUX)
   #define CK_ENTRY
   #define CK_POINTER         *

   #define CK_DEFINE_FUNCTION(returnType, name) \
	returnType name

   #define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name

   #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)

   #define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

//   #pragma pack(1)
#else
   #error "Unknown platform!"
#endif

#define NULL_PTR           0

#define CK_PTR *

#include "../oasis/pkcs11.h"


#if defined(OS_WIN)
   #pragma pack(pop, cryptoki)
#elif defined(OS_UNIX) || defined(OS_LINUX)
//   #pragma pack
#else
   #error "Unknown platform!"
#endif

#ifdef __cplusplus
}
#endif

#ifdef _MSC_VER 
#pragma deprecated( CK_USHORT, CK_USHORT_PTR )
#endif 

#endif                /* CRYPTOKI_H_ */

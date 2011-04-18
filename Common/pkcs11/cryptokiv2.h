#ifndef _CRYPTOKIV2_H_
#define _CRYPTOKIV2_H_

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType __declspec(dllexport) (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#pragma pack(push, cryptoki, 1)
#include "pkcs11.h"
#pragma pack(pop, cryptoki)

#endif /* _CRYPTOKIV2_H_ */
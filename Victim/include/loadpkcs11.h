#ifndef _LOADPKCS11_H_
#define _LOADPKCS11_H_

#define TARGET_DLL "UsrPKCS11.dll"

#include "cryptokiv2.h"
#include <stdarg.h>

int loadPKCS11dll(char *filename);

#endif /* _LOADPKCS11_H_ */
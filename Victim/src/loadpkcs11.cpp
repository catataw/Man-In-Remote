#include <windows.h>

#include "loadpkcs11.h"

extern HINSTANCE hDLL;

CK_FUNCTION_LIST_PTR pFunctionList;

int loadPKCS11dll(char *filename)
{	
	CK_RV 					rv = CKR_OK;
	CK_C_GetFunctionList 	pC_GetFunctionList;

	hDLL = LoadLibrary(filename);
	if (hDLL == NULL) {
		return -1;
	}

	pC_GetFunctionList = (CK_C_GetFunctionList) GetProcAddress(hDLL, "C_GetFunctionList");

	rv = pC_GetFunctionList(&pFunctionList);

	return 0;
}

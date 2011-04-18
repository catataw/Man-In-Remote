#include <afxwin.h>
#include <afxext.h>
#include <afxdisp.h>

#include <stdio.h>
#include <windows.h>
#include <winsock2.h>

#include "cryptokiv2.h"
#include "data2inet.h"
#include "pkcs11t.h"

//#define _DEBUG_PKCS11_

CK_FUNCTION_LIST_PTR pFunctionList = NULL;
CK_FUNCTION_LIST functionList = {
		{2, 11},
#pragma pack(1)
		C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_GetSlotInfo,
        C_GetTokenInfo,
        C_GetMechanismList,
        C_GetMechanismInfo,
        C_InitToken,
        C_InitPIN,
        C_SetPIN,
        C_OpenSession,
        C_CloseSession,  
        C_CloseAllSessions,
        C_GetSessionInfo,
        C_GetOperationState,
        C_SetOperationState,
        C_Login,
        C_Logout,
        C_CreateObject,
        C_CopyObject,
        C_DestroyObject,
        C_GetObjectSize,
        C_GetAttributeValue,
        C_SetAttributeValue,
        C_FindObjectsInit,
        C_FindObjects,
        C_FindObjectsFinal,
        C_EncryptInit,
        C_Encrypt,
        C_EncryptUpdate,
        C_EncryptFinal,
        C_DecryptInit,
        C_Decrypt,
        C_DecryptUpdate,
        C_DecryptFinal,
        C_DigestInit,
        C_Digest,
        C_DigestUpdate,
        C_DigestKey,
        C_DigestFinal,
        C_SignInit,
        C_Sign,
        C_SignUpdate,
        C_SignFinal,
        C_SignRecoverInit,
        C_SignRecover,
        C_VerifyInit,
        C_Verify,
        C_VerifyUpdate,
        C_VerifyFinal,
        C_VerifyRecoverInit,
        C_VerifyRecover,
        C_DigestEncryptUpdate,
        C_DecryptDigestUpdate,
        C_SignEncryptUpdate,
        C_DecryptVerifyUpdate,
        C_GenerateKey,
        C_GenerateKeyPair,
        C_WrapKey,
        C_UnwrapKey,
        C_DeriveKey,
        C_SeedRandom,
        C_GenerateRandom,
        C_GetFunctionStatus,
        C_CancelFunction,
        C_WaitForSlotEvent
};

#ifdef _DEBUG_PKCS11_
FILE		*fout = NULL;
#endif

SOCKET	client;
/* General-purpose */

/* C_Initialize initializes the Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV,C_Initialize)
(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced */
)
{
	CK_RV rv = CKR_OK;

#ifdef _DEBUG_PKCS11_
	if ((fout = fopen("C:\\pkcs11-a.out", "w+")) == NULL) {
		perror("fopen()");
		return CKR_CANCEL;
	}
#endif

	{
		int	a = 0x0;
		WSADATA				wsaData;
		FILE				*fip = NULL;
		char				ip[32];
		WORD				version;
		int					error;
		struct sockaddr_in	sock;
		
		DataMarshalling	*d = NULL;

		version = MAKEWORD(2, 0);

		error = WSAStartup(version, &wsaData);
		if (error) {
			rv = CKR_CANCEL;
			goto exit;
		}

		if ((fip = fopen("C:\\pkcs11-ip.cfg", "r")) == NULL) {
			perror("fopen(ip)");
			return CKR_CANCEL;
		}

		fscanf(fip, "%s", ip);
		fclose(fip);

		if ((client = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			rv = CKR_CANCEL;
			goto exit;
		}

		memset(&sock, 0, sizeof(sock));

		sock.sin_family = AF_INET;
		//sock.sin_addr.s_addr = inet_addr("83.39.72.237");
		//sock.sin_addr.s_addr = inet_addr("192.168.0.145");
		sock.sin_addr.s_addr = inet_addr(ip);
		sock.sin_port = htons(1024 + 666);

		if (connect(client, (struct sockaddr *)&sock, sizeof(sock)) == SOCKET_ERROR) {
			rv = CKR_CANCEL;
			goto exit;
		}

		d = new DataMarshalling(client);
		d->setMsgType("C_Initialize");
		d->packInt((char *)&a);
		d->sendData();
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_Initialize ret: %d\n", rv);
#endif

exit:
	return rv;
}

/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_DEFINE_FUNCTION(CK_RV,C_Finalize)
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	CK_RV rv = CKR_OK;
	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_Finalize");
		{
			/*
			 * Retrieve Number of Slots
			 */
			unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&pReserved);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}
	{
		closesocket(client);
		WSACleanup();
	}
#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_Finalize ret: %d\n", rv);
	fclose(fout);
#endif

exit:
	return rv;
}


/* C_GetInfo returns general information about Cryptoki. */
CK_DEFINE_FUNCTION(CK_RV,C_GetInfo)
(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
	CK_RV rv = CKR_OK;
		
	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetInfo");
		{
			/*
			 * Retrieve Number of Slots
			 */
			unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&pInfo);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			pInfo->cryptokiVersion.major = d2->unpackChar();
			pInfo->cryptokiVersion.minor = d2->unpackChar();
			d2->unpackMem((char *)pInfo->manufacturerID, 32);
			pInfo->flags = d2->unpackInt();
			d2->unpackMem((char *)pInfo->libraryDescription, 32);
			pInfo->libraryVersion.major = d2->unpackChar();
			pInfo->libraryVersion.minor = d2->unpackChar();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetInfo ret: %d\n", rv);
#endif

exit:
	return rv;
}

/* C_GetInfo returns general information about Cryptoki. */
CK_DEFINE_FUNCTION(CK_RV,C_GetFunctionList)
(
  CK_FUNCTION_LIST_PTR_PTR   ppFunctionList  /* location that receives information */
)
{
	CK_RV rv = CKR_OK;

	if (ppFunctionList == NULL)
		rv = CKR_ARGUMENTS_BAD;
	else	
		*ppFunctionList = &functionList;

	return rv;
}

/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_DEFINE_FUNCTION(CK_RV,C_GetSlotList)
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetSlotList");
		if (pSlotList == NULL) {
			/*
			 * Retrieve Number of Slots
			 */
			static unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			if (len == 0) {
				d->packInt((char *)&len);
				d->sendData();
				d2->recvData();
				if (strcmp(d2->getMsgType(), d->getMsgType())) {
					rv = CKR_CANCEL;
					goto exit;
				}
				rv = d2->unpackInt();
				len = d2->unpackInt();
				delete d2;
				printf("%d\n", len);
			}
			*pulCount = len;
		} else {
			/*
			 * Retrieve Slots
			 */
			unsigned int	len = 1;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&len);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			len = d2->unpackInt();
			for (int i = 0; i < len; i ++)
				pSlotList[i] = d2->unpackInt();
			delete d2;
			*pulCount = len;
		}

		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetSlotList ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
CK_DEFINE_FUNCTION(CK_RV,C_GetSlotInfo)
(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetSlotInfo");
		{
			/*
			 * Retrieve Number of Slots
			 */
			unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&slotID);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			d2->unpackMem((char *)pInfo->slotDescription, 64);
			d2->unpackMem((char *)pInfo->manufacturerID, 32);
			pInfo->flags = d2->unpackInt();
			pInfo->hardwareVersion.major = d2->unpackChar();
			pInfo->hardwareVersion.minor = d2->unpackChar();
			pInfo->firmwareVersion.major = d2->unpackChar();
			pInfo->firmwareVersion.minor = d2->unpackChar();

			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetSlotInfo ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
CK_DEFINE_FUNCTION(CK_RV,C_GetTokenInfo)
(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetTokenInfo");
		{
			/*
			 * Retrieve Number of Slots
			 */
			unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&slotID);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			d2->unpackMem((char *)pInfo->label, 32);
			d2->unpackMem((char *)pInfo->manufacturerID, 32);
			d2->unpackMem((char *)pInfo->model, 16);
			d2->unpackMem((char *)pInfo->serialNumber, 16);
			pInfo->flags = d2->unpackInt();
			pInfo->ulMaxSessionCount = d2->unpackInt();
			pInfo->ulSessionCount = d2->unpackInt();
			pInfo->ulMaxRwSessionCount = d2->unpackInt();
			pInfo->ulRwSessionCount = d2->unpackInt();
			pInfo->ulMaxPinLen = d2->unpackInt();
			pInfo->ulMinPinLen = d2->unpackInt();
			pInfo->ulTotalPublicMemory = d2->unpackInt();
			pInfo->ulFreePublicMemory = d2->unpackInt();
			pInfo->ulTotalPrivateMemory = d2->unpackInt();
			pInfo->ulFreePrivateMemory = d2->unpackInt();
			pInfo->hardwareVersion.major = d2->unpackChar();
			pInfo->hardwareVersion.minor = d2->unpackChar();
			pInfo->firmwareVersion.major = d2->unpackChar();
			pInfo->firmwareVersion.minor = d2->unpackChar();
			d2->unpackMem((char *)pInfo->utcTime, 16);

			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetTokenInfo ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
CK_DEFINE_FUNCTION(CK_RV,C_GetMechanismList)
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetMechanismList");
		d->packInt((char *)&slotID);
		d->packInt((char *)&pMechanismList);
		if (pMechanismList == NULL) {
			/*
			 * Retrieve Number of Slots
			 */
			unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);
			
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			len = d2->unpackInt();
			delete d2;
			//printf("%d\n", len);
			*pulCount = len;
		} else {
			/*
			 * Retrieve Slots
			 */
			unsigned int	len = 1;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			len = d2->unpackInt();
			*pulCount = len;
			for (int i = 0; i < len; i ++)
				pMechanismList[i] = d2->unpackInt();
			delete d2;
			
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetMechanismList ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
CK_DEFINE_FUNCTION(CK_RV,C_GetMechanismInfo)
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetMechanismInfo");
		{
			/*
			 * Retrieve Mechanism
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&slotID);
			d->packInt((char *)&type);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			pInfo->ulMinKeySize = d2->unpackInt();
			pInfo->ulMaxKeySize = d2->unpackInt();
			pInfo->flags = d2->unpackInt();

			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetMechanismInfo ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_InitToken initializes a token. */
CK_DEFINE_FUNCTION(CK_RV,C_InitToken)
(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_InitToken
		(
		slotID,    /* ID of the token's slot */
		pPin,      /* the SO's initial PIN */
		ulPinLen,  /* length in bytes of the PIN */
		pLabel     /* 32-byte token label (blank padded) */
		);

	return rv;
}


/* C_InitPIN initializes the normal user's PIN. */
CK_DEFINE_FUNCTION(CK_RV,C_InitPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_InitPIN
		(
		hSession,  /* the session's handle */
		pPin,      /* the normal user's PIN */
		ulPinLen   /* length in bytes of the PIN */
		);

	return rv;
}



/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV,C_SetPIN)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SetPIN
		(
		hSession,  /* the session's handle */
		pOldPin,   /* the old PIN */
		ulOldLen,  /* length of the old PIN */
		pNewPin,   /* the new PIN */
		ulNewLen   /* length of the new PIN */
		);

	return rv;
}



/* Session management */

/* C_OpenSession opens a session between an application and a
 * token. */
CK_DEFINE_FUNCTION(CK_RV,C_OpenSession)
(
  CK_SLOT_ID            slotID,        //* the slot's ID 
  CK_FLAGS              flags,         //* from CK_SESSION_INFO 
  CK_VOID_PTR           pApplication,  //* passed to callback 
  CK_NOTIFY             Notify,        //* callback function 
  CK_SESSION_HANDLE_PTR phSession      //* gets session handle 
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_OpenSession");
		{
			/*
			 * Open session
			 */
			unsigned int	sessionId = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&slotID);
			d->packInt((char *)&flags);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			sessionId = d2->unpackInt();
			delete d2;
			*phSession = sessionId;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_OpenSession ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_CloseSession closes a session between an application and a
 * token. */
CK_DEFINE_FUNCTION(CK_RV,C_CloseSession)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_CloseSession");
		{
			/*
			 * Open session
			 */
			unsigned int	sessionId = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_CloseSession ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_CloseAllSessions closes all sessions with a token. */
CK_DEFINE_FUNCTION(CK_RV,C_CloseAllSessions)
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_CloseSession");
		{
			/*
			 * Open session
			 */
			unsigned int	sessionId = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&slotID);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_CloseAllSessions ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GetSessionInfo obtains information about the session. */
CK_DEFINE_FUNCTION(CK_RV,C_GetSessionInfo)
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetSessionInfo");
		{
			/*
			 * Retrieve Number of Slots
			 */
			unsigned int	len = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			pInfo->slotID = d2->unpackInt();
			pInfo->state = d2->unpackInt();
			pInfo->flags = d2->unpackInt();
			pInfo->ulDeviceError = d2->unpackInt();

			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetSessionInfo ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_DEFINE_FUNCTION(CK_RV,C_GetOperationState)
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_GetOperationState
		(
		hSession,             /* session's handle */
		pOperationState,      /* gets state */
		pulOperationStateLen  /* gets state length */
		);

	return rv;
}



/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_DEFINE_FUNCTION(CK_RV,C_SetOperationState)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SetOperationState
		(
		hSession,            /* session's handle */
		pOperationState,      /* holds state */
		ulOperationStateLen,  /* holds state length */
		hEncryptionKey,       /* en/decryption key */
		hAuthenticationKey    /* sign/verify key */
		);

	return rv;
}



/* C_Login logs a user into a token. */
CK_DEFINE_FUNCTION(CK_RV,C_Login)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_Login");
		{
			/*
			 * Open session
			 */
			unsigned int	sessionId = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&userType);
			d->packInt((char *)&ulPinLen);
			d->packMem((char *)pPin, ulPinLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_Login ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_Logout logs a user out from a token. */
CK_DEFINE_FUNCTION(CK_RV,C_Logout)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_Logout");
		{
			/*
			 * Open session
			 */
			unsigned int	sessionId = 0;
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_Logout ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* Object management */

/* C_CreateObject creates a new object. */
CK_DEFINE_FUNCTION(CK_RV,C_CreateObject)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_CreateObject
		(
		hSession,    /* the session's handle */
		pTemplate,   /* the object's template */
		ulCount,     /* attributes in template */
		phObject  /* gets new object's handle. */
		);

	return rv;
}



/* C_CopyObject copies an object, creating a new object for the
 * copy. */
CK_DEFINE_FUNCTION(CK_RV,C_CopyObject)
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_CopyObject
		(
		hSession,    /* the session's handle */
		hObject,     /* the object's handle */
		pTemplate,   /* template for new object */
		ulCount,     /* attributes in template */
		phNewObject  /* receives handle of copy */
		);

	return rv;
}



/* C_DestroyObject destroys an object. */
CK_DEFINE_FUNCTION(CK_RV,C_DestroyObject)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DestroyObject
		(
		hSession,  /* the session's handle */
		hObject    /* the object's handle */
		);

	return rv;
}



/* C_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV,C_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_GetObjectSize
		(
		hSession,  /* the session's handle */
		hObject,   /* the object's handle */
		pulSize    /* receives size of object */
		);

	return rv;
}



/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
CK_DEFINE_FUNCTION(CK_RV,C_GetAttributeValue)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	CK_RV rv = CKR_OK;
	
#ifdef _DEBUG_PKCS11_
	fprintf(fout, ">> C_GetAttributeValue\n");
	fprintf(fout, "\tsession: %d\n", hSession);
	fprintf(fout, "\tobject: %d\n", hObject);
	fprintf(fout, "\tcount: %d\n", ulCount);
	for (int i = 0; i < ulCount; i ++) {
		fprintf(fout, "template: \n");
		fprintf(fout, "\ttype: %d\n", pTemplate[i].type);
		fprintf(fout, "\tvalueLen: %d\n", pTemplate[i].ulValueLen);
		fprintf(fout, "\tpValue: %p\n", pTemplate[i].pValue);
	}
#endif


	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GetAttributeValue");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&hObject);
			d->packInt((char *)&ulCount);
			for (int i = 0; i < ulCount; i ++) {
				d->packInt((char *)&pTemplate[i].type);
				d->packInt((char *)&pTemplate[i].ulValueLen);
				d->packInt((char *)&pTemplate[i].pValue);
				//if (pTemplate[i].pValue != NULL)
				//	d->packMem((char *)pTemplate[i].pValue, pTemplate[i].ulValueLen);
			}
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			for (int i = 0; i < ulCount; i ++) {
				pTemplate[i].type = d2->unpackInt();
				pTemplate[i].ulValueLen = d2->unpackInt();
				if (d2->unpackInt() != 0x0)
					d2->unpackMem((char *)pTemplate[i].pValue, pTemplate[i].ulValueLen);
			}
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GetAttributeValue ret: %d\n", rv);
	for (int i = 0; i < ulCount; i ++) {
		fprintf(fout, "template: \n");
		fprintf(fout, "\ttype: %d\n", pTemplate[i].type);
		fprintf(fout, "\tvalueLen: %d\n", pTemplate[i].ulValueLen);
		fprintf(fout, "\tpValue: %p\n", pTemplate[i].pValue);
		if (pTemplate[i].pValue != NULL)
			for (int j = 0; j < pTemplate[i].ulValueLen; j ++) {
				fprintf(fout, "%x", *((char *)pTemplate[i].pValue) + j);
			}
		fprintf(fout, "\n");
	}
#endif

exit:
	return rv;
}



/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
CK_DEFINE_FUNCTION(CK_RV,C_SetAttributeValue)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SetAttributeValue
		(
		hSession,   /* the session's handle */
		hObject,    /* the object's handle */
		pTemplate,  /* specifies attrs and values */
		ulCount     /* attributes in template */
		);

	return rv;
}



/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV,C_FindObjectsInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
	CK_RV rv = CKR_OK;
	
#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_FindObjectsInit ret: %d\n", rv);
	fprintf(fout, "ulCount: %d\n", ulCount);
	for (int i = 0; i < ulCount; i ++) {
		fprintf(fout, "template: \n");
		fprintf(fout, "\ttype %d\n", pTemplate[i].type);
		fprintf(fout, "\tulValueLen %d\n", pTemplate[i].ulValueLen);
		fprintf(fout, "\tpValue ");
		for (int j = 0; j < pTemplate[i].ulValueLen; j ++)
			fprintf(fout, "%x", *((char *)pTemplate[i].pValue) + j);
		fprintf(fout, "\n");
	}
#endif

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_FindObjectsInit");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&ulCount);
			for (int i = 0; i < ulCount; i ++) {
				d->packInt((char *)&pTemplate[i].type);
				d->packInt((char *)&pTemplate[i].ulValueLen);
				d->packMem((char *)pTemplate[i].pValue, pTemplate[i].ulValueLen);
			}
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}
exit:
	return rv;
}



/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_DEFINE_FUNCTION(CK_RV,C_FindObjects)
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_FindObjects");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&ulMaxObjectCount);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			*pulObjectCount = d2->unpackInt();
			for (int i = 0; (i < *pulObjectCount) && (i < ulMaxObjectCount); i ++)
				*(phObject + i)= d2->unpackInt();
			
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_FindObjects ret: %d\n", rv);
	fprintf(fout, "\tObject %d\n", *phObject);
	fprintf(fout, "\tpulObjectCount %d\n", *pulObjectCount);
#endif

exit:
	return rv;
}



/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_DEFINE_FUNCTION(CK_RV,C_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_FindObjectsFinal");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_FindObjectsFinal ret: %d\n", rv);
#endif

exit:
	return rv;
}




/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_DEFINE_FUNCTION(CK_RV,C_EncryptInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_EncryptInit
		(
		hSession,    /* the session's handle */
		pMechanism,  /* the encryption mechanism */
		hKey         /* handle of encryption key */
		);

	return rv;
}



/* C_Encrypt encrypts single-part data. */
CK_DEFINE_FUNCTION(CK_RV,C_Encrypt)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
	CK_RV rv = CKR_OK;
	
	rv = pFunctionList->C_Encrypt
		(
		hSession,            /* session's handle */
		pData,               /* the plaintext data */
		ulDataLen,           /* bytes of plaintext */
		pEncryptedData,      /* gets ciphertext */
		pulEncryptedDataLen  /* gets c-text size */
		);

	return rv;
}



/* C_EncryptUpdate continues a multiple-part encryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV,C_EncryptUpdate)
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_EncryptUpdate
		(
		hSession,           /* session's handle */
		pPart,              /* the plaintext data */
		ulPartLen,          /* plaintext data len */
		pEncryptedPart,     /* gets ciphertext */
		pulEncryptedPartLen /* gets c-text size */
		);

	return rv;
}



/* C_EncryptFinal finishes a multiple-part encryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV,C_EncryptFinal)
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_EncryptFinal
		(
		hSession,                /* session handle */
		pLastEncryptedPart,      /* last c-text */
		pulLastEncryptedPartLen  /* gets last size */
		);

	return rv;
}



/* C_DecryptInit initializes a decryption operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DecryptInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DecryptInit
		(
		hSession,    /* the session's handle */
		pMechanism,  /* the decryption mechanism */
		hKey         /* handle of decryption key */
		);

	return rv;
}



/* C_Decrypt decrypts encrypted data in a single part. */
CK_DEFINE_FUNCTION(CK_RV,C_Decrypt)
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
	CK_RV rv = CKR_OK;
	
	rv = pFunctionList->C_Decrypt
		(
		hSession,           /* session's handle */
		pEncryptedData,     /* ciphertext */
		ulEncryptedDataLen, /* ciphertext length */
		pData,              /* gets plaintext */
		pulDataLen          /* gets p-text size */
		);

	return rv;
}



/* C_DecryptUpdate continues a multiple-part decryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DecryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DecryptUpdate
		(
		hSession,            /* session's handle */
		pEncryptedPart,      /* encrypted data */
		ulEncryptedPartLen,  /* input length */
		pPart,               /* gets plaintext */
		pulPartLen           /* p-text size */
		);

	return rv;
}



/* C_DecryptFinal finishes a multiple-part decryption
 * operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DecryptFinal)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DecryptFinal
		(
		hSession,       /* the session's handle */
		pLastPart,      /* gets plaintext */
		pulLastPartLen  /* p-text size */
		);

	return rv;
}




/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DigestInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DigestInit
		(
		hSession,   /* the session's handle */
		pMechanism  /* the digesting mechanism */
		);

	return rv;
}



/* C_Digest digests data in a single part. */
CK_DEFINE_FUNCTION(CK_RV,C_Digest)
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_Digest
		(
		hSession,     /* the session's handle */
		pData,        /* data to be digested */
		ulDataLen,    /* bytes of data to digest */
		pDigest,      /* gets the message digest */
		pulDigestLen  /* gets digest length */
		);

	return rv;
}



/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DigestUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DigestUpdate
		(
		hSession,  /* the session's handle */
		pPart,     /* data to be digested */
		ulPartLen  /* bytes of data to be digested */
		);

	return rv;
}



/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_DEFINE_FUNCTION(CK_RV,C_DigestKey)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DigestKey
		(
		hSession,  /* the session's handle */
		hKey       /* secret key to digest */
		);

	return rv;
}



/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DigestFinal)
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DigestFinal
		(
		hSession,     /* the session's handle */
		pDigest,      /* gets the message digest */
		pulDigestLen  /* gets byte count of digest */
		);

	return rv;
}




/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
CK_DEFINE_FUNCTION(CK_RV,C_SignInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_SignInit");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&hKey);
			d->packInt((char *)&pMechanism->mechanism);
			d->packInt((char *)&pMechanism->ulParameterLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_SignInit ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_Sign)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_Sign");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&ulDataLen);
			d->packInt((char *)&pData);
			if (pData != NULL)
				d->packMem((char *)pData, ulDataLen);
			d->packInt((char *)pulSignatureLen);
			d->packInt((char *)&pSignature);
			if (pSignature != NULL)
				d->packMem((char *)pSignature, *pulSignatureLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			*pulSignatureLen = d2->unpackInt();
			if (pSignature != NULL)
				d2->unpackMem((char *)pSignature, *pulSignatureLen);
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_Sign ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data, 
 * and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_SignUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SignUpdate
		(
		hSession,  /* the session's handle */
		pPart,     /* the data to sign */
		ulPartLen  /* count of bytes to sign */
		);

	return rv;
}



/* C_SignFinal finishes a multiple-part signature operation, 
 * returning the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_SignFinal)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SignFinal
		(
		hSession,        /* the session's handle */
		pSignature,      /* gets the signature */
		pulSignatureLen  /* gets signature length */
		);

	return rv;
}



/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_SignRecoverInit)
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SignRecoverInit
		(
		hSession,   /* the session's handle */
		pMechanism, /* the signature mechanism */
		hKey        /* handle of the signature key */
		);

	return rv;
}



/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_SignRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SignRecover
		(
		hSession,        /* the session's handle */
		pData,           /* the data to sign */
		ulDataLen,       /* count of bytes to sign */
		pSignature,      /* gets the signature */
		pulSignatureLen  /* gets signature length */
		);

	return rv;
}


/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 *  cannot be recovered from the signature (e.g. DSA). */
CK_DEFINE_FUNCTION(CK_RV,C_VerifyInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */ 
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_VerifyInit");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&hKey);
			d->packInt((char *)&pMechanism->mechanism);
			d->packInt((char *)&pMechanism->ulParameterLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_VerifyInit ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_Verify verifies a signature in a single-part operation, 
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_Verify)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_Verify");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&ulDataLen);
			d->packInt((char *)&pData);
			if (pData != NULL)
				d->packMem((char *)pData, ulDataLen);
			d->packInt((char *)&ulSignatureLen);
			d->packInt((char *)&pSignature);
			if (pSignature != NULL)
				d->packMem((char *)pSignature, ulSignatureLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_Verify ret: %d\n", rv);
#endif

exit:	
	return rv;
}

/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data, 
 * and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_VerifyUpdate)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_VerifyUpdate
		(
		hSession,  /* the session's handle */
		pPart,     /* signed data */
		ulPartLen  /* length of signed data */
		);

	return rv;
}



/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_VerifyFinal)
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_VerifyFinal
		(
		hSession,       /* the session's handle */
		pSignature,     /* signature to verify */
		ulSignatureLen  /* signature length */
		);

	return rv;
}



/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_VerifyRecoverInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_VerifyRecoverInit
		(
		hSession,    /* the session's handle */
		pMechanism,  /* the verification mechanism */
		hKey         /* verification key */
		);

	return rv;
}



/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV,C_VerifyRecover)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_VerifyRecover
		(
		hSession,        /* the session's handle */
		pSignature,      /* signature to verify */
		ulSignatureLen,  /* signature length */
		pData,           /* gets signed data */
		pulDataLen       /* gets signed data len */
		);

	return rv;
}




/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DigestEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DigestEncryptUpdate
		(
		hSession,            /* session's handle */
		pPart,               /* the plaintext data */
		ulPartLen,           /* plaintext length */
		pEncryptedPart,      /* gets ciphertext */
		pulEncryptedPartLen  /* gets c-text length */
		);

	return rv;
}



/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DecryptDigestUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DecryptDigestUpdate
		(
		hSession,            /* session's handle */
		pEncryptedPart,      /* ciphertext */
		ulEncryptedPartLen,  /* ciphertext length */
		pPart,               /* gets plaintext */
		pulPartLen           /* gets plaintext len */
		);

	return rv;
}



/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_DEFINE_FUNCTION(CK_RV,C_SignEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_SignEncryptUpdate
		(
		hSession,            /* session's handle */
		pPart,               /* the plaintext data */
		ulPartLen,           /* plaintext length */
		pEncryptedPart,      /* gets ciphertext */
		pulEncryptedPartLen  /* gets c-text length */
		);

	return rv;
}



/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_DEFINE_FUNCTION(CK_RV,C_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DecryptVerifyUpdate
		(
		hSession,            /* session's handle */
		pEncryptedPart,      /* ciphertext */
		ulEncryptedPartLen,  /* ciphertext length */
		pPart,               /* gets plaintext */
		pulPartLen           /* gets p-text length */
		);

	return rv;
}




/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV,C_GenerateKey)
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_GenerateKey
		(
		hSession,    /* the session's handle */
		pMechanism,  /* key generation mech. */
		pTemplate,   /* template for new key */
		ulCount,     /* # of attrs in template */
		phKey        /* gets handle of new key */
		);

	return rv;
}



/* C_GenerateKeyPair generates a public-key/private-key pair, 
 * creating new key objects. */
CK_DEFINE_FUNCTION(CK_RV,C_GenerateKeyPair)
(
  CK_SESSION_HANDLE    hSession,                    /* session
                                                     * handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
                                                     * mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
                                                     * for pub.
                                                     * key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
                                                     * attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
                                                     * for priv.
                                                     * key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
                                                     * attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
                                                     * key
                                                     * handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
                                                     * priv. key
                                                     * handle */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_GenerateKeyPair
		(
		hSession, 
		pMechanism,
		pPublicKeyTemplate,
		ulPublicKeyAttributeCount,
		pPrivateKeyTemplate,
		ulPrivateKeyAttributeCount,
		phPublicKey,
		phPrivateKey 
		);

	return rv;
}



/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_DEFINE_FUNCTION(CK_RV,C_WrapKey)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_WrapKey
		(
		hSession,        /* the session's handle */
		pMechanism,      /* the wrapping mechanism */
		hWrappingKey,    /* wrapping key */
		hKey,            /* key to be wrapped */
		pWrappedKey,     /* gets wrapped key */
		pulWrappedKeyLen /* gets wrapped key size */
		);

	return rv;
}



/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_DEFINE_FUNCTION(CK_RV,C_UnwrapKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_UnwrapKey
		(
		hSession,          /* session's handle */
		pMechanism,        /* unwrapping mech. */
		hUnwrappingKey,    /* unwrapping key */
		pWrappedKey,       /* the wrapped key */
		ulWrappedKeyLen,   /* wrapped key len */
		pTemplate,         /* new key template */
		ulAttributeCount,  /* template length */
		phKey              /* gets new handle */
		);

	return rv;
}



/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_DEFINE_FUNCTION(CK_RV,C_DeriveKey)
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_DeriveKey
		(
		hSession,          /* session's handle */
		pMechanism,        /* key deriv. mech. */
		hBaseKey,          /* base key */
		pTemplate,         /* new key template */
		ulAttributeCount,  /* template length */
		phKey              /* gets new handle */
		);

	return rv;
}




/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator. */
CK_DEFINE_FUNCTION(CK_RV,C_SeedRandom)
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_SeedRandom");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&ulSeedLen);
			d->packInt((char *)&pSeed);
			if (pSeed != NULL)
				d->packMem((char *)pSeed, ulSeedLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();

			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_SeedRandom ret: %d\n", rv);
#endif

exit:
	return rv;
}



/* C_GenerateRandom generates random data. */
CK_DEFINE_FUNCTION(CK_RV,C_GenerateRandom)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
	CK_RV rv = CKR_OK;

	{
		DataMarshalling *d = new DataMarshalling(client);
		d->setMsgType("C_GenerateRandom");
		{
			/*
			 * Open session
			 */
			DataMarshalling	*d2 = new DataMarshalling(client);

			d->packInt((char *)&hSession);
			d->packInt((char *)&ulRandomLen);
			d->packInt((char *)&RandomData);
			//if (RandomData != NULL)
			//	d->packMem((char *)RandomData, ulRandomLen);
			d->sendData();
			d2->recvData();
			if (strcmp(d2->getMsgType(), d->getMsgType())) {
				rv = CKR_CANCEL;
				goto exit;
			}
			rv = d2->unpackInt();
			if (RandomData != NULL)
				d2->unpackMem((char *)RandomData, ulRandomLen);
			delete d2;
		}
		delete d;
	}

#ifdef _DEBUG_PKCS11_
	fprintf(fout, "C_GenerateRandom ret: %d\n", rv);
#endif

exit:
	return rv;
}




/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application. */
CK_DEFINE_FUNCTION(CK_RV,C_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_GetFunctionStatus
		(
		hSession  /* the session's handle */
		);

	return rv;
}



/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel. */
CK_DEFINE_FUNCTION(CK_RV,C_CancelFunction)
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_CancelFunction
		(
		hSession  /* the session's handle */
		);

	return rv;
}




/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
CK_DEFINE_FUNCTION(CK_RV,C_WaitForSlotEvent)
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
	CK_RV rv = CKR_OK;

	rv = pFunctionList->C_WaitForSlotEvent
		(
		flags,        /* blocking/nonblocking flag */
		pSlot,  /* location that receives the slot ID */
		pRserved   /* reserved.  Should be NULL_PTR */
		);

	return rv;
}

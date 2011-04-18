#include <stdio.h>
#include <windows.h>
#include <atlstr.h>
#include <iostream>

#include "loadpkcs11.h"
#include "data2inet.h"

//#define FUNC_DEBUG_

extern CK_FUNCTION_LIST_PTR pFunctionList;

HINSTANCE hDLL;

CString byte2str(byte *bytes, int len)
{
	int 	pos = 0;
	CString ret;
	char 	pBuffer[100];

	for(int n = 0; n < len; n ++)
	{
		_itoa(bytes[n], pBuffer, 16);

		if(bytes[n] < 16)
		{
			ret.Insert(pos, "0");
			pos++;
			ret.Insert(pos, pBuffer);
			pos++;
		}
		else
		{
			ret.Insert(pos, pBuffer);
			pos+=2;
		}
	}

	ret.MakeUpper();
	return ret;
}

void
processRequest(int client)
{
	DataMarshalling	*d = NULL;

	while (1) {
		d = new DataMarshalling(client);
		d->recvData();
		if (!strcmp(d->getMsgType(), "C_Initialize")) {
			int	p = 0;
			printf("Processing: C_Initialize\n");
			p = d->unpackInt();
			if (p == 0)
				pFunctionList->C_Initialize(NULL);
			else {
				printf("ERROR: C_Initialize shouldn't be called with not NULL\n");
			}
		} else if (!strcmp(d->getMsgType(), "C_Finalize")) {
			int		p = 0;
			CK_RV	ret = 0;

			printf("Processing: C_Finalize\n");
			p = d->unpackInt();
			if (p == NULL) {
				ret = pFunctionList->C_Finalize(NULL);
			} else {
				printf("ERROR: C_Finalize shouldn't be called with not NULL\n");
				ret = CKR_CANCEL;
			}
			{
				CK_ULONG		count = 0;
				
				DataMarshalling	*d2 = new DataMarshalling(client);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
			break;
		} else if (!strcmp(d->getMsgType(), "C_GetSlotList")) {
			int	p = 0;
			printf("Processing: C_GetSlotList\n");
			p = d->unpackInt();
			if (p == 0) {
				CK_ULONG		count = 0;
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Retrieving Slots size
				 */
				ret = pFunctionList->C_GetSlotList(TRUE, NULL, &count);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&count);
				d2->sendData();
				delete d2;
			} else {
				CK_ULONG		count = 0;
				CK_SLOT_ID_PTR	slot = NULL;
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Retrieving Slots size
				 */
				pFunctionList->C_GetSlotList(TRUE, NULL, &count);
				slot = new(CK_SLOT_ID[count]);

				ret = pFunctionList->C_GetSlotList(TRUE, slot, &count);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&count);
				for (int i = 0; i < count; i ++)
					d2->packInt((char *)&slot[i]);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_OpenSession")) {
			unsigned int	slotId = 0, flags = 0;
			CK_SESSION_HANDLE	sessionId = 0;
			printf("Processing: C_OpenSession\n");
			slotId = d->unpackInt();
			flags = d->unpackInt();
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_OpenSession(slotId, flags, NULL, NULL, &sessionId);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&sessionId);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_CloseSession")) {
			CK_SESSION_HANDLE	sessionId = 0;
			printf("Processing: C_CloseSession\n");
			sessionId = d->unpackInt();
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_CloseSession(sessionId);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetInfo")) {
			unsigned int	slotId = 0, flags = 0;
			CK_SESSION_HANDLE	sessionId = 0;
			CK_INFO		info;
			printf("Processing: C_GetInfo\n");
			slotId = d->unpackInt();
			{
				CK_RV			ret = 0;
				CK_TOKEN_INFO	token;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_GetInfo(&info);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packChar(info.cryptokiVersion.major);
				d2->packChar(info.cryptokiVersion.minor);
				d2->packMem((char *)info.manufacturerID, 32);
				d2->packInt((char *)&info.flags);
				d2->packMem((char *)info.libraryDescription, 32);
				d2->packChar(info.libraryVersion.major);
				d2->packChar(info.libraryVersion.minor);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetSlotInfo")) {
			unsigned int	slotId = 0, flags = 0;
			CK_SESSION_HANDLE	sessionId = 0;
			printf("Processing: C_GetSlotInfo\n");
			slotId = d->unpackInt();
			{
				CK_RV			ret = 0;
				CK_SLOT_INFO	slot;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_GetSlotInfo(slotId, &slot);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packMem((char *)slot.slotDescription, 64);
				d2->packMem((char *)slot.manufacturerID, 32);
				d2->packInt((char *)&slot.flags);
				d2->packChar(slot.hardwareVersion.major);
				d2->packChar(slot.hardwareVersion.minor);
				d2->packChar(slot.firmwareVersion.major);
				d2->packChar(slot.firmwareVersion.minor);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetTokenInfo")) {
			unsigned int	slotId = 0, flags = 0;
			CK_SESSION_HANDLE	sessionId = 0;
			printf("Processing: C_GetTokenInfo\n");
			slotId = d->unpackInt();
			{
				CK_RV			ret = 0;
				CK_TOKEN_INFO	token;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_GetTokenInfo(slotId, &token);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packMem((char *)token.label, 32);
				d2->packMem((char *)token.manufacturerID, 32);
				d2->packMem((char *)token.model, 16);
				d2->packMem((char *)token.serialNumber, 16);
				d2->packInt((char *)&token.flags);
				d2->packInt((char *)&token.ulMaxSessionCount);
				d2->packInt((char *)&token.ulSessionCount);
				d2->packInt((char *)&token.ulMaxRwSessionCount);
				d2->packInt((char *)&token.ulRwSessionCount);
				d2->packInt((char *)&token.ulMaxPinLen);
				d2->packInt((char *)&token.ulMinPinLen);
				d2->packInt((char *)&token.ulTotalPublicMemory);
				d2->packInt((char *)&token.ulFreePublicMemory);
				d2->packInt((char *)&token.ulTotalPrivateMemory);
				d2->packInt((char *)&token.ulFreePrivateMemory);
				d2->packChar(token.hardwareVersion.major);
				d2->packChar(token.hardwareVersion.minor);
				d2->packChar(token.firmwareVersion.major);
				d2->packChar(token.firmwareVersion.minor);
				d2->packMem((char *)token.utcTime, 16);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetMechanismList")) {
			unsigned int	slotId = 0;
			CK_MECHANISM_TYPE_PTR	pMechanismList = NULL;
			printf("Processing: C_GetMechanismList\n");
			slotId = d->unpackInt();
			pMechanismList = (CK_MECHANISM_TYPE_PTR)d->unpackInt();
			if (pMechanismList == NULL) {
				CK_ULONG		count = 0;
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Retrieving Slots size
				 */
				ret = pFunctionList->C_GetMechanismList(slotId, pMechanismList, &count);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&count);
				printf("C_GetMechanismList count: %d\n", count);
				d2->sendData();
				delete d2;
			} else {
				CK_ULONG		count = 0;
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Retrieving Slots size
				 */
				pFunctionList->C_GetMechanismList(TRUE, NULL, &count);
				pMechanismList = new(CK_MECHANISM_TYPE[count]);

				ret = pFunctionList->C_GetMechanismList(slotId, pMechanismList, &count);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&count);
				printf("C_GetMechanismList count: %d\n", count);
				for (int i = 0; i < count; i ++)
					d2->packInt((char *)&pMechanismList[i]);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetMechanismInfo")) {
			unsigned int	slotId = 0, mechanismType = 0;
			printf("Processing: C_GetMechanismInfo\n");
			slotId = d->unpackInt();
			mechanismType = d->unpackInt();
			{
				CK_RV				ret = 0;
				CK_MECHANISM_INFO	mechanism;
				DataMarshalling	*d2 = new DataMarshalling(client);

				ret = pFunctionList->C_GetMechanismInfo(slotId, mechanismType, &mechanism);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&mechanism.ulMinKeySize);
				d2->packInt((char *)&mechanism.ulMaxKeySize);
				d2->packInt((char *)&mechanism.flags);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_Login")) {
			CK_SESSION_HANDLE	sessionId = 0;
			unsigned int		user = 0, len = 0;
			CK_CHAR_PTR			pin = NULL;

			printf("Processing: C_Login\n");

			sessionId = d->unpackInt();
			user = d->unpackInt();
			len = d->unpackInt();
			pin = (CK_CHAR_PTR) calloc(1, len + 1);
			if (!pin) {
				printf("ERROR: NO MEMORY\n");
				break;
			}
			d->unpackMem((char *)pin, len);
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_Login(sessionId, user, pin, len);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_Logout")) {
			CK_SESSION_HANDLE	sessionId = 0;

			printf("Processing: C_Logout\n");

			sessionId = d->unpackInt();
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_Logout(sessionId);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_FindObjectsInit")) {
			CK_SESSION_HANDLE	sessionId = 0;
			unsigned int		len = 0;
			CK_ATTRIBUTE_PTR	attr = NULL;

			printf("Processing: C_FindObjectsInit\n");

			sessionId = d->unpackInt();
			len = d->unpackInt();
			attr = (CK_ATTRIBUTE_PTR) calloc(len, sizeof(CK_ATTRIBUTE));
			if (!attr) {
				printf("ERROR: NO MEMORY\n");
				break;
			}
			for (int i = 0; i < len; i ++) {
				attr[i].type = d->unpackInt();
				attr[i].ulValueLen = d->unpackInt();
				attr[i].pValue = (char *)calloc(1, attr[i].ulValueLen);
				d->unpackMem((char *)attr[i].pValue, attr[i].ulValueLen);
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_FindObjectsInit(sessionId, attr, len);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_FindObjects")) {
			CK_SESSION_HANDLE	sessionId = 0;
			CK_OBJECT_HANDLE_PTR	phObject = NULL;
			CK_ULONG			len = 0, maxlen = 0;

			printf("Processing: C_FindObjects\n");

			sessionId = d->unpackInt();
			maxlen = d->unpackInt();
			if (maxlen > 0) {
				phObject = new(CK_OBJECT_HANDLE[maxlen]);
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_FindObjects(sessionId, phObject, maxlen, &len);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&len);
				for (int i = 0; i < len && i < maxlen; i ++)
					d2->packInt((char *)&phObject[i]);
				
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetAttributeValue")) {
			CK_SESSION_HANDLE	sessionId = 0;
			CK_OBJECT_HANDLE	hObject = 0;
			CK_ULONG			len = 0;
			CK_ATTRIBUTE_PTR	attr = NULL;

			printf("Processing: C_GetAttributeValue\n");

			sessionId = d->unpackInt();
			hObject = d->unpackInt();
			len = d->unpackInt();
			attr = (CK_ATTRIBUTE_PTR) calloc(len, sizeof(CK_ATTRIBUTE));
			if (!attr) {
				printf("ERROR: NO MEM C_GetAttributeValue\n");
				break;
			}
			for (int i = 0; i < len; i ++) {
				attr[i].type = d->unpackInt();
				attr[i].ulValueLen = d->unpackInt();
				attr[i].pValue = (char *)d->unpackInt();
				if (attr[i].pValue != NULL) {
					attr[i].pValue = (char *)calloc(1, attr[i].ulValueLen);
					if (!attr[i].pValue) {
						printf("ERROR: NO MEM\n");
						exit(-1);
					}
					//d->unpackMem((char *)attr[i].pValue, attr[i].ulValueLen);
				}
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);

				ret = pFunctionList->C_GetAttributeValue(sessionId, hObject, attr, len);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				for (int i = 0; i < len; i ++) {
					d2->packInt((char *)&attr[i].type);
					d2->packInt((char *)&attr[i].ulValueLen);
					d2->packInt((char *)&attr[i].pValue);
					if (attr[i].pValue != NULL) {
						d2->packMem((char *)attr[i].pValue, attr[i].ulValueLen);
#ifdef FUNC_DEBUG_
						if (i == 2) {
							PCCERT_CONTEXT	pCertContext;

							pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,((BYTE *)attr[i].pValue),attr[i].ulValueLen);
							printf("data len: %d\n", attr[i].ulValueLen);
							printf("issuer len: %d\n", pCertContext->pCertInfo->Issuer.cbData);
							std::wcout << byte2str(pCertContext->pCertInfo->Issuer.pbData, pCertContext->pCertInfo->Issuer.cbData);
							CertFreeCertificateContext(pCertContext);
						}
		
#endif
					}
				}
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_FindObjectsFinal")) {
			CK_SESSION_HANDLE	sessionId = 0;

			printf("Processing: C_FindObjectsFinal\n");

			sessionId = d->unpackInt();
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_FindObjectsFinal(sessionId);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_SignInit")) {
			CK_SESSION_HANDLE	sessionId = 0;
			CK_MECHANISM		mechanism;
			CK_OBJECT_HANDLE	hKey;

			printf("Processing: C_SignInit\n");

			sessionId = d->unpackInt();
			hKey = d->unpackInt();
			mechanism.mechanism = d->unpackInt();
			mechanism.ulParameterLen = d->unpackInt();
			mechanism.pParameter = NULL;
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_SignInit(sessionId, &mechanism, hKey);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_Sign")) {
			CK_SESSION_HANDLE	sessionId = 0;
			char				*data = NULL, *signature = NULL;
			CK_ULONG			dataLen = 0, signatureLen = 0;

			printf("Processing: C_Sign\n");

			sessionId = d->unpackInt();
			dataLen = d->unpackInt();
			data = (char *)d->unpackInt();
			if (data != NULL) {
				data = (char *)calloc(1, dataLen);
				if (!data) {
					printf("ERROR: NO MEM C_Sign\n");
					break;
				}
				d->unpackMem((char *)data, dataLen);
			}
			signatureLen = d->unpackInt();
			signature = (char *)d->unpackInt();
			if (signature != NULL) {
				signature = (char *)calloc(1, signatureLen);
				if (!signature) {
					printf("ERROR: NO MEM C_Sign\n");
					break;
				}
				d->unpackMem((char *)signature, signatureLen);
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_Sign(sessionId, (CK_BYTE_PTR)data, dataLen, (CK_BYTE_PTR)signature, &signatureLen);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&signatureLen);
				if (signature != NULL)
					d2->packMem((char *)signature, signatureLen);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_VerifyInit")) {
			CK_SESSION_HANDLE	sessionId = 0;
			CK_MECHANISM		mechanism;
			CK_OBJECT_HANDLE	hKey;

			printf("Processing: C_VerifyInit\n");

			sessionId = d->unpackInt();
			hKey = d->unpackInt();
			mechanism.mechanism = d->unpackInt();
			mechanism.ulParameterLen = d->unpackInt();
			mechanism.pParameter = NULL;
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_VerifyInit(sessionId, &mechanism, hKey);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_Verify")) {
			CK_SESSION_HANDLE	sessionId = 0;
			char				*data = NULL, *signature = NULL;
			CK_ULONG			dataLen = 0, signatureLen = 0;

			printf("Processing: C_Verify\n");

			sessionId = d->unpackInt();
			dataLen = d->unpackInt();
			data = (char *)d->unpackInt();
			if (data != NULL) {
				data = (char *)calloc(1, dataLen);
				if (!data) {
					printf("ERROR: NO MEM C_Verify\n");
					break;
				}
				d->unpackMem((char *)data, dataLen);
			}
			signatureLen = d->unpackInt();
			signature = (char *)d->unpackInt();
			if (signature != NULL) {
				signature = (char *)calloc(1, signatureLen);
				if (!signature) {
					printf("ERROR: NO MEM C_Verify\n");
					break;
				}
				d->unpackMem((char *)signature, signatureLen);
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_Verify(sessionId, (CK_BYTE_PTR)data, dataLen, (CK_BYTE_PTR)signature, signatureLen);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GenerateRandom")) {
			CK_SESSION_HANDLE	sessionId = 0;
			char				*data = NULL;
			CK_ULONG			dataLen = 0;

			printf("Processing: C_GenerateRandom\n");

			sessionId = d->unpackInt();
			dataLen = d->unpackInt();
			data = (char *)d->unpackInt();
			if (data != NULL) {
				data = (char *)calloc(1, dataLen);
				if (!data) {
					printf("ERROR: NO MEM C_GenerateRandom\n");
					break;
				}
				//d->unpackMem((char *)data, dataLen);
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_GenerateRandom(sessionId, (CK_BYTE_PTR)data, dataLen);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				if (data != NULL)
					d2->packMem((char *)data, dataLen);
				d2->sendData();
				delete d2;
			}
		}  else if (!strcmp(d->getMsgType(), "C_SeedRandom")) {
			CK_SESSION_HANDLE	sessionId = 0;
			char				*data = NULL;
			CK_ULONG			dataLen = 0;

			printf("Processing: C_SeedRandom\n");

			sessionId = d->unpackInt();
			dataLen = d->unpackInt();
			data = (char *)d->unpackInt();
			if (data != NULL) {
				data = (char *)calloc(1, dataLen);
				if (!data) {
					printf("ERROR: NO MEM C_SeedRandom\n");
					break;
				}
				d->unpackMem((char *)data, dataLen);
			}
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_SeedRandom(sessionId, (CK_BYTE_PTR)data, dataLen);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_GetSessionInfo")) {
			CK_SESSION_HANDLE	sessionId = 0;

			printf("Processing: C_GetSessionInfo\n");
			sessionId = d->unpackInt();
			{
				CK_RV			ret = 0;
				CK_SESSION_INFO	info;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_GetSessionInfo(sessionId, &info);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->packInt((char *)&info.slotID);
				d2->packInt((char *)&info.state);
				d2->packInt((char *)&info.flags);
				d2->packInt((char *)&info.ulDeviceError);
				d2->sendData();
				delete d2;
			}
		} else if (!strcmp(d->getMsgType(), "C_CloseAllSessions")) {
			CK_SLOT_ID	slotID = 0;

			printf("Processing: C_Logout\n");

			slotID = d->unpackInt();
			{
				CK_RV			ret = 0;
				DataMarshalling	*d2 = new DataMarshalling(client);
				/*
				 * Opening session
				 */
				ret = pFunctionList->C_CloseAllSessions(slotID);
				d2->setMsgType(d->getMsgType());
				d2->packInt((char *)&ret);
				d2->sendData();
				delete d2;
			}
		} else {
			pFunctionList->C_Finalize(NULL);
		}
		delete d;
	}
}

int
main(int argc, char *argv[])
{
	SOCKET	client, server;
	
	if (loadPKCS11dll(TARGET_DLL) == -1)
		printf("ERROR");

	// Init socket server
	{
		WSADATA				wsaData;
		WORD				version;
		int					error, len;
		struct sockaddr_in	sock, sin;

		version = MAKEWORD(2, 0);

		error = WSAStartup(version, &wsaData);
		if (error) {
			perror("WSAStartup(): ");
			return -1;
		}

		if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket()");
			return -1;
		}

		memset(&sock, 0, sizeof(sock));

		sock.sin_family = AF_INET;
		sock.sin_addr.s_addr = INADDR_ANY; //inet_addr("127.0.0.1");
		sock.sin_port = htons(1024 + 666);

		if (bind(server, (struct sockaddr *)&sock, sizeof(sock)) == SOCKET_ERROR) {
			perror("bind()");
			return -1;
		}

		listen(server, 5);

		len = sizeof(sin);
		client = accept(server, (struct sockaddr *)&sin, &len);
	}
	// Create entry function evaluate type of message to perform actions

	processRequest(client);
}
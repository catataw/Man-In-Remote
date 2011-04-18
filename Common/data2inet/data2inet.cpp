#include <memory.h>
#include <windows.h>
#include <stdio.h>

#include "data2inet.h"

//#define _DM_DEBUG_

/*
 * TODO:
 * - Error management
 * - Endianess independence
 */

DataMarshalling::DataMarshalling(int socket)
{
	this->client = socket;
	this->len = 0;
	this->d2recv = this->d2send = this->recvp = NULL;
	memset(this->msg, 0x0, sizeof(this->msg));
}

DataMarshalling::~DataMarshalling()
{
	if (this->recvp != NULL)
		free(this->recvp);

	if (this->d2send != NULL)
		free(this->d2send);
}

void
DataMarshalling::printSendData()
{
	for (int i = 0; i < this->len; i ++)
		printf("%x ", this->d2send);
	printf("\n");
}

void
DataMarshalling::printRecvData()
{
	for (int i = 0; i < this->len; i ++)
		printf("%x ", this->d2recv);
	printf("\n");
}

void
DataMarshalling::sendData()
{
	if (send(this->client, (char *)this->msg, sizeof(this->msg), 0) < 0)
		return;
	
	if (send(this->client, (char *)&this->len, sizeof(this->len), 0) < 0)
			return;

	if ((this->len > 0) && (this->d2send != NULL)) {
		if (send(this->client, (char *)this->d2send, this->len, 0) < 0)
			return;
	}
}

void
DataMarshalling::recvData()
{
	if (recv(this->client, (char *)&this->msg, sizeof(this->msg), 0) < 0)
		return;

	if (recv(this->client, (char *)&this->len, sizeof(this->len), 0) < 0)
		return;

	if ((this->len > 0)) {
		this->recvp = this->d2recv = (char *)calloc(1, this->len + 1);
		if (!this->d2recv)
			return;

		{
			int	ret = 0, read = 0, rem = this->len;

			while (rem > 0) {
				if ((ret = recv(this->client, (char *)this->d2recv + read, rem, 0)) < 0)
					return;
				rem -= ret;
				read += ret;
			}
		}
	}
}

void
DataMarshalling::setMsgType(char *msg)
{
	strncpy(this->msg, msg, 127);
	this->msg[127] = 0x0;
}

char *
DataMarshalling::getMsgType()
{
	return this->msg;
}

int
DataMarshalling::packInt(char *data)
{
	this->DMAlloc(4);

	for (int i = 0; i < 4; i ++)
		this->byte2hex(data[i], this->d2send);
	
	return 4;
}

int
DataMarshalling::packMem(char *data, int len)
{
	this->DMAlloc(len);

	for (int i = 0; i < len; i ++)
		this->byte2hex(data[i], this->d2send);

	return len;
}

int
DataMarshalling::packChar(char data)
{
	this->DMAlloc(1);

	this->byte2hex(data, this->d2send);

	return 1;
}

int
DataMarshalling::unpackInt()
{
	int	ret = 0;

	for (int i = 0; i < 4; i ++, this->d2recv += 2) {
		ret |= (this->hex2byte(this->d2recv) << (8 * i)) & (0xFF << (8 * i));
	}

	return ret;
}

void
DataMarshalling::unpackMem(char *out, int len)
{
	int ret = 0;

	for (int i = 0; i < len; i ++, this->d2recv += 2) {
		out[i] = this->hex2byte(this->d2recv) & 0xFF;
	}
}

char
DataMarshalling::unpackChar()
{
	char	ret = 0;

	ret = this->hex2byte(this->d2recv) & 0xFF;
	this->d2recv += 2;

	return ret;
}

char
DataMarshalling::hex2byte(char *in)
{
	char	tmp = 0;

	if (in[0] <= '9')
		tmp = (in[0] - '0') << 4;
	else
		tmp = ((in[0] - 'A') + 0xA) << 4;

	if (in[1] <= '9')
		tmp |= (in[1] - '0') & 0x0F;
	else
		tmp |= ((in[1] - 'A') + 0xA) & 0x0F;

	return tmp;
}

void
DataMarshalling::byte2hex(char byte, char *out)
{
	char	tmp[3];

	tmp[0] = (byte & 0xF0) >> 4;
	if (tmp[0] <= 9)
		tmp[0] += '0';
	else
		tmp[0] = 'A' + (tmp[0] - 10);

	tmp[1] = (byte & 0x0F);
	if (tmp[1] <= 9)
		tmp[1] += '0';
	else
		tmp[1] = 'A' + (tmp[1] - 10);
	
	tmp[2] = 0x0;

	strcat(out, tmp);
}


void
DataMarshalling::DMAlloc(int size)
{
	char	*newp = NULL;
	int		tmp = this->len + (size * 2) + 1;

	if ((newp = (char *)realloc(this->d2send, tmp)) == NULL) {
		if (this->d2send != NULL)
			free(this->d2send);
		this->d2send = NULL;
		this->len = 0;
	}
	this->d2send = newp;
	newp = this->d2send + this->len;
	memset(newp, 0x0, tmp - this->len);
#ifdef _DM_DEBUG_
	for (int i = 0; i < tmp; i ++)
		printf("%x ", this->d2send[i]);
	printf("\n");
#endif
	this->len = tmp;
}
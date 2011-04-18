#ifndef _DATA2INET_H_
#define _DATA2INET_H_

class DataMarshalling {
public:
	DataMarshalling(int socket);
	~DataMarshalling();


	void	recvData();
	void	sendData();

	char	*getMsgType();
	void	setMsgType(char *msg);

	/*
	 * (un)pack data and returns number of bytes packed
	 */
	int		packInt(char *data);
	int		packuInt(char *data);
	int		packMem(char *data, int len);
	int		packChar(char data);

	int		unpackInt();
	unsigned int unpackuInt();
	void	unpackMem(char *out, int len);
	char	unpackChar();

	void	printSendData();
	void	printRecvData();
private:
	void	DMAlloc(int size);

private:
	void	byte2hex(char byte, char *out);
	char	hex2byte(char *in);

private:
	int		client;
	char	msg[128];
	int		len;
	char	*d2send, *d2recv, *recvp;
	
};

#endif /* _DATA2INET_H_ */
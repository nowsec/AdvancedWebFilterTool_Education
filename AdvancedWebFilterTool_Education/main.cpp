/*						�߿����																*/
//	1. ȣ��Ʈ�� ��Ʋ��������� �����͸� ������ ��Ʈ��ũ�� �򿣵�� ������� �����͸� ó���Ѵ�.  //
////////////////////////////////////////////////////////////////////////

#define _CRT_SECURE_NO_WARNINGS		// ���� ��� ����

#include <stdio.h>			// ����� �Լ� ����� ���� ��� �߰�
#include <stdlib.h>			// ���ڿ� �Լ� ����� ���� ��� �߰�

#include "windivert.h"		// windivert �Լ����� ����ϱ� ���� ��� �߰�

#define MAXBUF 0xFFFF		// ���۰��� �ִ� ũ��
#define MAXURL 4096			// URL�� �ִ� ũ��

/*
* URL and blacklist representation.
*/
typedef struct url			// url ����ü�� �ȿ� domain�� uri ����
{							// www.naver.com/ko/index.nhn �̷��� �ּҰ� ���� ��
	char *domain;			// www.naver.com�� ������
	char *uri;				// ko/index.nhn�� uri (���ͳݿ� �ִ� �ڿ��� ��Ÿ���� ������ �ּ�)
} URL, *PURL;

typedef struct blacklist		// ������ ����Ʈ���� ����Ʈ�� ����üȭ 
{
	UINT size;					// ����Ʈ�� �� �� �ִ� �ִ� list ����
	UINT length;				// ����Ʈ�� �� list ����
	PURL *urls;					// blacklist�� ��ϵ� url
} BLACKLIST, *PBLACKLIST;

/*
* Pre-fabricated packets.
*/
typedef struct ipandtcp			// ip�� tcp�� ����� ����üȭ
{
	WINDIVERT_IPHDR  ip;		// ip�� ���
	WINDIVERT_TCPHDR tcp;		// tcp�� ���
} PACKET, *PPACKET;
typedef struct datapacket
{
	PACKET header;				// ������ ��Ŷ�� ���
	UINT8 data[];				// ������ ��Ŷ�� ������
} DATAPACKET, *PDATAPACKET;

const char block_data[] =				// blocklist�� ��ϵ� ����Ʈ�� ������ ��� block_data�� ���� ������ ����
"HTTP/1.1 200 OK\r\n"					// HTTP 1.1 �������� 200 : ��û ���� https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html �� ��ȣ�� ���� ������ ����Ʈ ���� 
"Connection: close\r\n"					// ������ ����
"Content-Type: text/html\r\n"			// ���� Ÿ�� text http://hbesthee.tistory.com/45
"\r\n"
"<!doctype html>\n"						// DOCTYPE�̶�, HTML ������ �����Ҷ� �� ������ html �����̰� ������� ��������� �� ������ �´� ������� �ؼ��ض�� ���������� �˷��ִ� ���� http://changeroom.blog.me/220452343759
"<html>\n"								// html������ �˸�, html�̶� �� ������ ����� ���Ͽ� ����ϴ� �⺻���� ���α׷��� ����� �� ����
"\t<head>\n"							// <head>�±״� ������ ����, ��Ÿ ����, ��ũ��Ʈ, ��Ÿ�� ��Ʈ ���� ��Ҹ� ������ �� ����
"\t\t<title>BLOCKED!</title>\n"			// ������ ������ ������ ����
"\t</head>\n"							// </head> ���� ������ ����� ��
"\t<body>\n"							// HTML body �±״� HTML �������� ������ �̷�� �κ�
"\t\t<h1>BLOCKED!</h1>\n"				// <h1> to <h6> �±״� ������ ���� ����
"\t\t<hr>\n"							// hr ���м� ����
"\t\t<p>This URL has been blocked!</p>\n"		// <p></p>�±״� ������ �����ϴ� �±�
"\t</body>\n"									// </body> �ٵ� �κ� ����
"</html>\n";									// </html> html ����

/*
* Prototypes
*/
bool mal_site_state;												// ������ ����Ʈ�� ���ػ���Ʈ�� true �ƴϸ� false
char blockedDomain[MAXURL];											// block�� �������� �ּҸ� ��� ����

void PacketInit(PPACKET packet);									// ��Ŷ �ʱ�ȭ �Լ�
int __cdecl UrlCompare(const void *a, const void *b);				// blacklist�� ����ִ� url���� ���Ľ�Ű�� ���� �� �Լ�
int UrlMatch(PURL urla, PURL urlb);									// ������ url�� blacklist�� ���Ե� url���� �� �Լ�
PBLACKLIST BlackListInit(void);										// blacklist �ʱ�ȭ �Լ�
void BlackListInsert(PBLACKLIST blacklist, PURL url);				// �� ��° ������ url�� blacklist�� �߰�
void BlackListSort(PBLACKLIST blacklist);							// blacklist�� �ִ� ����Ʈ���� ���ĺ� ������ ����
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);				// blacklist�� �ִ� ����Ʈ�� ������ ����Ʈ ��
void BlackListRead(PBLACKLIST blacklist, const char *filename);		// ���� �̸��� �о� �ȿ� �ִ� �ּҵ��� blacklist�� ���
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site);			// ��Ŷ�� ���̷ε� �κ� ��, ���� �κп��� �ڼ��� ����

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	FILE *f_log_txt;						// �α� ������ �������� ����
	HANDLE handle;							// WinDivertOpen�� �ڵ� ���� ������
	WINDIVERT_ADDRESS addr;					// Packet's interface index, Packet's sub-interface index, Packet's direction ������ ���� ����                               
	UINT8 packet[MAXBUF];					// ������ ��Ŷ�� ���� �迭
	UINT packet_len;						// ��Ŷ�� ����
	PWINDIVERT_IPHDR ip_header;				// ip ���
	PWINDIVERT_TCPHDR tcp_header;			// tcp ���
	PVOID payload;							// ���̷ε� : ��ſ� �ʿ����������� ��
	UINT payload_len;						// ���̷ε� ����
	PACKET reset0;							// �ʱ�ȭ�� ��Ŷ
	PPACKET reset = &reset0;				// �ʱ�ȭ�� ��Ŷ
	PACKET finish0;							// Flag���� fin�� ���Ե� ��Ŷ
	PPACKET finish = &finish0;				// Flag���� fin�� ���Ե� ��Ŷ
	PDATAPACKET blockpage;					// ���� �������� ��Ŷ ������
	UINT16 blockpage_len;					// ���� ������ ����
	PBLACKLIST blacklist;					// ���� ������ ����Ʈ
	unsigned i;
	INT16 priority = 404;       // Arbitrary.
	mal_site_state = false;					//  
	char buf[1024] = { 0, };
	// Read the blacklists.

	blacklist = BlackListInit();			// ������Ʈ�� �ʱ�ȭ

	BlackListRead(blacklist, "mal_site.txt");		// mal_site.txt�� ����ִ� url�� blacklist�� ����

	BlackListSort(blacklist);						// blacklist�ȿ� �ִ� �����͸� ����

	// Initialize the pre-frabricated packets:
	blockpage_len = sizeof(DATAPACKET)+sizeof(block_data)-1;		// block �������� ���� ������ ����
	blockpage = (PDATAPACKET)malloc(blockpage_len);					// block �������� ���� �޸� �Ҵ�(�������� ������ ���� ��ŭ)
	if (blockpage == NULL)											// blockpage�� ���� �޸� �Ҵ��� �������� ��� exit
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);									// block�������� ��� �ʱ�ȭ
	blockpage->header.ip.Length = htons(blockpage_len);				// htons ��Ʋ������� �򿣵������ ��ȯ�Ͽ� �־��ش�
	blockpage->header.tcp.SrcPort = htons(80);						// ��Ʈ 80���� ��Ʈ��ũ ������ �򿣵������ ��ȯ�Ͽ� �־��ش�(htons)
	blockpage->header.tcp.Psh = 1;									// tcp ��� �÷��� ���� http://www.ktword.co.kr/abbr_view.php?m_temp1=2437
	blockpage->header.tcp.Ack = 1;									// Psh ��ٸ��� �ʰ� Ǫ��, Ack ����Ǿ����� Ȯ��
	memcpy(blockpage->data, block_data, sizeof(block_data)-1);		// block_data�� block page�� ������ �����Ϳ� ����
	PacketInit(reset);												// reset ��Ŷ �ʱ�ȭ
	reset->tcp.Rst = 1;												// Rst ������ ������ ����
	reset->tcp.Ack = 1;												// ���� flag 1�� ����
	PacketInit(finish);												// finish ��Ŷ�� �ʱ�ȭ
	finish->tcp.Fin = 1;											// Fin flag : ��Ŷ ������ ���������� ����, Rst�� ���� ����
	finish->tcp.Ack = 1;											// ���� flag 1�� ����

	// Open the Divert device:
	handle = WinDivertOpen(											// WinDivert�� �����Ͽ� �ڵ鰪�� handle�� �ѱ�
		"outbound && "              // Outbound traffic only		// ���� ���� ���� ������ ��Ŷ ��
		"ip && "                    // Only IPv4 supported			// �������̸鼭
		"tcp.DstPort == 80 && "     // HTTP (port 80) only			// tcp ������ ��Ʈ�� 80
		"tcp.PayloadLength > 0",    // TCP data packets only		// ���̷ε� ���̰� 0�� �Ѵ� ��Ŷ�� ���͸���
		WINDIVERT_LAYER_NETWORK, priority, 0						// WINDIVERT_LAYER_NETWORK ��Ʈ��ũ ���̾�� ������
		);
	if (handle == INVALID_HANDLE_VALUE)								// WinDivertOpen�� ����� ���� �ʾ����� ����
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");									// ����� ���� �Ǿ����� "OPENED WinDivert" ���

	// Main loop:
	while (TRUE)													// ���ѷ����� ���� ��������� ��Ŷ�� ����
	{
		f_log_txt = fopen("log.txt", "a");							// �α� ���� ����� ���� log.txt ����

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))		//������ Open�� ���� ���� �������� ��Ŷ�� ����
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,			//WinDivertHelperParsePacket ������ ��Ŷ���� �ֿ� �������� ���� ip, tcp ��� ���
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char*)payload, (UINT16)payload_len, blockedDomain))		//������ ��Ŷ���� ����Ʈ ������ �����Ͽ� blocklist ����Ʈ���� üũ
		{
			// Packet does not match the blacklist; simply reinject it.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))					//������ ����Ʈ�� ���� ����Ʈ�� �ƴ� ���
			{																				//������ ��Ŷ�� �ٽ� send�ϰ� while������ ���ư�
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.

		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		// ������ ��Ŷ�� ���ػ���Ʈ�� ��� flag rst�� �־� ������ �����ϴ� ��Ŷ ���� out bound

		reset->ip.SrcAddr = ip_header->SrcAddr;			// Src �ּҿ� Dst �ּҸ� ����
		reset->ip.DstAddr = ip_header->DstAddr;			// ������ ��Ŷ�� �ٽ� ������ ������ ����
		reset->tcp.SrcPort = tcp_header->SrcPort;		// Src��Ʈ�� �״�� �־��ָ� 
		reset->tcp.DstPort = htons(80);					// Dst ��Ʈ�� 80���� �־���
		reset->tcp.SeqNum = tcp_header->SeqNum;			// SeqNum�� AckNum ���� �״�� �־���
		reset->tcp.AckNum = tcp_header->AckNum;			// SeqNum�� AckNum�� �ſ� �߿��� �κ��̹Ƿ� ���� �����غ��� �ٶ�, �󸶸�ŭ�� �����͸� �ְ� �޾Ҵ��� �� �κ��� ���� üũ ���� + �ٸ� ������Ʈ���� ���� �ڼ��� �ٷ� ���� 
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);		//ip����� tcp ����� üũ�� ���� ����Ͽ� �־���
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))		//������ ������ �����Ű�� reset ��Ŷ ����
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) Send the blockpage to the browser:
		//���ػ���Ʈ�� ��� src, dst ������ �ٲ� ������ block data�� �ѷ��� in bound

		blockpage->header.ip.SrcAddr = ip_header->DstAddr;							// src �ּҿ� dst �ּҸ� ����
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;						// Src ��Ʈ�� Dst ��Ʈ�� ����			
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;							// Seq�ѹ� ���� AckNum�� �־��ָ�
		blockpage->header.tcp.AckNum =												// AckNum���� ������ SeqNum�� ������ ���̷ε��� ���� ���ؼ� AckNum�� �־���
			htonl(ntohl(tcp_header->SeqNum) + payload_len);							// �̺κ� ���� �߿�!! ���� Seq, Ack�ѿ� ���� ������ �� 
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);			// blockpage ��Ŷ�� ���� checksum �� ���
		addr.Direction = !addr.Direction;     // Reverse direction.					// ��Ŷ�� ���⿡�� in bound(1), out bound(0) �� ����
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,			// ������ blockpage ��Ŷ�� ����
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		// (3) Send a TCP FIN to the browser; closing the connection at the 
		//     browser's end.
		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data)-1);				// seq�� ack num�� block data�� ���̸� ���� ���� ���� 
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);							// ack�� ó���� ������ ���̷ε��� ���̸�ŭ�� seq�� ���� ���� ����
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);				// finish ��Ŷ�� checksum �� ���
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))		// ���Ḧ ���� fin packet ����
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}

		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;							// ������ ����� ��Ŷ�� src�� dst �����Ǹ� ���
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fprintf(f_log_txt, "BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", blockedDomain,		// ������ ����� ��Ŷ�� src�� dst ������, �������� log.txt�� ���
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fclose(f_log_txt);		//��� �Ϸ��� ���� ����
		}

	}
}

void PacketInit(PPACKET packet)					// ��Ŷ�� �ʱ�ȭ�� ���� �Լ�
{
	memset(packet, 0, sizeof(PACKET));			// ��Ŷ�� 0���� �ʱ�ȭ
	packet->ip.Version = 4;						// ��Ŷ ������ 4
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);	// ������ ������� 20
	packet->ip.Length = htons(sizeof(PACKET));							// �⺻ ip length�� 40
	packet->ip.TTL = 64;												// �⺻ TTL 64
	packet->ip.Protocol = IPPROTO_TCP;									// �������� Ÿ�� TCP
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);		//tcp ������� 20
}

/*
* Initialize an empty blacklist.
*/
PBLACKLIST BlackListInit(void)		// blacklist�� �ʱ�ȭ
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));	// blacklist �������� 40�޸� �Ҵ�
	UINT size;
	int d = sizeof(PURL);
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;													// �� �� �ִ� size�� 1024
	blacklist->urls = (PURL *)malloc(size*sizeof(PURL));			// url 8 x 1024 �޸� �Ҵ�
	if (blacklist->urls == NULL)									// blacklist->urls == NULL�̸� �޸� �Ҵ� ����
	{
		goto memory_error;
	}
	blacklist->size = size;											// ������ 1024 
	blacklist->length = 0;											// ���� 0
																	// ���⼭ ������� �ִ� �� �� �ִ� list ���� length�� ���� ���ִ� list ������ �ǹ�
	return blacklist;												// ����ü�� ��ȯ

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}

/*
* URL comparison.
*/
int __cdecl UrlCompare(const void *a, const void *b)		// ������ url�� blacklist�� ���Ե� url���� �� �Լ�
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);			// strcmp�Լ��� ���� url domain ���� retrun ������ �Ѱ���
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);					// domain�� ���ٸ� url�� ���Ͽ� ��ȯ
}

/*
* Sort the blacklist (for searching).
*/
void BlackListSort(PBLACKLIST blacklist)					// blacklist�� �� �ִ� ����Ʈ���� qsort�� ���� ����
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* URL matching
*/
static int UrlMatch(PURL urla, PURL urlb)					// ������ ����Ʈ�� ���ػ���Ʈ���� üũ�ϴ� �Լ�
{															// ���ڵ��� �ϳ��ϳ� ���ذ��� mal_site.txt�� �����ִ� �ּҿ� ������ üũ
	UINT16 i;

	for (i = 0; urla->domain[i] && urlb->domain[i]; i++)
	{
		int cmp = (int)urlb->domain[i] - (int)urla->domain[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->domain[i] == '\0' && urlb->domain[i] != '\0')
	{
		return 1;
	}

	for (i = 0; urla->uri[i] && urlb->uri[i]; i++)
	{
		int cmp = (int)urlb->uri[i] - (int)urla->uri[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->uri[i] == '\0' && urlb->uri[i] != '\0')
	{
		return 1;
	}
	return 0;
}

/*
* Match a URL against the blacklist.
*/
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)	// ������ ����Ʈ�� ���ػ���Ʈ���� üũ�ϴ� �Լ�
{													// �̺κе� UrlMatch�� ��� ������ �� ������ �� �� �м��� �ʿ䰡 ����
	int lo = 0, hi = ((int)blacklist->length) - 1;

	while (lo <= hi)
	{
		INT mid = (lo + hi) / 2;
		int cmp = UrlMatch(url, blacklist->urls[mid]);
		if (cmp > 0)
		{
			hi = mid - 1;
		}
		else if (cmp < 0)
		{
			lo = mid + 1;
		}
		else
		{
			return TRUE;			// �̺κп��� ��������� ���ػ���Ʈ�� ������ True
		}
	}
	return FALSE;					// �ٸ��� Flase�� ��ȯ
}


/*
* Insert a URL into a blacklist.
*/
void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)		//�� list�� �ִ� ũ���� 1024�� �ʰ��� ��� �޸𸮸� ���Ҵ� �Ͽ� ũ�⸦ �ø� 
	{
		blacklist->size = (blacklist->size * 3) / 2;
		printf("GROW blacklist to %u\n", blacklist->size);
		blacklist->urls = (PURL *)realloc(blacklist->urls,
			blacklist->size*sizeof(PURL));
		if (blacklist->urls == NULL)
		{
			fprintf(stderr, "error: failed to reallocate memory\n");
			exit(EXIT_FAILURE);
		}
	}

	blacklist->urls[blacklist->length++] = url;		//blacklist�� url�� �߰��ϴ� �κ�
}


/*
* Read URLs from a file.
*/
void BlackListRead(PBLACKLIST blacklist, const char *filename)		//�ι�° ������ ������ �о�鿩 blacklist�� ���� 
{
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");								//������ ����

	if (file == NULL)												//������ ������ ������ ����
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}

	// Read URLs from the file and add them to the blacklist: 
	while (TRUE)
	{
		while (isspace(c = getc(file)))			//isspace �����̽����� �ƴ��� üũ
			;
		if (c == EOF)							//���� ������ üũ
		{
			break;
		}
		if (c != '-' && !isalnum(c))			//�����̸鼭 '-' ���̸� true ,isalnum : ���ĺ� �Ǵ� �����̸� 0�� �ƴ� �� ��ȯ
		{
			while (!isspace(c = getc(file)) && c != EOF)		//isspace ������ �ƴϸ� 0�� �ƴ� ���� ��ȯ�Ѵ�.
				;
			if (c == EOF)
			{
				break;
			}
			continue;
		}
		i = 0;
		domain[i++] = (char)c;
		while ((isalnum(c = getc(file)) || c == '-' || c == '.') && i < MAXURL)		//isalnum ���ڳ� ���ڰ� �ƴϸ� 0�� �ƴ� ���� ����.
		{
			domain[i++] = (char)c;													//���Ͽ��� �о���� ���ػ���Ʈ�� domain �迭�� ����
		}
		domain[i] = '\0';															//�迭 �������� \0 �� �߰�
		j = 0;
		if (c == '/')																// '/'�� �������� �ڿ� uri ���� ������
		{
			while (!isspace(c = getc(file)) && c != EOF && j < MAXURL)
			{
				uri[j++] = (char)c;
			}
			uri[j] = '\0';
		}
		else if (isspace(c))
		{
			uri[j] = '\0';
		}
		else
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			continue;
		}

		printf("ADD %s/%s\n", domain, uri);											// mal_site.txt�� �ִ� domain�� uri ���

		url = (PURL)malloc(sizeof(URL));											// url �κ� �������� �޸� �Ҵ�
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1)*sizeof(char));							//�տ��� ����� ��ŭ domain �޸� ���� �Ҵ�
		url->uri = (char *)malloc((j + 1)*sizeof(char));							//�տ��� ����� ��ŭ uri �޸� ���� �Ҵ�
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];										// url�κп��� �ּҸ� �Ųٷ� ���� ex) nate.com -> moc.etan 
		}																			// ȣ��Ʈ���� ��Ʈ��ũ�� �о���̴� ����� �ٸ� 
		url->domain[j] = '\0';														// ��Ʈ��ũ�� �򿣵��
																					// ȣ��Ʈ�� ��Ʋ�����
		BlackListInsert(blacklist, url);
	}

	fclose(file);
	return;

memory_error:
	fprintf(stderr, "error: memory allocation failed\n");
	exit(EXIT_FAILURE);
}

/*
* Attempt to parse a URL and match it with the blacklist.
*
* BUG:
* - This function makes several assumptions about HTTP requests, such as:
*      1) The URL will be contained within one packet;
*      2) The HTTP request begins at a packet boundary;
*      3) The Host header immediately follows the GET/POST line.
*   Some browsers, such as Internet Explorer, violate these assumptions
*   and therefore matching will not work.
*/

/*
* modify strcpy function.
*/
void mystrcpy(unsigned char *dest, unsigned char *src)			//unsigned char* ���ڿ� ���縦 ���� strcpy�Լ� ����
{
	int index = 0;
	// ������ NULL �̰ų� ����� NULL �̸� ����

	if (!src || !dest) exit(1);
	while ((*(src + index) != 13)){
		*(dest + index) = *(src + index);
		index++;

	}
	*(dest + index) = '\n';
	*(dest + index) = '\0';
}

/*
* modify strstr function.
*/
char *findStr(unsigned char *str1, char *str2)		//unsigned char* ���ڿ� ã�� ���� strstr�Լ� ����
{
	char *cp = (char *)str1;
	char *s1, *s2;

	if (!*str2) return (char *)str1;

	while (*cp)
	{
		s1 = cp;
		s2 = (char *)str2;

		while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
		if (!*s2) return cp;
		cp++;
	}
}


BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site)		//������ ����Ʈ�� Blacklist�� ���Ͽ� true, false�� ��ȯ
{
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	URL url = { domain, uri };
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;

	if (len <= sizeof(post_str)+sizeof(http_host_str))
	{
		return FALSE;
	}
	if (strncmp(data, get_str, sizeof(get_str)-1) == 0)			//GET ������� POST ������� üũ
	{
		i += sizeof(get_str)-1;
	}
	else if (strncmp(data, post_str, sizeof(post_str)-1) == 0)		//GET ������� POST ������� üũ
	{
		i += sizeof(post_str)-1;
	}
	else
	{
		return FALSE;
	}

	for (j = 0; i < len && data[i] != ' '; j++, i++)
	{
		uri[j] = data[i];
	}
	uri[j] = '\0';
	if (i + sizeof(http_host_str)-1 >= len)
	{
		return FALSE;
	}

	if (strncmp(data + i, http_host_str, sizeof(http_host_str)-1) != 0)			// HTTP ���� üũ
	{
		return FALSE;
	}
	i += sizeof(http_host_str)-1;

	for (j = 0; i < len && data[i] != '\r'; j++, i++)
	{
		domain[j] = data[i];
	}
	if (i >= len)
	{
		return FALSE;
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		// Nice try...
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';

	printf("URL %s/%s: ", domain, uri);							// �����ΰ� uri ���
	memcpy(blockedDomain_site, domain, sizeof(domain));
	// Reverse the domain:
	for (i = 0; i < j / 2; i++)									// �ռ� ���ߵ��� ȣ��Ʈ�� ��Ʈ��ũ�� ������ ó�� ����� �ٸ��Ƿ� �������� ������ �ٲ������
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}

	// Search the blacklist:
	result = BlackListMatch(blacklist, &url);					// BlackListMatch�� �Լ��� ���� ���ػ���Ʈ�� true �ƴϸ� false�� ��ȯ ����

	// Print the verdict:
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)													// ���ػ���Ʈ �� ��� �����۾��� "BLCOKED! " ���
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		printf("BLOCKED! ");
	}
	else														// ���ػ���Ʈ�� �ƴ� ��� �ʷ� �۾��� "allowed" ��� 
	{		
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;												// ����� ����!
}






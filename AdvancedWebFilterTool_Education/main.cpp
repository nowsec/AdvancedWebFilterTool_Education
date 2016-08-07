/*						중요사항																*/
//	1. 호스트는 리틀엔디안으로 데이터를 읽지만 네트워크는 빅엔디안 방식으로 데이터를 처리한다.  //
////////////////////////////////////////////////////////////////////////

#define _CRT_SECURE_NO_WARNINGS		// 보안 경고 무시

#include <stdio.h>			// 입출력 함수 사용을 위한 헤더 추가
#include <stdlib.h>			// 문자열 함수 사용을 위한 헤더 추가

#include "windivert.h"		// windivert 함수들을 사용하기 위한 헤더 추가

#define MAXBUF 0xFFFF		// 버퍼값의 최대 크기
#define MAXURL 4096			// URL의 최대 크기

/*
* URL and blacklist representation.
*/
typedef struct url			// url 구조체로 안에 domain과 uri 포함
{							// www.naver.com/ko/index.nhn 이러한 주소가 있을 때
	char *domain;			// www.naver.com은 도메인
	char *uri;				// ko/index.nhn은 uri (인터넷에 있는 자원을 나타내는 유일한 주소)
} URL, *PURL;

typedef struct blacklist		// 차단할 사이트들의 리스트를 구조체화 
{
	UINT size;					// 리스트에 들어갈 수 있는 최대 list 개수
	UINT length;				// 리스트에 들어간 list 개수
	PURL *urls;					// blacklist로 등록된 url
} BLACKLIST, *PBLACKLIST;

/*
* Pre-fabricated packets.
*/
typedef struct ipandtcp			// ip와 tcp의 헤더를 구조체화
{
	WINDIVERT_IPHDR  ip;		// ip의 헤더
	WINDIVERT_TCPHDR tcp;		// tcp의 헤더
} PACKET, *PPACKET;
typedef struct datapacket
{
	PACKET header;				// 전송할 패킷의 헤더
	UINT8 data[];				// 정송할 패킷의 데이터
} DATAPACKET, *PDATAPACKET;

const char block_data[] =				// blocklist에 등록된 사이트에 접근할 경우 block_data를 보내 연결을 종료
"HTTP/1.1 200 OK\r\n"					// HTTP 1.1 프로토콜 200 : 요청 성공 https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html 각 번호에 대한 설명은 사이트 참고 
"Connection: close\r\n"					// 연결을 종료
"Content-Type: text/html\r\n"			// 내용 타입 text http://hbesthee.tistory.com/45
"\r\n"
"<!doctype html>\n"						// DOCTYPE이란, HTML 문서를 시작할때 이 문서는 html 문서이고 어떤버전을 사용했으며 그 버전에 맞는 방법으로 해석해라고 브라우저에게 알려주는 선언문 http://changeroom.blog.me/220452343759
"<html>\n"								// html시작을 알림, html이란 웹 문서를 만들기 위하여 사용하는 기본적인 프로그래밍 언어의 한 종류
"\t<head>\n"							// <head>태그는 브라우즈 정보, 메타 정보, 스크립트, 스타일 시트 등의 요소를 포함할 수 있음
"\t\t<title>BLOCKED!</title>\n"			// 브라우저 툴바의 제목을 정의
"\t</head>\n"							// </head> 여기 까지가 헤더의 끝
"\t<body>\n"							// HTML body 태그는 HTML 문서에서 몸통을 이루는 부분
"\t\t<h1>BLOCKED!</h1>\n"				// <h1> to <h6> 태그는 본문의 제목 역할
"\t\t<hr>\n"							// hr 구분선 넣음
"\t\t<p>This URL has been blocked!</p>\n"		// <p></p>태그는 문단을 정의하는 태그
"\t</body>\n"									// </body> 바디 부분 종료
"</html>\n";									// </html> html 종료

/*
* Prototypes
*/
bool mal_site_state;												// 접속한 사이트가 유해사이트면 true 아니면 false
char blockedDomain[MAXURL];											// block된 도메인의 주소를 담고 있음

void PacketInit(PPACKET packet);									// 패킷 초기화 함수
int __cdecl UrlCompare(const void *a, const void *b);				// blacklist에 들어있는 url들을 정렬시키기 위해 비교 함수
int UrlMatch(PURL urla, PURL urlb);									// 접속한 url이 blacklist에 포함된 url인지 비교 함수
PBLACKLIST BlackListInit(void);										// blacklist 초기화 함수
void BlackListInsert(PBLACKLIST blacklist, PURL url);				// 두 번째 인자의 url을 blacklist에 추가
void BlackListSort(PBLACKLIST blacklist);							// blacklist에 있는 사이트들을 알파벳 순으로 정렬
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);				// blacklist에 있는 사이트와 접속한 사이트 비교
void BlackListRead(PBLACKLIST blacklist, const char *filename);		// 파일 이름을 읽어 안에 있는 주소들을 blacklist에 등록
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site);			// 패킷의 페이로드 부분 비교, 정의 부분에서 자세히 설명

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	FILE *f_log_txt;						// 로그 파일을 열기위한 변수
	HANDLE handle;							// WinDivertOpen의 핸들 값을 가져옴
	WINDIVERT_ADDRESS addr;					// Packet's interface index, Packet's sub-interface index, Packet's direction 정보를 갖고 있음                               
	UINT8 packet[MAXBUF];					// 수집한 패킷을 담을 배열
	UINT packet_len;						// 패킷의 길이
	PWINDIVERT_IPHDR ip_header;				// ip 헤더
	PWINDIVERT_TCPHDR tcp_header;			// tcp 헤더
	PVOID payload;							// 페이로드 : 통신에 필요한정보가들어간 것
	UINT payload_len;						// 페이로드 길이
	PACKET reset0;							// 초기화된 패킷
	PPACKET reset = &reset0;				// 초기화된 패킷
	PACKET finish0;							// Flag에서 fin에 포함된 패킷
	PPACKET finish = &finish0;				// Flag에서 fin에 포함된 패킷
	PDATAPACKET blockpage;					// 블랙할 페이지의 패킷 데이터
	UINT16 blockpage_len;					// 블랙된 페이지 개수
	PBLACKLIST blacklist;					// 블랙된 페이지 리스트
	unsigned i;
	INT16 priority = 404;       // Arbitrary.
	mal_site_state = false;					//  
	char buf[1024] = { 0, };
	// Read the blacklists.

	blacklist = BlackListInit();			// 블랙리스트를 초기화

	BlackListRead(blacklist, "mal_site.txt");		// mal_site.txt에 들어있는 url을 blacklist에 넣음

	BlackListSort(blacklist);						// blacklist안에 있는 데이터를 정렬

	// Initialize the pre-frabricated packets:
	blockpage_len = sizeof(DATAPACKET)+sizeof(block_data)-1;		// block 페이지에 들어가는 데이터 길이
	blockpage = (PDATAPACKET)malloc(blockpage_len);					// block 페이지에 동적 메모리 할당(위에서의 데이터 길이 만큼)
	if (blockpage == NULL)											// blockpage의 동적 메모리 할당이 실패했을 경우 exit
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);									// block페이지의 헤더 초기화
	blockpage->header.ip.Length = htons(blockpage_len);				// htons 리틀엔디안을 빅엔디안으로 변환하여 넣어준다
	blockpage->header.tcp.SrcPort = htons(80);						// 포트 80번을 네트워크 형식인 빅엔디안으로 변환하여 넣어준다(htons)
	blockpage->header.tcp.Psh = 1;									// tcp 헤더 플래그 참고 http://www.ktword.co.kr/abbr_view.php?m_temp1=2437
	blockpage->header.tcp.Ack = 1;									// Psh 기다리지 않고 푸쉬, Ack 응답되었음을 확인
	memcpy(blockpage->data, block_data, sizeof(block_data)-1);		// block_data를 block page에 보여줄 데이터에 복사
	PacketInit(reset);												// reset 패킷 초기화
	reset->tcp.Rst = 1;												// Rst 연결을 강제로 끊음
	reset->tcp.Ack = 1;												// 응답 flag 1로 설정
	PacketInit(finish);												// finish 패킷을 초기화
	finish->tcp.Fin = 1;											// Fin flag : 패킷 전송을 정상적으로 끝냄, Rst은 강제 종료
	finish->tcp.Ack = 1;											// 응답 flag 1로 설정

	// Open the Divert device:
	handle = WinDivertOpen(											// WinDivert를 오픈하여 핸들값을 handle에 넘김
		"outbound && "              // Outbound traffic only		// 필터 값을 보면 나가는 패킷 중
		"ip && "                    // Only IPv4 supported			// 아이피이면서
		"tcp.DstPort == 80 && "     // HTTP (port 80) only			// tcp 목적지 포트가 80
		"tcp.PayloadLength > 0",    // TCP data packets only		// 페이로드 길이가 0을 넘는 패킷을 필터링함
		WINDIVERT_LAYER_NETWORK, priority, 0						// WINDIVERT_LAYER_NETWORK 네트워크 레이어에서 수집함
		);
	if (handle == INVALID_HANDLE_VALUE)								// WinDivertOpen이 제대로 되지 않았으면 에러
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");									// 제대로 오픈 되었으면 "OPENED WinDivert" 출력

	// Main loop:
	while (TRUE)													// 무한루프를 통해 계속적으로 패킷을 수신
	{
		f_log_txt = fopen("log.txt", "a");							// 로그 파일 기록을 위해 log.txt 오픈

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))		//위에서 Open한 필터 값을 기준으로 패킷을 수신
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,			//WinDivertHelperParsePacket 수신한 패킷에서 주요 정보들을 추출 ip, tcp 헤더 등등
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char*)payload, (UINT16)payload_len, blockedDomain))		//수신한 패킷에서 사이트 정보를 추출하여 blocklist 사이트인지 체크
		{
			// Packet does not match the blacklist; simply reinject it.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))					//접속한 사이트가 유해 사이트가 아닌 경우
			{																				//수신한 패킷을 다시 send하고 while문으로 돌아감
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		// The URL matched the blacklist; we block it by hijacking the TCP
		// connection.

		// (1) Send a TCP RST to the server; immediately closing the
		//     connection at the server's end.
		// 수신한 패킷이 유해사이트인 경우 flag rst를 넣어 연결을 종료하는 패킷 전송 out bound

		reset->ip.SrcAddr = ip_header->SrcAddr;			// Src 주소와 Dst 주소를 변경
		reset->ip.DstAddr = ip_header->DstAddr;			// 수신한 패킷을 다시 나에게 보내기 위함
		reset->tcp.SrcPort = tcp_header->SrcPort;		// Src포트는 그대로 넣어주며 
		reset->tcp.DstPort = htons(80);					// Dst 포트는 80으로 넣어줌
		reset->tcp.SeqNum = tcp_header->SeqNum;			// SeqNum와 AckNum 값은 그대로 넣어줌
		reset->tcp.AckNum = tcp_header->AckNum;			// SeqNum과 AckNum은 매우 중요한 부분이므로 따로 공부해보길 바람, 얼마만큼의 데이터를 주고 받았는지 이 부분을 통해 체크 가능 + 다른 프로젝트에서 더욱 자세히 다룰 예정 
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);		//ip헤더와 tcp 헤더의 체크섬 값을 계산하여 넣어줌
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))		//연결을 강제로 종료시키는 reset 패킷 전송
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		// (2) Send the blockpage to the browser:
		//유해사이트인 경우 src, dst 정보를 바꿔 나에게 block data를 뿌려줌 in bound

		blockpage->header.ip.SrcAddr = ip_header->DstAddr;							// src 주소와 dst 주소를 스왑
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;						// Src 포트를 Dst 포트로 변경			
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;							// Seq넘버 값에 AckNum을 넣어주며
		blockpage->header.tcp.AckNum =												// AckNum에는 기존의 SeqNum과 수신한 페이로드의 값을 더해서 AckNum에 넣어줌
			htonl(ntohl(tcp_header->SeqNum) + payload_len);							// 이부분 아주 중요!! 필히 Seq, Ack넘에 대해 공부할 것 
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);			// blockpage 패킷에 대한 checksum 값 계산
		addr.Direction = !addr.Direction;     // Reverse direction.					// 패킷의 방향에는 in bound(1), out bound(0) 가 있음
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,			// 나에게 blockpage 패킷을 전송
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
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data)-1);				// seq에 ack num과 block data의 길이를 더한 값을 넣음 
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);							// ack에 처음에 수신한 페이로드의 길이만큼을 seq에 더한 값을 넣음
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);				// finish 패킷의 checksum 값 계산
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))		// 종료를 위한 fin packet 전송
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}

		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;							// 접속이 블락된 패킷의 src와 dst 아이피를 출력
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fprintf(f_log_txt, "BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", blockedDomain,		// 접속이 블락된 패킷의 src와 dst 아이피, 도메인을 log.txt에 기록
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fclose(f_log_txt);		//기록 완료후 파일 종료
		}

	}
}

void PacketInit(PPACKET packet)					// 패킷의 초기화를 위한 함수
{
	memset(packet, 0, sizeof(PACKET));			// 패킷을 0으로 초기화
	packet->ip.Version = 4;						// 패킷 버전은 4
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);	// 아이피 헤더길이 20
	packet->ip.Length = htons(sizeof(PACKET));							// 기본 ip length는 40
	packet->ip.TTL = 64;												// 기본 TTL 64
	packet->ip.Protocol = IPPROTO_TCP;									// 프로토콜 타입 TCP
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);		//tcp 헤더길이 20
}

/*
* Initialize an empty blacklist.
*/
PBLACKLIST BlackListInit(void)		// blacklist를 초기화
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));	// blacklist 동적으로 40메모리 할당
	UINT size;
	int d = sizeof(PURL);
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;													// 들어갈 수 있는 size는 1024
	blacklist->urls = (PURL *)malloc(size*sizeof(PURL));			// url 8 x 1024 메모리 할당
	if (blacklist->urls == NULL)									// blacklist->urls == NULL이면 메모리 할당 실패
	{
		goto memory_error;
	}
	blacklist->size = size;											// 사이즈 1024 
	blacklist->length = 0;											// 길이 0
																	// 여기서 사이즈는 최대 들어갈 수 있는 list 개수 length는 현재 들어가있는 list 개수를 의미
	return blacklist;												// 구조체를 반환

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}

/*
* URL comparison.
*/
int __cdecl UrlCompare(const void *a, const void *b)		// 접속한 url이 blacklist에 포함된 url인지 비교 함수
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);			// strcmp함수를 통해 url domain 비교후 retrun 값으로 넘겨줌
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);					// domain이 같다면 url을 비교하여 반환
}

/*
* Sort the blacklist (for searching).
*/
void BlackListSort(PBLACKLIST blacklist)					// blacklist에 들어가 있는 리스트들을 qsort를 통해 정렬
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* URL matching
*/
static int UrlMatch(PURL urla, PURL urlb)					// 접속한 사이트가 유해사이트인지 체크하는 함수
{															// 문자들을 하나하나 비교해가며 mal_site.txt에 쓰여있는 주소와 같은지 체크
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
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)	// 접속한 사이트가 유해사이트인지 체크하는 함수
{													// 이부분도 UrlMatch와 비슷 하지만 비교 로직을 좀 더 분석할 필요가 있음
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
			return TRUE;			// 이부분에서 결론적으로 유해사이트와 같으면 True
		}
	}
	return FALSE;					// 다르면 Flase를 반환
}


/*
* Insert a URL into a blacklist.
*/
void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)		//들어간 list가 최대 크기인 1024를 초과할 경우 메모리를 재할당 하여 크기를 늘림 
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

	blacklist->urls[blacklist->length++] = url;		//blacklist에 url을 추가하는 부분
}


/*
* Read URLs from a file.
*/
void BlackListRead(PBLACKLIST blacklist, const char *filename)		//두번째 인자의 파일을 읽어들여 blacklist에 넣음 
{
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");								//파일을 오픈

	if (file == NULL)												//파일이 열리지 않으면 에러
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}

	// Read URLs from the file and add them to the blacklist: 
	while (TRUE)
	{
		while (isspace(c = getc(file)))			//isspace 스페이스인지 아닌지 체크
			;
		if (c == EOF)							//파일 끝인지 체크
		{
			break;
		}
		if (c != '-' && !isalnum(c))			//숫자이면서 '-' 값이면 true ,isalnum : 알파벳 또는 숫자이면 0이 아닌 값 반환
		{
			while (!isspace(c = getc(file)) && c != EOF)		//isspace 공백이 아니면 0이 아닌 값을 반환한다.
				;
			if (c == EOF)
			{
				break;
			}
			continue;
		}
		i = 0;
		domain[i++] = (char)c;
		while ((isalnum(c = getc(file)) || c == '-' || c == '.') && i < MAXURL)		//isalnum 숫자나 문자가 아니면 0이 아닌 값이 들어간다.
		{
			domain[i++] = (char)c;													//파일에서 읽어들인 유해사이트를 domain 배열에 저장
		}
		domain[i] = '\0';															//배열 마지막에 \0 값 추가
		j = 0;
		if (c == '/')																// '/'를 기준으로 뒤에 uri 값을 가져옴
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

		printf("ADD %s/%s\n", domain, uri);											// mal_site.txt에 있는 domain과 uri 출력

		url = (PURL)malloc(sizeof(URL));											// url 부분 동적으로 메모리 할당
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1)*sizeof(char));							//앞에서 계산한 만큼 domain 메모리 동적 할당
		url->uri = (char *)malloc((j + 1)*sizeof(char));							//앞에서 계산한 만큼 uri 메모리 동적 할당
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];										// url부분에는 주소를 거꾸로 저장 ex) nate.com -> moc.etan 
		}																			// 호스트에와 네트워크가 읽어들이는 방식이 다름 
		url->domain[j] = '\0';														// 네트워크는 빅엔디안
																					// 호스트는 리틀엔디안
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
void mystrcpy(unsigned char *dest, unsigned char *src)			//unsigned char* 문자열 복사를 위해 strcpy함수 수정
{
	int index = 0;
	// 원본이 NULL 이거나 대상이 NULL 이면 종료

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
char *findStr(unsigned char *str1, char *str2)		//unsigned char* 문자열 찾기 위해 strstr함수 수정
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


BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site)		//접속한 사이트와 Blacklist를 비교하여 true, false를 반환
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
	if (strncmp(data, get_str, sizeof(get_str)-1) == 0)			//GET 방식인지 POST 방식인지 체크
	{
		i += sizeof(get_str)-1;
	}
	else if (strncmp(data, post_str, sizeof(post_str)-1) == 0)		//GET 방식인지 POST 방식인지 체크
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

	if (strncmp(data + i, http_host_str, sizeof(http_host_str)-1) != 0)			// HTTP 버전 체크
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

	printf("URL %s/%s: ", domain, uri);							// 도메인과 uri 출력
	memcpy(blockedDomain_site, domain, sizeof(domain));
	// Reverse the domain:
	for (i = 0; i < j / 2; i++)									// 앞서 말했듯이 호스트와 네트워크는 데이터 처리 방법이 다르므로 도메인을 역으로 바꿔줘야함
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}

	// Search the blacklist:
	result = BlackListMatch(blacklist, &url);					// BlackListMatch이 함수를 통해 유해사이트면 true 아니면 false를 반환 받음

	// Print the verdict:
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)													// 유해사이트 일 경우 빨간글씨로 "BLCOKED! " 출력
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		printf("BLOCKED! ");
	}
	else														// 유해사이트가 아닐 경우 초록 글씨로 "allowed" 출력 
	{		
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;												// 결과값 리턴!
}






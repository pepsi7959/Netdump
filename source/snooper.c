#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
//#include <pcap.h>

#define STREQ(a, b) (strcmp(a, b) == 0)

static char HEXTABLE[] = {'0','1',
	'2','3','4','5','6','7','8','9',
	'a','b','c','d','e','f'};

static int src_port = 0;
static int dst_port = 0;
char * dec_to_hex(char c){
	static char b[3];
	b[1] = HEXTABLE[0x0f & c];	
	b[0] = HEXTABLE[(c>>4) & 0x0f];
	b[2] = 0;
	return b; 
}

int filter(char *buffer, int blen, char *str_filter, int len){
	if (str_filter[0] == 0)
		return 1;
#ifdef FILTER_ON
	char *p = NULL;
	buffer[blen] = 0;
	if(blen < 52 || (p = (char*)memmem(buffer+52, blen-52, str_filter, 4)) == NULL ){
		return 0;
	}
	printf("Match[%s]\n",p);
#endif
		return 1;
}

int getSrcIP(char *buffer, char *srcIP){
	if(buffer == NULL){
		return -1;
	}

	sprintf(srcIP,"%d.%d.%d.%d"
		, buffer[12]
		, buffer[13]
		, buffer[14]
		, buffer[15]);
	return 0;
}
int getDstIP(char *buffer, char *dstIP ){
	if(buffer == NULL){
		return -1;
	}

	sprintf(dstIP,"%d.%d.%d.%d"
		, buffer[16]
		, buffer[17]
		, buffer[18]
		, buffer[19]);
	return 0;
}
int getSrcPort(char *buffer){
	int port = 0;
	port = 0x00ff & buffer[21];
	port = port | (0xff00 & (buffer[20] << 8));
	return src_port = port;
}

int getDstPort(char *buffer){
	int port = 0;
	port = 0x00ff & buffer[23];
	port = port | (0xff00 & (buffer[22] << 8));
	return dst_port = port;
}

int filter_port(int port ){
	if ( port < 0 ) 
		return 1;
#ifdef FILTER_ON
	if( !((port == dst_port) || (port == src_port))){	
		return 0;
	}
#endif	
	return 1;
}
void dump(char *buffer, int len){
	int i = 0, j = 0;
	int Ishex = 1;	
	for(i = 0; i < len; i++){

		if( Ishex == 1 ){	
			printf("%s ", dec_to_hex(buffer[i]));
			if( ((i+1)%8 == 0) && i){
				printf(" ");
			}
			if(((i+1) % 16 == 0) && i || (i+1 == len)){	
				j = (i+1) % 16;	
				if(j){
					i = i-j;
					if( j < 8){
						printf("  ");
					}
					else if( j >= 8 && j < 16){
						printf(" ");
					}
				}
				else{ 
					i = i - 16;	
				}
				Ishex = 0;
				j = 16 - j;	
				while(j<16 && j--)
					printf("   ");
				printf(" | ");
			}
			
		}
		else{ 
			printf("%c",( buffer[i]>32 && buffer[i]<127 )?buffer[i]:'.');
			if( ((i+1)%8 == 0) && i){
				printf(" ");
			}
			if(((i+1) % 16 == 0) && i){
				Ishex = 1;
				printf("\n");
			}	
		}
	}
	
	printf("\n");	
}

int getparam(int *fport, char *fdata,int *len, int argc, char *argv[]){
	int i = 0;	
	*fport = -1;
	fdata[0] = 0;
	for(i =  1;i < argc; i++){
		if( STREQ(argv[i],"-p")){
			if( i+1 < argc){
				*fport = atoi(argv[i+1]);	
				i++;
			}else{
				 return -1;
			}
		}
		else if ( STREQ(argv[i],"-d")){
			if( i+1 < argc){
				sprintf(fdata,argv[i+1]);
				*len = strlen(argv[i+1]);
				i++;
			}else{
				return -1;
			}	
		}
		else {
			return -1;
		}
	}
	return 0;
}


int main(int argc, char *argv[] ) {
	int i, recv_length, sockfd;
	unsigned char buff[90000];
	char dstIP[16];
	char srcIP[16];
	int fport;
	int fdata_len= 0;
	char fdata[256];	
	if(getparam (&fport, fdata, &fdata_len, argc, argv) != 0)	
		return -1;
	if (( sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1){
		printf("ERROR: %s\n",strerror(errno));
		return -1;}

		
	for (i=1; i ;){
		//memset(buff,0,sizeof(buff));
		recv_length =  recv(sockfd, buff, 80000, 0);
		(void) getSrcPort(buff);
		(void) getDstPort(buff);
		(void) getSrcIP(buff,srcIP);
		(void) getDstIP(buff,dstIP);
		if(1
#ifdef FILTERDATA_ON
		&& filter(buff, recv_length, fdata, fdata_len)
#endif
#ifdef FILTERPORT_ON 
		&& filter_port(fport)
#endif
){
			printf("\nsource(%s:%d) > destination(%s:%d) got a %d byte packet\n"
				, srcIP
				, getSrcPort(buff)
				, dstIP
				, getDstPort(buff) 
				,recv_length);
			dump(buff, recv_length);}
		}

	/*	
	struct pcap_pkthdr header;
	pcap_t *pcap_handle;
	const unsigned char *packet;
	char err[256];
	char *device = NULL;	
	device = (char *)pcap_lookupdev(err);

	if(device == NULL)
		return -1;
	printf("sniffing on device %s\n");
	if((pcap_handle = pcap_open_live(device, 4096, 1, 0, err))==NULL)
		return -1;
	for (i=1; i ;){
		packet =  pcap_next(pcap_handle, &header);
		printf("got a %d byte packet\n\n", header.len);
		dump(packat, header.len);
	}
*/	
	return -1;
}
	

#include <stdio.h>
#include <stdlib.h>
typedef unsigned short u_short;
typedef unsigned char u_char;

struct mac {
	u_short m1,m2,m3,m4,m5,m6;
};

struct e_h{
	struct mac dst_mac, src_mac;
	u_short type;
};
struct ip_add{
	u_short ip1,ip2,ip3,ip4;
};

struct ip_h{
	u_char ip_v,ip_hl;
	u_short total_len;
	u_short identification;
	u_short ip_off;
	u_char ttl;
	u_char ip_protocol;
	u_short chksum;
	struct ip_add ip_src,ip_dst;
};

struct tcp_h{
	u_short src_port;
	u_short dst_port;
	int seq, ack;
};
/*

   global header : 24Byte
   pacp header : 16Byte
   MAC dest : 6byte
   MAC src : 6byte
	Ethernet_type 2byte
ip_v : 1byte
Type of service :1byte (??)
total length : 2byte
identification : 2byte
offset(Fragment) :2byte
TTL : 1byte
Ptotocol : 1byte
checksum : 2byte

src IP : 4byte
des IP : 4byte

source port : 2byte
des port : 2byte

   */

int main(){
	FILE *in;
	int *cp;
	int ch;
	int add =0;
	int wi=40;
		if ( ( in = fopen("lecture_http_header.pcap","rb"))==NULL){
			fputs("Error",stderr);
			exit(1);
		}
	
		while((ch=fgetc(in))!=EOF){
					add++;
				}
		fclose(in);
		
		if ( ( in = fopen("lecture_http_header.pcap","rb"))==NULL){
			fputs("Error",stderr);
			exit(1);
		}
	
		cp = (int *)malloc(sizeof(int)*add);
		int i = 0;
		while((cp[i]=fgetc(in))!=EOF){
		i++;
		}
		printf("MAC dest : ");
		for(int j=wi;j<wi+6;j++){
			printf("%02x",cp[j]);
		}
		wi+=6;
		printf("\nMac src : ");
		for(int j=wi;j<wi+6;j++){
			printf("%02x",cp[j]);
		}
		wi+=6;
		printf("\nEthernet Type :0x");
		
		for(int j=wi;j<wi+2;j++){
			printf("%02x",cp[j]);
		}
		wi+=4;
		printf("\ntotal Length : 0x");

		for(int j=wi;j<wi+2;j++){
			printf("%02x",cp[j]);
		}
		wi+=6;
		printf("\nTTL : ");

		for(int j=wi;j<wi+1;j++){
			printf("%02d",cp[j]);
		}
		wi+=2;
		
		printf("\nCheck Sum : ");

		for(int j=wi;j<wi+2;j++){
			printf("%02x ",cp[j]);
		}
		wi+=2;
		printf("\nSrc IP : ");

		for(int j=wi;j<wi+4;j++){
			printf("%03d ",cp[j]);
		}
		wi+=4;
		printf("\ndes IP : ");
		for(int j=wi;j<wi+4;j++){
			printf("%03d ",cp[j]);
		}
		printf("\n");
		fclose(in);
		return 0;
}

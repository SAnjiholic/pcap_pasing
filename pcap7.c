#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "libnet.h"

#define IP_COUNT 255;
int ipCnt = 1;

struct arp_table{
	int num;
	uint8_t ip[4];
	uint8_t mac[6];
};


void my_mac(uint8_t mac[]){
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void my_ip(uint8_t ip[]){
	printf("%d.%d.%d.%d\n",ip[0],ip[1],ip[2],ip[3]);
}

void addkey(struct arp_table *p, int key, uint8_t ip[], uint8_t mac[]){
	p[key-1].num = key;
	for(int i = 0; i < 4; i++){	p[key-1].ip[i] = ip[i];}
	for(int i = 0; i <6; i++) { p[key-1].mac[i] = mac[i];}
	ipCnt++;
	printf("No.%d : \nip : ",key);
	my_ip(ip);
	printf("Mac : ");
	my_mac(mac);
}

void check_ip(struct arp_table *p, int key, uint8_t ip[], uint8_t mac[]){
	int flag = 0;
	int check = 0;
	for(int a = key-1; a >= 0; a--){
		for(int i = 4; i > 0; i--){

			if (p[a].ip[i-1] != ip[i-1]){break; }
			else{check++;}
		}
		if(check == 4){ flag = -1;}
	}
	if(flag == 0 ) {
		if(mac[0] != 0x00){
			addkey(p, key, ip, mac); }
	}

}

int main(int argc, char *argv[]) {
	const u_char *data;
	char *err;
	char ip_buf[16];	
	int pktCnt=0;
	int i=0;
	int j=0;
	int devnum;
	int res;

	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_arp_hdr *arp;
	struct libnet_tcp_hdr *tcp;
	struct libnet_udp_hdr *udp;
	struct arp_table p[255];

	pcap_if_t *alldevs;
	pcap_if_t *dev;
	pcap_t *pcap;

	memset(p, 0x00, sizeof(p));

	if (pcap_findalldevs(&alldevs, err) == -1){
		fprintf(stderr,"Not find devs: %s\n", err);
		exit(1);
	}

	for(dev = alldevs; dev; dev = dev->next){
		printf("%d. %s\n", ++j, dev->name);
	}

	if(j==0){
		printf("Not found Interfaces");
		return -1;
	}

	printf("Enter interface number (1-%d):",j);
	scanf("%d", &devnum);

	if (devnum < 1 || devnum > j ){
		printf("\nNo.%d is wrong number", devnum);
		pcap_freealldevs(alldevs);
		return -1;
	}
	for (dev = alldevs, j = 0; j< devnum-1; dev = dev->next,i++);

	if ((pcap = pcap_open_live(	dev->name, 65536, 1, 1000, err)) == NULL){
		fprintf(stderr, "\n%s open fail :( \n", dev->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nListening on %s\n", dev->description);
	while((res= pcap_next_ex(pcap, &header, &data)) >=0){
		if(res == 0) continue;
		eth = (struct libnet_ethernet_hdr *) data;
		if((ntohs(eth->ether_type)) == ETHERTYPE_ARP) {
			arp = (struct libnet_arp_hdr *)(data + sizeof(struct libnet_ethernet_hdr));
			check_ip(p,ipCnt,arp->s_ip,arp->s_mac);
			check_ip(p,ipCnt,arp->t_ip,arp->t_mac);
		} 
	}
}


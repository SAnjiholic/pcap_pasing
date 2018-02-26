#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <libnet.h>

#define ETHER_ADDR_LEN 0x6
#define eth_h libnet_ethernet_hdr

/*
struct eth{
	struct libnet_ether_addr ma1, ma2;
	u_short eth_type;
};
*/

struct arp_h{
	struct libnet_arp_hdr arp;
	uint8_t s_mac[6];
	//struct libnet_ether_addr Send_mac;
	struct in_addr Send_ip;
	uint8_t t_mac[6];
	//struct libnet_ether_addr Target_mac;
	struct in_addr Target_ip;
};

int main(int argc, char *argv[]) {
		int pktCnt=0;
		int i=0;	
		struct pcap_pkthdr header;
		struct eth_h *eth;
		struct libnet_ipv4_hdr *ip;
		struct arp_h *arp;
		struct libnet_tcp_hdr *tcp;
		struct libnet_udp_hdr *udp;

		const u_char *data;
		char file[]= "lecture_http_header.pcap";
		char *err;
		
		pcap_t *pcap = pcap_open_offline(file, err);
		for(i=0;(data= pcap_next(pcap, &header))!=NULL;i++){
			eth = (struct eth_h *) data;
			printf("\n%04x\n",eth->ether_type);
			printf("Pcaket No .%i\n",++pktCnt);
			printf("Packet size : %d bytes\n",header.len);
			
			if((eth->ether_type) == 0x0008){		//IP
			ip = (struct libnet_ipv4_hdr *)(data + sizeof(struct libnet_ethernet_hdr));
			
			printf("Dst Mac : %02x",(eth->ether_dhost[0]));
			for(i=1;i<6;i++){
				printf(":%02x",eth->ether_dhost[i]);
			}
			printf("\n");
			printf("Src Mac : %02x",eth->ether_shost[0]);
			for(i=1;i<6;i++){
				printf(":%02x",eth->ether_shost[i]);
			}
			printf("\n");
			printf("Src IP : %s\n",inet_ntoa(ip->ip_src));	
			printf("Dst IP : %s\n",inet_ntoa(ip->ip_dst));	
			
			if((ip->ip_p)== 0x11){				//UDP
			udp =(struct libnet_udp_hdr *)(data +sizeof(struct eth_h)+sizeof(struct libnet_ipv4_hdr));
			printf("Src Port : %d\n",ntohs(udp->uh_sport));
			printf("Dst Port : %d\n",ntohs(udp->uh_dport));
			printf("Length : %d\n",udp->uh_ulen);
			printf("CheckSum : %x\n",udp->uh_sum);
			}
			
			else if((ip->ip_p) == 0x06){		//TCP
			tcp = (struct libnet_tcp_hdr *)(data + sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
			
			printf("Src port : %d\n",ntohs(tcp->th_sport));		
			printf("Dst Port : %d\n",ntohs(tcp->th_dport));		
			printf("Win Size : %d\n",ntohs(tcp->th_win));
			printf("Check Sum : %x\n",htons(tcp->th_sum));
			}
			}

			else if((eth->ether_type) == 0x0608){		//ARP
			arp = (struct arp_h *)(data + sizeof(struct eth_h));
			
			printf("HardWare Type : %0x\n",arp->arp.ar_hrd);
			printf("Protocol Type : %0x\n",arp->arp.ar_pro);
			printf("HardWare Size : %x\n" ,arp->arp.ar_hln);
			printf("Protocol Size : %x\n",arp->arp.ar_pln);
			printf("OpCode : %x",arp->arp.ar_op);
			printf("Sender MAC : %02x",arp->s_mac[0]);
			for(i=1;i<6;i++){
			printf(":%02x",arp->s_mac[i]);
			}
			printf("\n");
			printf("Sender IP : %s\n",inet_ntoa(arp->Send_ip));
			printf("Target  MAC : %02x",arp->t_mac[0]);
			for(i=1;i<6;i++){
			printf(":%02x",arp->t_mac[i]);
			}
			printf("\n");
			printf("Target IP : %s\n",inet_ntoa(arp->Target_ip));
			} 


			}

                return 1;
        }


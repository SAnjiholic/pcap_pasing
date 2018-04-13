#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "libnet.h"


void my_mac(uint8_t mac[]){
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	
}

int main(int argc, char *argv[]) {
		int pktCnt=0;
		int i=0;	
		struct pcap_pkthdr header;
		struct libnet_ethernet_hdr *eth;
		struct libnet_ipv4_hdr *ip;
		struct libnet_arp_hdr *arp;
		struct libnet_tcp_hdr *tcp;
		struct libnet_udp_hdr *udp;

		const u_char *data;
		char file[]= "lecture_http_header.pcap";
		char *err;
		char ip_buf[16];	

		pcap_t *pcap = pcap_open_offline(file, err);
		for(i=0;(data= pcap_next(pcap, &header))!=NULL;i++){
			eth = (struct libnet_ethernet_hdr *) data;
			printf("\nPcaket No .%i\n",++pktCnt);
			printf("Packet size : %d bytes\n",header.len);
			
			if((ntohs(eth->ether_type)) == ETHERTYPE_IP){		//IP
			ip = (struct libnet_ipv4_hdr *)(data + sizeof(struct libnet_ethernet_hdr));
			
			printf("Dst Mac : "); my_mac(eth->ether_dhost);
			printf("Src Mac : "); my_mac(eth->ether_shost);
	
			printf("Src IP : %s\n",inet_ntop(AF_INET,&(ip->ip_src),ip_buf,sizeof(ip_buf)));
			printf("Src IP : %s\n",inet_ntop(AF_INET,&(ip->ip_dst),ip_buf,sizeof(ip_buf)));

			if((ip->ip_p)== IPPROTO_UDP){				//UDP
			udp =(struct libnet_udp_hdr *)(data +sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
			printf("Src Port : %d\n",ntohs(udp->uh_sport));
			printf("Dst Port : %d\n",ntohs(udp->uh_dport));
			printf("Length : %d\n",udp->uh_ulen);
			printf("CheckSum : %x\n",udp->uh_sum);
			}
			
			else if((ip->ip_p) == IPPROTO_TCP){		//TCP
			tcp = (struct libnet_tcp_hdr *)(data + sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
			
			printf("Src port : %d\n",ntohs(tcp->th_sport));		
			printf("Dst Port : %d\n",ntohs(tcp->th_dport));		
			printf("Win Size : %d\n",ntohs(tcp->th_win));
			printf("Check Sum : %x\n",htons(tcp->th_sum));
			}
			}

			else if((ntohs(eth->ether_type)) == ETHERTYPE_ARP){		//ARP
			arp = (struct libnet_arp_hdr *)(data + sizeof(struct libnet_ethernet_hdr));
			
			printf("HardWare Type : %0x\n",arp->ar_hrd);
			printf("Protocol Type : %0x\n",arp->ar_pro);
			printf("HardWare Size : %x\n" ,arp->ar_hln);
			printf("Protocol Size : %x\n",arp->ar_pln);
			printf("OpCode : %x",arp->ar_op);
			printf("Sender Mac : "); my_mac(arp->s_mac);
			printf("Sender IP : %s\n",inet_ntoa(arp->send_ip));
			printf("Targer Mac : "); my_mac(arp->t_mac);
			printf("Target IP : %s\n",inet_ntoa(arp->target_ip));
			} 


			}
                return 1;
        }

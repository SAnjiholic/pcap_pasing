#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>

struct mac{
	u_short b1,b2,b3;
};
struct eth_h{
	struct mac dst_mac,src_mac;
	u_short type;
};
struct iad{
	u_char i1,i2,i3,i4;
};
struct ip_h{
	u_char ip_v; 
	u_char ip_hl;
	u_short total_len;
	u_short identification;
	u_short ip_off;
	u_char ttl;
	u_char ip_protocol;
	u_short chksum;
	struct in_addr ip_src, ip_dst;
};

struct tcp_h{
	u_short src_port;
	u_short dst_port;
	int seq,ack;
	u_char Header_len;
	u_short WinSize;
	u_short chksum;
};

int main(int argc, char *argv[]) {
                int num = 1;
				int i=0;
				int pktCnt=0;
				char *dev;
                char errbuf[PCAP_ERRBUF_SIZE];
                bpf_u_int32 net;
                bpf_u_int32 mask;
                struct in_addr net_addr, mask_addr;
				struct pcap_pkthdr header;
				struct eth_h *eth;
				struct ip_h *ip;
				struct tcp_h *tcp;

				const u_char *data;
            
				if(!(dev = pcap_lookupdev(errbuf))) {
                        perror(errbuf);
                        exit(1);
                }

                if(pcap_lookupnet(dev, &net, &mask, errbuf) < 0) {
                        perror(errbuf);
                        exit(1);
                }
			
                net_addr.s_addr = net;
                mask_addr.s_addr = mask;

                printf("my Device : %s\n", dev);
                printf("my Net Address : %s\n", inet_ntoa(net_addr));
                printf("my Netmask : %s\n---------------------------\n\n", inet_ntoa(mask_addr));

				char file[]= "httpGet.pcap";
				char *err;
				pcap_t *pcap = pcap_open_offline(file, err);
				for(i=0;(data= pcap_next(pcap, &header))!=NULL;i++){
					eth=(struct eth_h *) data;
					ip = (struct ip_h *)(data + sizeof(struct eth_h));
					tcp=(struct tcp_h*)(data + sizeof(struct eth_h)+sizeof(struct ip_h));
//			printf("==================================\n");	
				printf("Pcaket No .%i\n",++pktCnt);
				printf("Packet size : %d bytes\n",header.len);
				printf("MAC src : %04x:%04x:%04x\n",htons(eth->src_mac.b1),htons(eth->src_mac.b2),htons(eth->src_mac.b3));
				printf("MAC dst : %04x:%04x:%04x\n",htons(eth->dst_mac.b1),htons(eth->dst_mac.b2),htons(eth->dst_mac.b3));
				printf("ip src : %s\n",inet_ntoa(ip->ip_src));
				printf("ip det : %s\n",inet_ntoa(ip->ip_dst));
				printf("Src port : %d\n",ntohs(tcp->src_port));
				printf("Dst port : %d\n",ntohs(tcp->dst_port));
				//printf("seq %d, ack %d\n",tcp->seq,tcp->ack);
				printf("Winsize : %d\n",ntohs(tcp->WinSize));
				printf("check_sum : %x\n",htons(tcp->chksum));
				printf("=================================\n\n");
				}

                return 1;
        }


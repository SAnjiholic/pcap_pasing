#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

void my_mac(uint8_t mac[]){
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 }

int main(){
	struct ifreq *ifr;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	struct ifconf ifcfg;
	int fd;
	int n;
	int numreqs = 30;
	fd = socket (AF_INET, SOCK_DGRAM, 0);

	memset(&ifcfg, 0, sizeof(ifcfg));
	ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
	ifcfg.ifc_buf = realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
	ioctl(fd, SIOCGIFCONF, (char *)&ifcfg);	
	ifr = ifcfg.ifc_req;
	
	for(n = 0; n < ifcfg.ifc_len; n+=sizeof(struct ifreq)){
		printf("[%s]\n", ifr->ifr_name);
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		printf("IP : %s\n", inet_ntoa(sin->sin_addr));
		ioctl(fd, SIOCGIFHWADDR, (char *)ifr);
		sa = &ifr->ifr_hwaddr;
		my_mac(sa->sa_data);
		ifr++;
		}
}

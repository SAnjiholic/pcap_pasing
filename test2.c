#include "pcap.h"
#include <stdlib.h>
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;             
	pcap_if_t *d;                    
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

#if 0
#endif
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);

	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for(d=alldevs, i=0; i< inum-1 ;d=d->next,i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name, // name of the device
					65536,             // portion of the packet to capture. 
					// 65536 grants that the whole packet will be captured on all the MACs.
					1,         // promiscuous mode (nonzero means promiscuous)
					1000,              // read timeout
					errbuf         // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\n%s open fail :( \n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

}

#include <stdio.h>
#include <stdlib.h>

int main(){
	FILE *in;
	int *cp;
	int ch;
	int add =0;
	if ( ( in = fopen("httpGet.pcap","rb"))==NULL){
		fputs("Error",stderr);
		exit(1);
	}
	
	while((ch=fgetc(in))!=EOF){
				add++;
			}
	fclose(in);
		
	if ( ( in = fopen("httpGet.pcap","rb"))==NULL){
		fputs("Error",stderr);
		exit(1);
	}
	
	cp = (int *)malloc(sizeof(int)*add);
	int i = 0;
	int c = 16;
	while((cp[i]=fgetc(in))!=EOF){
		if(c==16){
			printf("\n0x%04x : ",i);
			c=0;
		}
		if(c==8){
			printf("| ");
		}
		printf("%02d ",cp[i]);
		i++;
		c++;	
	}
	fclose(in);
	

	printf("\n");
	
	return 0;
}

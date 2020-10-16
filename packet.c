#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>


void packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void ip_packet(const u_char * , int);
void print_ip(const u_char * , int);
void print_tcp(const u_char *  , int );
void print_udp(const u_char * , int);
void print_icmp(const u_char * , int );
void PrintData(const u_char * , int);


FILE *logs;
struct sockaddr_in source, destination;
int tcp=0,udp=0,icmp=0,misc=0,total=0,i,j;



int main(){
	pcap_if_t *all , *device;
	pcap_t *selected;			//For handling the selected device
	char errorbuff[1000], *devicename, devs[1000][1000];
	int counter=1, n;
	
	//Finding the list of available devices
	printf("Available devices: ");
	if(pcap_findalldevs(&all, errorbuff)){
		printf("Error encountered: %s", errorbuff);
		exit(1);
	}
	printf("Done\n");
	
	//Printing the list of available devices
	for(device = all; device!= NULL; device=device->next){
		printf("%d.%s-%s\n",counter, device->name, device->description);
		if(device->name!=NULL){
			strcpy(devs[counter] , device->name);
		}
		counter++;
	}
	
	//select the device to be sniffed
	printf("Enter the number of the device you want to start sniffing:");
	scanf("%d", &n);
	devicename=devs[n];
	
	//Getting the device ready for sniffing
	printf("Getting device %s ready for sniffing...", devicename);
	selected= pcap_open_live(devicename, 65536, 1, 0, errorbuff);
	
	if (selected==NULL){
		fprintf(stderr, "Counldn't make device %s ready for sniffing: %s\n", devicename, errorbuff);
		exit(1);
	}
	printf("Done\n");
	logs=fopen("sniffed.txt","w");
	
	if(logs==NULL){
		printf("File was not created.");
	}
	
	//putting the device in sniffer loop
	pcap_loop(selected , -1 , packet , NULL);
	
	return 0;	
	
}	
void packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;
	
	//Getting IP Header and excluding Ethernet header
	struct iphdr *ip=(struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (ip->protocol)  //Checking the protocol being used and proceeding further
	{
		case 1: 	//ICMP
			++icmp;
			print_icmp(buffer,size);
			break;
		 case 6:	//TCP
		 	++tcp;
		 	print_tcp(buffer,size);
		 	break;
		 case 17:	//UDP
		 	++udp;
		 	print_udp(buffer,size);
		 	break;
		 default:	
		 	++misc;
		 	break;		 
	}
	printf("TCP: %d\t UDP: %d\t ICMP: %d\t Misc: %d\t Total: %d\r",tcp,udp,icmp,misc,total);
}

void print_ethernet_header(const u_char *buffer, int size)
{
	struct ethhdr *eth = (struct ethhdr *)buffer;
	
	fprintf(logs , "\n");
	fprintf(logs , "Ethernet Header\n");
	fprintf(logs , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logs , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logs , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

//ip header print
void print_ip(const u_char * buffer, int size){
	print_ethernet_header(buffer , size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&destination, 0, sizeof(destination));
	destination.sin_addr.s_addr = iph->daddr;
	
	fprintf(logs , "\n");
	fprintf(logs , "IP Header\n");
	fprintf(logs , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logs , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logs , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logs , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logs , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(logs , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logs , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logs , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logs , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logs , "   |-Destination IP   : %s\n" , inet_ntoa(destination.sin_addr) );
}


void print_tcp(const u_char * buffer , int size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
			
	fprintf(logs,"\n\n***********************TCP Packet*************************\n");	
		
	print_ip(buffer,size);
		
	fprintf(logs,"\n");
	fprintf(logs,"TCP Header\n");
	fprintf(logs,"   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logs,"   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logs,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logs,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logs,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logs,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logs,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logs,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logs,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logs,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logs,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logs,"   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logs,"   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logs,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logs,"\n");
	fprintf(logs,"                        DATA Dump                         ");
	fprintf(logs,"\n");
		
	fprintf(logs,"IP Header\n");
	PrintData(buffer,iphdrlen);
		
	fprintf(logs,"TCP Header\n");
	PrintData(buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logs,"Data Payload\n");	
	PrintData(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4) );
						
	fprintf(logs,"\n###########################################################");
}

//UDP packet
void print_udp(const u_char * buffer, int size){

	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int size_header =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logs , "\n\n***********************UDP Packet*************************\n");
	
	print_ip(buffer,size);			
	
	fprintf(logs , "\nUDP Header\n");
	fprintf(logs , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logs , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logs , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logs , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logs , "\n");
	fprintf(logs , "IP Header\n");
	PrintData(buffer , iphdrlen);
		
	fprintf(logs , "UDP Header\n");
	PrintData(buffer+iphdrlen , sizeof udph);
		
	fprintf(logs , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(buffer + size_header , size - size_header);
	
	fprintf(logs , "\n###########################################################");
}

//ICMP packet
void print_icmp(const u_char * buffer, int size){
	unsigned short iphdrlen;
	struct iphdr *ip=(struct iphdr *)(buffer +sizeof(struct ethhdr));
	iphdrlen = ip->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
	
	int size_header = sizeof(struct ethhdr)	+ iphdrlen + sizeof(icmph);
	
	fprintf(logs , "\n\n***********************ICMP Packet*************************\n");	
	
	print_ip(buffer , size);
			
	fprintf(logs , "\n");
		
	fprintf(logs , "ICMP Header\n");
	fprintf(logs , "   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logs , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logs , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logs , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logs , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	fprintf(logs , "\n");

	fprintf(logs , "IP Header\n");
	PrintData(buffer,iphdrlen);
		
	fprintf(logs , "UDP Header\n");
	PrintData(buffer + iphdrlen , sizeof icmph);
		
	fprintf(logs , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(buffer + size_header, (size - size_header));
	
	fprintf(logs , "\n###########################################################");
}

void PrintData(const u_char * data , int size)
{
	for(i=0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logs , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logs , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logs , "."); //otherwise print a dot
			}
			fprintf(logs , "\n");
		} 
		
		if(i%16==0) fprintf(logs , "   ");
			fprintf(logs , " %02X",(unsigned int)data[i]);
				
		if( i==size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logs , "   "); //extra spaces
			}
			
			fprintf(logs , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logs , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logs , ".");
				}
			}
			
			fprintf(logs ,  "\n" );
		}
	}
}


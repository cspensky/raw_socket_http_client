#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include<stdio.h>
#include<features.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/ethernet.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdlib.h>



#define VERBOSE 1;
//
// Global public data
//
unsigned char cMacAddr[8]; // Local Machine's MAC address
struct sin_addr *cIPAddr; // Local Machines's IP address

unsigned char gatewayMacAddr[8];
#define MAX_IFS 64  // Max Interface Requests

//
//
//
//							NETWORK STRUCTURES
//
//

///
//		Structure for ARP Request (Used for getting the Gateway MAC)
///
#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */
struct arp_req 
{
	u_int8_t src_mac[6];
	unsigned int src_ip;
	u_int8_t dest_mac[6];
	unsigned int dest_ip;
	//u_int8_t padding[1];
};
#pragma pack(pop)   /* restore original alignment from stack */


///
//			DNS STRUCTURES
/// Thanks: http://www.binarytides.com/blog/dns-query-code-in-c-with-winsock-and-linux-sockets/

//Type field of Query and Answer
#define T_A 1 /* host address */
#define T_NS 2 /* authoritative server */
#define T_CNAME 5 /* canonical name */
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 /* mail routing information */
 
//Function Prototypes
void ngethostbyname (unsigned char*);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void RetrieveDnsServersFromRegistry(void);
unsigned char* PrepareDnsQueryPacket (unsigned char*);
 
//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number
 
	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag
 
	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available
 
	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct DNS_QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct DNS_R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct DNS_RES_RECORD
{
	unsigned char *name;
	struct DNS_R_DATA *resource;
	unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
	unsigned char *name;
	struct DNS_QUESTION *ques;
} DNS_QUERY;


//
//
//
//							Interface Functions
//
//

///
//		CREATE OUR RAW SOCKET
///
int createRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

///
//		Returns the MAC address for the given interface
///
static int GetSvrMacAddress( char *pIface )
{
	int nSD; // Socket descriptor
	struct ifreq sIfReq; // Interface request
	struct if_nameindex *pIfList; // Ptr to interface name index
	struct if_nameindex *pListSave; // Ptr to interface name index
	struct ifconf *sIfReq2;
	
	//
	// Initialize this function
	//
	pIfList = (struct if_nameindex *)NULL;
	pListSave = (struct if_nameindex *)NULL;
	#ifndef SIOCGIFADDR
	// The kernel does not support the required ioctls
	return( 0 );
	#endif

	//
	// Create a socket that we can use for all of our ioctls
	//
	nSD = socket( PF_INET, SOCK_STREAM, 0 );
	if ( nSD < 0 )
	{
		// Socket creation failed, this is a fatal error
		printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
		return( 0 );
	}

	//
	// Obtain a list of dynamically allocated structures
	//
	pIfList = pListSave = if_nameindex();
	
	//
	// Walk thru the array returned and query for each interface's
	// address
	//
	for ( pIfList; *(char *)pIfList != 0; pIfList++ )
	{
		//
		// Determine if we are processing the interface that we
		// are interested in
		//
		if ( strcmp(pIfList->if_name, pIface) )
		// Nope, check the next one in the list
			continue;
		strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

		//
		// Get the MAC address for this interface
		//
		
		if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
		{
			// We failed to get the MAC address for the interface
			printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
			return( 0 );
		}
		memmove( (void *)&cMacAddr[0], (void *)		&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );

		break;
	}


	//
	//		Get the IP Address now (Different method.)
	//		This could be combined with the code above as we are also calling a 
	//		SIOCGIFHWADDR, however I'm keeping them seperate to demonstrate 
	//		multiple techniques.
	//
	struct ifreq *ifr, *ifend;
	struct ifreq ifreq;
	struct ifconf ifc;
	struct ifreq ifs[MAX_IFS];


	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;
	if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0)
	{
	printf("ioctl(SIOCGIFCONF): %m\n");
	return 0;
	}


	ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
	for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
	{
		//
		// Determine if we are processing the interface that we
		// are interested in
		//
		if ( strcmp(ifr->ifr_name, pIface) )
		// Nope, check the next one in the list
			continue;
		// Is this an internet interface?
		/*
		if (ifr->ifr_addr.sa_family == AF_INET)
		{
			strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));
			if (ioctl (nSD, SIOCGIFHWADDR, &ifreq) < 0)
			{
	printf("SIOCGIFHWADDR(%s): %m\n", ifreq.ifr_name);
	return 0;
			}
		}
		*/
		//cIPAddr = ( (struct sockaddr_in *)  &ifr->ifr_addr)->sin_addr;
		cIPAddr = (struct sin_addr *)malloc(sizeof(struct in_addr));
		memmove( (void *) cIPAddr, (void *)&(( (struct sockaddr_in *)  &ifr->ifr_addr)->sin_addr), sizeof(struct in_addr) );

	}
	//
	// Clean up things and return
	//
	if_freenameindex( pListSave );
	close( nSD );
	return( 1 );
}


//
//
//					CHECKSUM FUNCTIONS
//
//

///
//			IP CHECKSUM
///
/* Ripped from Richard Stevans Book */
unsigned short computeIpChecksum(unsigned char *header, int len)
{
         long sum = 0;  /* assume 32 bit long, 16 bit short */
	 unsigned short *ip_header = (unsigned short *)header;

         while(len > 1){
             sum += *((unsigned short*) ip_header)++;
             if(sum & 0x80000000)   /* if high order bit set, fold */
               sum = (sum & 0xFFFF) + (sum >> 16);
             len -= 2;
         }

         if(len)       /* take care of left over byte */
             sum += (unsigned short) *(unsigned char *)ip_header;
          
         while(sum>>16)
             sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}

///
//		TCP CHECKSUM
///
unsigned short tcp_sum_calc(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], unsigned short buff[])
{
    unsigned char prot_tcp=6; // Constant
    unsigned long sum;
    int nleft;
    unsigned short *w;
 
    sum = 0;
    nleft = len_tcp;
    w=buff;
 
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
 
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
	    sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }
 
    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];
    
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
 
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
 
    // Take the one's complement of sum
    sum = ~sum;
 
	return ((unsigned short) sum);
}


///
//		UDP CHECKSUM
///
unsigned short udp_sum_calc(unsigned short len_udp, unsigned short src_addr[],unsigned short dest_addr[], unsigned short buff[])
{
	uint16_t *buf = buff;
	unsigned long sum = 0;
	int nleft = len_udp;
	
	while (nleft > 1)
	{
		sum += *buf++;
		// See if we are filled up?  (Would be a huge UDP packet, but who knows)
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		nleft -= 2;
	}
	
	// Do we have an odd number?  (Add the remainder)
	if (nleft > 0)
		//sum += *((uint8_t *)buf);
		sum += *buf&ntohs(0xFF00);
	
	// add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];
    
    sum += htons(len_udp);
    sum += htons(IPPROTO_UDP);
    
    // Add any carries
    while (sum >> 16)
    	sum = (sum & 0xFFFF) + (sum >> 16);
    	
    // Return the one's complement
    return ( (unsigned short) (~sum) );
}


//
//
//
//					GENERATE GENERIC HEADERS  (Good for default values)
//
//

///
//		CREATE ETHERNET HEADER (struct)
///
struct ethhdr *createEthernetHeader(struct ethhdr *ethernet_header, char *src_mac, char *dst_mac, int protocol) {
	
	// copy our mac address
	memcpy(ethernet_header->h_source, (void*)src_mac, 6);
	memcpy(ethernet_header->h_dest, (void*)dst_mac, 6);
	// set the protocol	
	ethernet_header->h_proto = htons(protocol);
	
	return ethernet_header;
}

///
//		CREATE IP HEADER (struct)
/// http://en.wikipedia.org/wiki/IPv4#Packet_structure
struct iphdr *createIPHeader(struct iphdr *ip_header, char *srcip, char *destip) {
	ip_header->version = 4;
	ip_header->ihl = (sizeof(struct iphdr))/4 ;
	ip_header->tos = 0;
	ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct tcphdr)));
	ip_header->id = htons(111);
	ip_header->frag_off = 0;
	ip_header->ttl = 111;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->check = 0; /* We will calculate the checksum later */
	ip_header->saddr = inet_addr(srcip);
	ip_header->daddr = inet_addr(destip);
	
	ip_header->check = computeIpChecksum((unsigned char *)ip_header, ip_header->ihl*4);

	return ip_header;
}

///
//		CREATE TCP HEADER (struct)
/// http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
void createTCPHeader(struct tcphdr *tcp_header,  u_int16_t src_port, u_int16_t dest_port) {
	
	tcp_header->source =  htons(src_port);
	tcp_header->dest =  htons(dest_port);
	tcp_header->seq = htonl(random());
	tcp_header->ack_seq = htonl(0);
	tcp_header->res1 = 0;
	tcp_header->doff = sizeof(struct tcphdr)/4;
	tcp_header->fin = 0;
	tcp_header->syn = 1;
	tcp_header->rst = 0;
	tcp_header->psh = 0;
	tcp_header->ack = 0;
	tcp_header->urg = 0;
	tcp_header->res2 = 0;
	tcp_header->window = htons (57344);
	tcp_header->check = 0;
	tcp_header->urg_ptr = 0;
	
	tcp_header->check = 0;
	//return tcp_header;
}

///
//		CREATE DNS HEADER (struct)
/// http://www.binarytides.com/blog/dns-query-code-in-c-with-winsock-and-linux-sockets/
void createDNSHeader(struct DNS_HEADER *dns_header, u_int16_t id) {
	dns_header->id = (unsigned short)htons(id); 
	dns_header->qr = 0; //This is a query
	dns_header->opcode = 0; //This is a standard query
	dns_header->aa = 0; //Not Authoritative
	dns_header->tc = 0; //This message is not truncated
	dns_header->rd = 1; //Recursion Desired
	dns_header->ra = 0; //Recursion not available! 
	dns_header->z = 0;
	dns_header->ad = 0;
	dns_header->cd = 0;
	dns_header->rcode = 0;
	dns_header->q_count = htons(1); //we have only 1 question
	dns_header->ans_count = 0;
	dns_header->auth_count = 0;
	dns_header->add_count = 0;
}

///
//		CREATE UDP HEADER (struct)
/// http://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
void createUDPHeader(struct udphdr *udp_header, u_int16_t src_port, u_int16_t dest_port) {
	udp_header->source = htons(src_port);
	udp_header->dest = htons(dest_port);
	udp_header->len = 0;
	udp_header->check = 0;
}


//
//
//								SUPPLEMENTAL FUNCTIONS
//
//

// Given host, write it to dns in the dns format
void dnsNameFormat(unsigned char* dns,unsigned char* host) {
	int i, lastPtr;
	lastPtr = 0;
	// go through the string one chracter at a time
	for(i = 0 ; i <= (int)strlen((char*)host) ; i++) {
	
		// did we hit a '.' or end of string?
		if(host[i]=='.' || i == (int)strlen((char*)host)) {
			// write the length to the output
			*dns++=i-lastPtr;
			// write all of the text after it
			for(;lastPtr<i;lastPtr++) {
				*dns++=host[lastPtr];
			}
			// increment our pointer one more (its currently on the '.' or \0)
			lastPtr++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

// Given a pointer into a DNS packet, read the name
// Thanks: http://www.binarytides.com/blog/dns-query-code-in-c-with-winsock-and-linux-sockets/
unsigned char* readDNSName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;
	 
	*count = 1;
	name = (unsigned char*)malloc(256);
 
	name[0]='\0';
 
	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		// is the value our 11 marker?
		if(*reader>=192)
		{
			// The pointer is 2 bytes
			//  +256 is a shift
			//  then add the second byte
			//  remove the 11 marker from the beginning
			//  (Each pointer is of the form 11________)
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
			name[p++]=*reader; // Just append the character
			
 		// increment pointer
		reader=reader+1;
 
		if(jumped==0) *count = *count + 1; //if we havent jumped to another location then we can count up
	}
 
	name[p]='\0'; //string complete
	if(jumped==1) *count = *count + 1; //number of steps we actually moved forward in the packet
	 
	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
	{
		p=name[i];
		for(j=0;j<(int)p;j++)
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	return name;
}


//
//
//								NETWORKING FUNCTIONS
//
//


///
//		PERFORMS AN ARP_REQUEST TO RESOLVE THE MAC ADDRESS FOR destip
///
unsigned char *arpRequest(int s,  struct sockaddr *socket_address, char *srcip, char *destip) {

	unsigned char rtnMac[8];
	
	// buffer for ethernet frame
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	void* bufferPtr = buffer;
	// Ethernet Header
	struct ethhdr *ethernet_header;
	ethernet_header = buffer;

	// Copy Contents into header
	char destination_mac[] = "FF:FF:FF:FF:FF:FF";
	createEthernetHeader(ethernet_header,cMacAddr,destination_mac,ETHERTYPE_ARP);
	memset(ethernet_header->h_dest, 0xFF, 6);
	//ethernet_header->h_proto = htons(ETHERTYPE_ARP);//0x00;

	// Fill out header
	struct arphdr *arp_header;
	arp_header = buffer+sizeof(struct ethhdr);
	arp_header->ar_hrd = htons(ARPHRD_ETHER);
	arp_header->ar_pro = htons(0x0800); // IP (Not sure what the constant name is for this :/ )
	arp_header->ar_hln = 6; // length of MAC address
	arp_header->ar_pln = 4; // length of ip Address
	arp_header->ar_op = htons(ARPOP_REQUEST);
	
	// Fill out our request
	struct arp_req *arp_request;
	arp_request = buffer+sizeof(struct ethhdr)+sizeof(struct arphdr);
	memcpy((void*) &arp_request->src_mac, (void*)cMacAddr, 6);
	arp_request->src_ip = inet_addr(srcip);
	
	memset((void*) &arp_request->dest_mac, 0x00, 6);
	arp_request->dest_ip = inet_addr(destip);

	// Send packet
	int send_result = 0;
	send_result = sendto(s, buffer, sizeof(struct ethhdr)+sizeof(struct arphdr)+sizeof(struct arp_req), 0, (const struct sockaddr *)socket_address, sizeof(struct 	sockaddr_ll));
	if (send_result == -1) {
		printf("FAILED TO SEND ARP REQUEST!!");
	}


	// Now lets get our response
	// note: All of our pointers are already set up since we are using the same buffer  :-)
	int response = 0;
	int n;
	int trys = 0;
	int MAX_TRYS = 1000;
	while (trys++ < MAX_TRYS) {
		if (n = recvfrom(s,buffer,2048,0,NULL,NULL)== -1) {
			perror("recvfrom");
	      exit(1);
		} 
		// Is the packet an ARP Reply?
		if (buffer != NULL && ethernet_header->h_proto == htons(ETHERTYPE_ARP) && arp_header->ar_op == htons(ARPOP_REPLY)){
			/* DEBUG!
			printf("\n--------------------------------------"
				"\nMAC destino (server): "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				ethhead[0],ethhead[1],ethhead[2],
				ethhead[3],ethhead[4],ethhead[5]);
			printf("MAC origen  (CAL30x): "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				ethhead[6],ethhead[7],ethhead[8],
				ethhead[9],ethhead[10],ethhead[11]);  
			printf("proto: %d %d %d %d\n",ethernet_header->h_proto,ethhead[12],ethhead[13],htons(ARPOP_REQUEST));
			printf("ar_hrd: %d  ar_pro: %d  ar_hln: %d  ar_pln: %d  ar_op: %d\n",arp_header->ar_hrd,arp_header->ar_pro ,arp_header->ar_hln,arp_header->ar_pln,arp_header->ar_op);
			printf("nMAC src: "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				arp_request->src_mac[0],arp_request->src_mac[1],arp_request->src_mac[2],
				arp_request->src_mac[3],arp_request->src_mac[4],arp_request->src_mac[5]);
			printf("MAC dest: "
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				arp_request->dest_mac[0],arp_request->dest_mac[1],arp_request->dest_mac[2],
				arp_request->dest_mac[3],arp_request->dest_mac[4],arp_request->dest_mac[5]);  
				printf("ip src: %d %d \n",arp_request->src_ip,inet_addr(srcip));
				printf("ip dest: %d %d \n",arp_request->dest_ip,inet_addr(destip));
				*/
				// Its a reply and crafted correctly, must be to us!
				if (
					inet_addr(srcip) == arp_request->dest_ip &&
					inet_addr(destip) == arp_request->src_ip
					) {
					memcpy(&rtnMac,arp_request->src_mac,8);
					response = 1;
					break;
				}
		}    
	}


	free(bufferPtr);
	if (response == 0)
		return NULL;
	else
		return rtnMac;
}


unsigned char *dnsRequest(int s,  struct sockaddr *socket_address, char *srcip, char *dnsip, char *destHostname, char *gatewayMac,char *resolved_ip) {

	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	void* bufferPtr = buffer;

	u_int16_t src_port = 4500;

	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	struct DNS_HEADER *dns_header;
	struct DNS_QUESTION *dns_question;
	unsigned char *dns_question_name;
	
	int headerSize, dataSize;
	
	headerSize = dataSize = 0;
	
	ethernet_header = buffer;
	createEthernetHeader(ethernet_header, cMacAddr, gatewayMac, ETHERTYPE_IP);

	ip_header = buffer+sizeof(struct ethhdr);
	createIPHeader(ip_header,srcip,dnsip);
	ip_header->protocol = IPPROTO_UDP;


	
	udp_header = buffer+sizeof(struct ethhdr)+sizeof(struct iphdr);//(struct tcphdr *)malloc(sizeof(struct tcphdr));
	createUDPHeader(udp_header,src_port,53);
	
	headerSize = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr);
	
	dns_header = buffer+headerSize;
	unsigned short dnsID = rand();//GetCurrentProcessId();
	createDNSHeader(dns_header,dnsID); // initialize a DNS query
	
	dns_question_name = buffer+headerSize+sizeof(struct DNS_HEADER);
	dnsNameFormat(dns_question_name,destHostname);
	
	//printf ("%s %s\n",destHostname,dns_question);


	dns_question = buffer+headerSize+sizeof(struct DNS_HEADER)+(strlen((const char*)dns_question_name)+1); // size of headers + the length of the string + the \0 char.
	
	dns_question->qtype = htons(1); // ipv4
	dns_question->qclass = htons(1); // internet works
	
	dataSize = sizeof(struct DNS_HEADER)+(strlen((const char*)dns_question_name)+1) + sizeof(struct DNS_QUESTION);

	// Calculate IP Checksum
	//ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct tcphdr))+dataSize);
	ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct udphdr))+dataSize);
	ip_header->check = 0;
	ip_header->check = computeIpChecksum((unsigned char *)ip_header, ip_header->ihl*4);
	
	
	udp_header->len = htons(8+dataSize);
	udp_header->check = 0;
	udp_header->check = (unsigned short) udp_sum_calc((unsigned short) (sizeof(struct udphdr)+dataSize), (unsigned short *) 	&ip_header->saddr, (unsigned short *) &ip_header->daddr, (unsigned short *) udp_header);

	// Send packet
	int send_result = 0;
	send_result = sendto(s, buffer,headerSize+dataSize, 0, (const struct sockaddr *)socket_address, sizeof(struct 	sockaddr_ll));
	if (send_result == -1) {
		printf("FAILED TO SEND ARP REQUEST!!");
	}


	// Now lets get our response
	// note: Some of our pointers are already set up since we are using the same buffer  :-)
	int response = 0;
	int n;
	int trys = 0;
	int MAX_TRYS = 1000;
	while (trys++ < MAX_TRYS) {
		if (n = recvfrom(s,buffer,2048,0,NULL,NULL)== -1) {
			perror("recvfrom");
	      exit(1);
		} 
		// Is the packet an ARP Reply?
		if (buffer != NULL 
			&& ethernet_header->h_proto == htons(ETHERTYPE_IP) 
			&& ip_header->protocol ==  IPPROTO_UDP) {
			if (dns_header->id == (unsigned short)htons(dnsID)){
				// Its a reply and crafted correctly, must be to us!
				printf("\nThe response contains : ");
				printf("\n %d Questions.",ntohs(dns_header->q_count));
				printf("\n %d Answers.",ntohs(dns_header->ans_count));
				printf("\n %d Authoritative Servers.",ntohs(dns_header->auth_count));
				printf("\n %d Additional records.\n\n",ntohs(dns_header->add_count));
				// Read the answers
				void *resPtr = buffer+headerSize+dataSize;
				struct DNS_R_DATA *dns_response;
				char *response_name;
				char *response_ip;
				int i;
				// just used to resolve the ip
				struct sockaddr_in a;
				long *p;
				
				printf("Listing Answers:\n");
				for (i = 0; i < ntohs(dns_header->ans_count); i++) {
					int offset = 0;
					response_name = readDNSName(resPtr,buffer+headerSize,&offset);
					printf("   name: %s\n",response_name);
					dns_response = resPtr+offset;
					printf("   type: %d\n",ntohs(dns_response->type));
					printf("   _class: %d\n",ntohs(dns_response->_class));
					printf("   ttl: %d\n",ntohs(dns_response->ttl));
					printf("   data_len: %d\n",ntohs(dns_response->data_len));
					free(response_name);
					if (ntohs(dns_response->type) == 1) {
						p = (long*)(resPtr+offset+sizeof(struct DNS_R_DATA));
						a.sin_addr.s_addr = *p;
						response_ip = inet_ntoa(a.sin_addr);
						resolved_ip = (char *)malloc(strlen(response_ip)+1);
						memcpy(resolved_ip,response_ip,strlen(response_ip));
						resolved_ip[strlen(response_ip)] = '\0';
						printf("   IPv4 address : %s\n",resolved_ip);
						// We found one IP, that's enough
						break;
					}
					resPtr += offset+sizeof(struct DNS_R_DATA)+ntohs(dns_response->data_len);
				}
					break;
			}
				
		}    
	}
	
	free(bufferPtr);
	return resolved_ip;
}

///
//		SEND AND HTTP GET / REQUEST
///
void httpRequest(int s,  struct sockaddr *socket_address, char *srcip, char *gatewayMac,char *dest_ip) {

	void* buffer = (void*)malloc(ETH_FRAME_LEN);

	void* bufferPtr = buffer;

	void* packetData;

	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;

	u_int16_t src_port = 45000;

	int headerSize, dataSize;
	
	headerSize = dataSize = 0;
	
	ethernet_header = buffer;
	createEthernetHeader(ethernet_header, cMacAddr, gatewayMac, ETHERTYPE_IP);

	ip_header = buffer+sizeof(struct ethhdr);
	createIPHeader(ip_header,srcip,dest_ip);
	ip_header->protocol = IPPROTO_TCP;


	unsigned short sequenceNumber = rand();//GetCurrentProcessId();
	tcp_header = buffer+sizeof(struct ethhdr)+sizeof(struct iphdr);//(struct tcphdr *)malloc(sizeof(struct tcphdr));
	createTCPHeader(tcp_header,src_port,80);
	tcp_header->seq = htonl(sequenceNumber);
	
	headerSize = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr);
	
	packetData = buffer+headerSize;
	

	// Calculate IP Checksum
	ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct tcphdr))+dataSize);
	ip_header->check = 0;
	ip_header->check = computeIpChecksum((unsigned char *)ip_header, ip_header->ihl*4);
	
	// Calculate TCP Checksum
	tcp_header->check = 0;
	tcp_header->check = (unsigned short) tcp_sum_calc((unsigned short) (sizeof(struct tcphdr)+dataSize), (unsigned short *) 	&ip_header->saddr, (unsigned short *) &ip_header->daddr, (unsigned short *) tcp_header);

	// Send SYN packet
	int send_result = 0;
	send_result = sendto(s, buffer,headerSize+dataSize, 0, (const struct sockaddr *)socket_address, sizeof(struct 		sockaddr_ll));
	if (send_result == -1) {
		printf("FAILED TO SEND SYN PACKET!");
	}


	// Now lets get our SYN-ACK response
	// note: All the pointers still work because we are overwriting the same buffer.
	int response = 0;
	int n;
	int trys = 0;
	int MAX_TRYS = 1000;
	int ack_seqn = 0;
	while (trys++ < MAX_TRYS) {
		if (n = recvfrom(s,buffer,2048,0,NULL,NULL)== -1) {
			perror("recvfrom");
	      exit(1);
		} 
		// Is the packet part of our TCP handshake?
		if (buffer != NULL 
			&& ethernet_header->h_proto == htons(ETHERTYPE_IP) 
			&& ip_header->protocol ==  IPPROTO_TCP
			&& tcp_header->syn == 1
			&& tcp_header->ack == 1) {
				printf("%d %d\n",htonl(sequenceNumber+1),tcp_header->ack_seq);
				if (tcp_header->ack_seq == htonl(sequenceNumber+1)) {
					ack_seqn = ntohl(tcp_header->seq);
					break;
				}
			}
	}
	if (trys == MAX_TRYS) {
		printf("No SYN-ACK received!!\n");
		return;
	}
	printf("Got SYN-ACK, Sending ACK...\n");
	// Reset our buffer
	createEthernetHeader(ethernet_header, cMacAddr, gatewayMac, ETHERTYPE_IP);
	createIPHeader(ip_header,srcip,dest_ip);
	createTCPHeader(tcp_header,src_port,80);
	
	tcp_header->syn = 0;
	tcp_header->ack = 1;
	tcp_header->seq = htonl(sequenceNumber+1);
	tcp_header->ack_seq = htonl(ack_seqn+1);
	

	// Calculate IP Checksum
	ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct tcphdr))+dataSize);
	ip_header->check = 0;
	ip_header->check = computeIpChecksum((unsigned char *)ip_header, ip_header->ihl*4);
	
	// Calculate TCP Checksum
	tcp_header->check = 0;
	tcp_header->check = (unsigned short) tcp_sum_calc((unsigned short) (sizeof(struct tcphdr)+dataSize), (unsigned short *) 	&ip_header->saddr, (unsigned short *) &ip_header->daddr, (unsigned short *) tcp_header);


	// Send our ACK
	send_result = 0;
	send_result = sendto(s, buffer,headerSize+dataSize, 0, (const struct sockaddr *)socket_address, sizeof(struct 		sockaddr_ll));
	if (send_result == -1) {
		printf("FAILED TO SEND SYN PACKET!");
	}

	
	char httpRequest[] = "GET / HTTP/1.1\r\n\0";
	
	memcpy(packetData,httpRequest,strlen(httpRequest));
	
	dataSize = strlen(httpRequest);
	
	//src_port++;
	//tcp_header->source = src_port;
	
	
	// Calculate IP Checksum
	ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct tcphdr))+dataSize);
	ip_header->check = 0;
	ip_header->check = computeIpChecksum((unsigned char *)ip_header, ip_header->ihl*4);
	
	// Calculate TCP Checksum
	tcp_header->check = 0;
	tcp_header->check = (unsigned short) tcp_sum_calc((unsigned short) (sizeof(struct tcphdr)+dataSize), (unsigned short *) 	&ip_header->saddr, (unsigned short *) &ip_header->daddr, (unsigned short *) tcp_header);
	
	// Send our HTTP REQUEST
	send_result = 0;
	send_result = sendto(s, buffer,headerSize+dataSize, 0, (const struct sockaddr *)socket_address, sizeof(struct 		sockaddr_ll));
	if (send_result == -1) {
		printf("FAILED TO SEND SYN PACKET!");
	}
	
	
	trys = 0;
	while (trys++ < MAX_TRYS) {
		if (n = recvfrom(s,buffer,2048,0,NULL,NULL)== -1) {
			perror("recvfrom");
	      exit(1);
		} 
		// Is the packet part of our TCP handshake?
		if (buffer != NULL 
			&& ethernet_header->h_proto == htons(ETHERTYPE_IP) 
			&& ip_header->protocol ==  IPPROTO_TCP
			//&& tcp_header->dest == htons(src_port)
			) {
				printf("response:%s\n\n\n",packetData);
		}
	}
}

//char gatewayip[] = "152.2.131.227";
//char gatewayip[] = "152.2.130.115";
char gatewayip[] = "152.2.128.1";
//char gatewayip[] = "8.8.8.8";

///
//		MAIN FUNCTION
///
int main(int argc, char **argv) {

	// Get input?




	printf("Detecting interface configuration...\n");
	// Try to mac the address for eth0 (hardcoded)
	if (! GetSvrMacAddress("eth0") ) {
		printf("ERROR: Could not find mac addres of eth0.");
		exit(0);
	}
	printf("-------------------------------------------\n"); 
	printf( "Hardware (MAC) Address: %02X:%02X:%02X:%02X:%02X:%02X\n",cMacAddr[0], cMacAddr[1], cMacAddr[2],	cMacAddr[3], cMacAddr[4], cMacAddr[5] );
	// Convert IP to readable
	//	char srcip[] = "1.2.3.4";
	char srcip[15];
	inet_ntop(AF_INET, cIPAddr, srcip, INET_ADDRSTRLEN);
	printf("Internet IP Address: %s\n", srcip);
	printf("-------------------------------------------\n");
	
	
  /* Seed our random function with Clock Time */
  /* Used for sequence numbers etc. */
  srand((unsigned) time(NULL));

	printf("Opening a RAW socket...\n");

	int s; // Socket 
	
	//
	// Open our RAW socket
	//
	s = createRawSocket(ETH_P_ALL);
	
	if (s < 0) {
		printf("ERROR: Could not open a RAW socket.");
		exit(0);
	}
	
	/*prepare sockaddr_ll*/
	struct sockaddr_ll *socket_address; // Target address
	socket_address = (struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll));
			
	/*RAW communication*/
	socket_address->sll_family   = PF_PACKET;	
	/*we don't use a protocoll above ethernet layer
	  ->just use anything here*/
	socket_address->sll_protocol = htons(ETH_P_IP);	
	
	/*index of the network device
	see full code later how to retrieve it*/
	socket_address->sll_ifindex  = 2;
	
	/*ARP hardware identifier is ethernet*/
	socket_address->sll_hatype   = ARPHRD_ETHER;
		
	/*target is another host*/
	socket_address->sll_pkttype  = PACKET_OTHERHOST;
	
	/*address length*/
	socket_address->sll_halen    = ETH_ALEN;		
	/*MAC - begin*/
	socket_address->sll_addr[0]  = cMacAddr[0];//0x00;		
	socket_address->sll_addr[1]  = cMacAddr[1];//0x01;		
	socket_address->sll_addr[2]  = cMacAddr[2];//0x02;
	socket_address->sll_addr[3]  = cMacAddr[3];//0x03;
	socket_address->sll_addr[4]  = cMacAddr[4];//0x04;
	socket_address->sll_addr[5]  = cMacAddr[5];//0x05;
	/*MAC - end*/
	socket_address->sll_addr[6]  = 0x00;/*not used*/
	socket_address->sll_addr[7]  = 0x00;/*not used*/
	


	//
	//		Get our Gateway's MAC Address
	//
	printf("-------------------------------------------\n");
	printf("Arping our Gateway IP to get its MAC Address...\n");
	
	char* gateMac;
	gateMac = arpRequest(s,socket_address,srcip,gatewayip);
	if (gateMac == NULL) {
		printf("Could not find the gateway's MAC!");
		exit(0);
	} else {
		memcpy(gatewayMacAddr,gateMac,8);
		printf("Found Gateways MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",gatewayMacAddr[0], gatewayMacAddr[1], gatewayMacAddr[2],	gatewayMacAddr[3], gatewayMacAddr[4], gatewayMacAddr[5] );
		
	}
	
	char destHostname[] = "spensky-lt.cs.unc.edu";
	char dnsip[] = "8.8.8.8";
	//
	//		Perform a DNS Request on the requested webserver IP
	//
	printf("-------------------------------------------\n");
	printf("Sending a dns query to %s to resolve %s...",dnsip,destHostname);
	
		
	char *dest_ip; // 3 1 3 1 3 1 3 1 = 3*4 + 4 = 16
	char *destPtr;
	
	destPtr = dnsRequest(s,socket_address,srcip,dnsip,destHostname,gatewayMacAddr,dest_ip);
	
	
	//
	//		Perform a DNS Request on the requested webserver IP
	//
	printf("-------------------------------------------\n");
	printf("Sending a HTTP GET request to %s...\n",destHostname);
	httpRequest(s,socket_address,srcip,gatewayMacAddr,destPtr);
	
	// buffer for ethernet frame
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	
	
	/*other host MAC address*/
	unsigned char destination_mac[6] = {0x00, 0x21, 0x86, 0x9F, 0x51, 0x0A};
				

	//
	//		ETHERNET HEADER
	//
	struct ethhdr *ethernet_header;
	ethernet_header = buffer;
	// Copy Contents into header
	createEthernetHeader(ethernet_header,cMacAddr,destination_mac,ETHERTYPE_IP);
	//memcpy(ethernet_header->h_dest, (void*)destination_mac, 6);
	//ethernet_header->h_proto = htons(ETHERTYPE_IP);//0x00;
	
	
	//
	//		IP HEADER
	//
	//char srcip[] = "1.2.3.4";
	char destip[] = "5.6.7.8";
	int j;
	// Create IP header and fill in fields
	struct iphdr *ip_header;
	ip_header = buffer+sizeof(struct ethhdr);
	createIPHeader(ip_header,srcip,destip);
	
	
	//
	//		TCP HEADER
	//
	ip_header->protocol = IPPROTO_TCP;
	struct tcphdr *tcp_header;
	//tcp_header = buffer+sizeof(struct ethhdr)+sizeof(struct iphdr);//(struct tcphdr *)malloc(sizeof(struct tcphdr));
	//createTCPHeader(tcp_header);
	
	
	//
	//		UDP HEADER
	//
	ip_header->protocol = IPPROTO_UDP;
	struct udphdr *udp_header;
	udp_header = buffer+sizeof(struct ethhdr)+sizeof(struct iphdr);//(struct tcphdr *)malloc(sizeof(struct tcphdr));
	createUDPHeader(udp_header,1,2);
		
	
	//
	//		DATA AND CHECKSUMS
	//
	//int headerSize = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr);
	int headerSize = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr);
	
	char message[] = "HELLO!!\0";
	int dataSize = strlen(message);
	
	// Calculate IP Checksum
	//ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct tcphdr))+dataSize);
	ip_header->tot_len = htons((sizeof(struct iphdr)+sizeof(struct udphdr))+dataSize);
	ip_header->check = 0;
	ip_header->check = computeIpChecksum((unsigned char *)ip_header, ip_header->ihl*4);
	
	// Include our message
	memcpy((void*)buffer+headerSize, (void*)message,  dataSize);
	
	// Calculate TCP Checksum
	//tcp_header->check =  (unsigned short) tcp_sum_calc((unsigned short) (sizeof(struct tcphdr)+dataSize), (unsigned short *) 	&ip_header->saddr, (unsigned short *) &ip_header->daddr, (unsignIPPROTO_RAWed short *) tcp_header);
	//printf("tcp checksum: 0x%x",tcp_header->check);

	
	udp_header->len = htons(8+dataSize);
	udp_header->check = (unsigned short) udp_sum_calc((unsigned short) (sizeof(struct udphdr)+dataSize), (unsigned short *) 	&ip_header->saddr, (unsigned short *) &ip_header->daddr, (unsigned short *) udp_header);

	/*send the packet*/
	int send_result = 0;

	//send_result = sendto(s, buffer, headerSize+dataSize, 0, (const struct sockaddr *)socket_address, sizeof(struct 	sockaddr_ll));
	if (send_result == -1) {
		printf("FAILED TO SEND!!");
	}


	printf("\nDone.\n");
	
	/*
	struct ethhdr *eh;
	int length = 0; 
	//length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
	if (length == -1) { printf("oh no"); }
	eh = buffer;
 printf( "srcMac: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->h_source[0],  eh->h_source[1],  eh->h_source[2],	 eh->h_source[3],  eh->h_source[4],  eh->h_source[5] );
*/
/*
	//int s;
	struct sockaddr_in saddr2;
	char packet[50];

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("error:");
		exit(EXIT_FAILURE);
	}

	memset(packet, 0, sizeof(packet));
	socklen_t *len = (socklen_t *)sizeof(saddr2);
	int fromlen = sizeof(saddr2);

	while(1) {
		if (recvfrom(s, (char *)&packet, sizeof(packet), 0,
			(struct sockaddr *)&saddr2, &fromlen) < 0)
			perror("packet receive error:");

		int i = sizeof(struct iphdr);	
		while (i < sizeof(packet)) {
			fprintf(stderr, "%c\n", packet[i]);
			i++;
		}
		printf("\n");
	}
	*/
	//struct sockaddr_ll ll;
	//struct ethhdr *eh;
	//int sock = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	/*
	int sock = s;
	if (sock < 0) {
		printf("Could not open socket!");
		exit;
	}
	
	
	size_t len;

    struct sockaddr_in	from;
    int			size, n;
    
   
    size = sizeof(from);
    char buffer2[2048];
    while (1) {
if (n = recvfrom(sock,buffer2,sizeof(buffer2),0,NULL,NULL)== -1) {
    perror("recvfrom");
     close(sock);
            exit(1);
} 
 
// n = recv(sock,buffer,2048,0);
unsigned char *iphead, *ethhead;
    ethhead = buffer2;
    if (ethhead != NULL)
              {
     
    printf("Source MAC address: "
           "%02x:%02x:%02x:%02x:%02x:%02x\n",
           ethhead[0],ethhead[1],ethhead[2],
           ethhead[3],ethhead[4],ethhead[5]);
    printf("Destination MAC address: "
           "%02x:%02x:%02x:%02x:%02x:%02x\n",
           ethhead[6],ethhead[7],ethhead[8],
           ethhead[9],ethhead[10],ethhead[11]);  
              }
       iphead = buffer2+14; 
    if (*iphead==0x45) { 
                         
      printf("Source host %d.%d.%d.%d\n",
             iphead[12],iphead[13],
             iphead[14],iphead[15]);
      printf("Dest host %d.%d.%d.%d\n",
             iphead[16],iphead[17],
             iphead[18],iphead[19]);
      printf("Source,Dest ports %d,%d\n",
             (iphead[20]<<8)+iphead[21],
             (iphead[22]<<8)+iphead[23]);
      printf("Layer-4 protocol %d\n",iphead[9]);
    }
 }    
	
	*/
	/*
	length = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);
	if (length == -1) { printf("oh no"); }
	eh = buffer;
 printf( "srcMac: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->h_source[0],  eh->h_source[1],  eh->h_source[2],	 eh->h_source[3],  eh->h_source[4],  eh->h_source[5] );
 
 */
 
 /*
	char buffer2[8192]; // single packets are usually not bigger than 8192 bytes 
	while (read (fd, buffer2, 8192) > 0) {
		 printf ("Caught tcp packet: \n" ); //buffer2+sizeof(struct iphdr)+sizeof(struct tcphdr)
		 eh = buffer2;
		 printf( "srcMac: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->h_source[0],  eh->h_source[1],  eh->h_source[2],	 eh->h_source[3],  eh->h_source[4],  eh->h_source[5] );
	}
	*/

}



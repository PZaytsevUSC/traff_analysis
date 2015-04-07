#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <math.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAXBYTES 2048
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define DEFAULT_EPOCH 1
#define ETH_ALEN	6

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* prtcl */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

struct iphdr {

	#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error  "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t prtcl;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

// udp header
struct udphdr {
		u_int16_t source;
		u_int16_t dest;
		u_int16_t len;
		u_int16_t check;

};

// tcp header
struct tcphdr {
		u_int16_t source;
		u_int16_t dest;
		u_int16_t seq;
		u_int16_t ack_seq;

		#if __BYTE_ORDER == __LITTLE_ENDIAN
		u_int16_t resl:4;
		u_int16_t	doff:4;
		u_int16_t	fin:1;
		u_int16_t syn:1;
		u_int16_t	rst:1;
		u_int16_t	psh:1;
		u_int16_t	ack:1;
		u_int16_t urg:1;
		u_int16_t ece:1;
		u_int16_t cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
		u_int16_t doff:4;
		u_int16_t	resl:4;
		u_int16_t	cwr:1;
		u_int16_t ece:1;
		u_int16_t	urg:1;
		u_int16_t	ack:1;
		u_int16_t	psh:1;
		u_int16_t rst:1;
		u_int16_t syn:1;
		u_int16_t fin:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		u_int16_t window;
		u_int16_t check;
		u_int16_t urg_ptr;

};

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
} __attribute__((packed));



struct node 
{
  struct in_addr source,dest;
	int src_port;
	int dst_port;	
	int prtcl;
  struct node *next;
	int visited;
}*current,*next,*head,*data,*trav;



// write file

void write_file(char *file_to_write,unsigned long first_pkt_sec,
 unsigned long first_pkt_usec,int packetCount,int bytes,int total_flow,
  int tcp_count,int udp_count, int icmp_count, int other_count, 
  int verbose,int tcp_flow, int udp_flow)
{

	int file_exists;
	FILE *file;
	file = fopen(file_to_write,"r");
	if(file == NULL) file_exists = 0;
	else file_exists = 1;

	if(file_exists == 1)
	{
		
		file = fopen(file_to_write,"a+");		
		if(verbose == 1)
		{
				fprintf(file,"%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,
				first_pkt_usec,packetCount,bytes,total_flow,tcp_count,udp_count,
				icmp_count,other_count,tcp_flow,udp_flow);
		}

		else
		{
			fprintf(file,"%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,packetCount,bytes,total_flow);
		}

		fclose(file);
	}

	else
	{
		file = fopen(file_to_write,"w+b");		
		if(verbose == 1)
		{
			fprintf(file,"%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,
			first_pkt_usec,packetCount,bytes,total_flow,tcp_count,udp_count,
			icmp_count,other_count,tcp_flow,udp_flow);		
		}

		else
		{
			fprintf(file,"%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,packetCount,bytes,total_flow);
		}
		fclose(file);
	}

}

// tcp for 5 tuple

int count_tcp_5_tuple()
{
	int count = 0 ;
	current = head;
	
	while(current !=  NULL)
	{
	    if(current->visited == 0 && current->prtcl == 2)
	    {
					trav = head->next;
					current->visited = 1;
					count++;
		while(trav !=  NULL)
		{
			
		   if(trav->visited == 0)
		   {
				if(strcmp(strdup(inet_ntoa(current->source)),strdup(inet_ntoa(trav->source)))  ==  0 && 
					strcmp(strdup(inet_ntoa(current->dest)),strdup(inet_ntoa(trav->dest)))  ==  0 && 
					current->src_port == trav->src_port && current->dst_port == trav->dst_port)
			{
				trav->visited = 1;
			}
			
		   }
		    trav = trav->next;	
		}
	   }  
		current = current->next;
	}

	return count;

}

// count 5 tuple tcp flow linked list

int count_tcp()
{
	int count = 0 ;
	current = head;
	
	while(current!=  NULL)
	{
	    if(current->visited == 0 && current->prtcl == 2)
	    {
					trav = head->next;
					current->visited = 1;
					count++;

		while(trav !=  NULL)
		{
			
		   if(trav->visited == 0)
		   {
					if(strcmp(strdup(inet_ntoa(current->source)),strdup(inet_ntoa(trav->source)))  ==  0 && 
						strcmp(strdup(inet_ntoa(current->dest)),strdup(inet_ntoa(trav->dest)))  ==  0)
			{
				trav->visited = 1;
			}
			
		   }
		    trav = trav->next;	
		}
	   }  
		current = current->next;
	}
	return count;

}

// count 5 tuple udp flow linked list

int count_udp_5_tuple()
{
	int count = 0 ;
	current = head;
	
	while(current!=  NULL)
	{
	    if(current->visited == 0 && current->prtcl == 1)
	    {
				trav = head->next;
				current->visited = 1;
				count++;
		while(trav !=  NULL)
		{
			
		   if(trav->visited == 0)
		   {
					if(strcmp(strdup(inet_ntoa(current->source)),strdup(inet_ntoa(trav->source)))  ==  0 && 
						strcmp(strdup(inet_ntoa(current->dest)),strdup(inet_ntoa(trav->dest)))  ==  0 && 
						current->src_port == trav->src_port && current->dst_port == trav->dst_port)
			{
				trav->visited = 1;
				
			}
			
		   }
		    trav = trav->next;	
		}
	   }  
		current = current->next;
	}
	return count;

}

// count 5 tuple other flow linked list

int count_other_5_tuple()
{
	int count = 0 ;
	current = head;
	
	while(current!=  NULL)
	{
	    if(current->visited == 0 && current->prtcl == 0)
	    {
					trav = head->next;
					current->visited = 1;
					count++;
		while(trav !=  NULL)
		{
			
		   if(trav->visited == 0)
		   {
					if(strcmp(strdup(inet_ntoa(current->source)),strdup(inet_ntoa(trav->source)))  ==  0
					 && strcmp(strdup(inet_ntoa(current->dest)),strdup(inet_ntoa(trav->dest)))  ==  0 
					 && current->src_port == trav->src_port && current->dst_port == trav->dst_port)
			{
				trav->visited = 1;
				
			}
			
		   }
		    trav = trav->next;	
		}
	   }  
		current = current->next;
	}
	return count;

}
// count udp flow linked list

int count_udp()
{
	int count = 0 ;
	current = head;
	
	while(current!=  NULL)
	{
	    if(current->visited == 0 && current->prtcl == 1)
	    {
					trav = head->next;
					current->visited = 1;
					count++;
		while(trav !=  NULL)
		{
			
		   if(trav->visited == 0)
		   {
					if(strcmp(strdup(inet_ntoa(current->source)),strdup(inet_ntoa(trav->source)))  ==  0 && 
						strcmp(strdup(inet_ntoa(current->dest)),strdup(inet_ntoa(trav->dest)))  ==  0)
			{
				trav->visited = 1;
				
			}
			
		   }
		    trav = trav->next;	
		}
	   }  
		current = current->next;
	}
	return count;

}

// count other linked list prtcl

int count_other()
{
	int count = 0 ;
	current = head;
	
	while(current!=  NULL)
	{
	    if(current->visited == 0)
	    {
					trav = head->next;
					current->visited = 1;
					count++;
		while(trav !=  NULL)
		{
			
		   if(trav->visited == 0)
		   {
			if(strcmp(strdup(inet_ntoa(current->source)),strdup(inet_ntoa(trav->source)))  ==  0 
				&& strcmp(strdup(inet_ntoa(current->dest)),strdup(inet_ntoa(trav->dest)))  ==  0)
			{
				trav->visited = 1;
				
			}
			
		   }
		    trav = trav->next;	
		}
	   }  
		current = current->next;
	}
	return count;

}


// delete a linked list

void delete_list()
{
	current = head;
	while(current !=  NULL)
	{
		next = current->next;
		free(current);
		current = next;
	}
	head = NULL;
}

// node  = > UDP linked list prtcl

void flow_udp(const u_char *packet)
{
		
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;     
    struct iphdr *iph  =  (struct iphdr *)(packet +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct udphdr *udph  =  (struct udphdr*)(packet + iphdrlen  + sizeof(struct ethhdr));
  
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    data  =  (struct node *)malloc(sizeof (struct node));
    data->source = source.sin_addr;
    data->dest = dest.sin_addr;
    data->src_port = ntohs(udph->source);
    data->dst_port = ntohs(udph->dest);
    data->prtcl = 1;
    data->visited = 0;

    if(head == NULL)
    {
			head = data;
			head->next = NULL;
    }

    else
    {
			data->next = head;
      head = data;
     }  
    

}

// node  = > TCP linked list prtcl

void flow_tcp(const u_char *packet)
{
    
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;
    struct iphdr *iph  =  (struct iphdr *)(packet +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph  =  (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    data  =  (struct node *)malloc(sizeof (struct node));
    data->source = source.sin_addr;
    data->dest = dest.sin_addr;
    data->src_port = ntohs(tcph->source);
    data->dst_port = ntohs(tcph->dest);
    data->prtcl = 2;
    data->visited = 0;
	 
    if(head == NULL)
    {
			head = data;
			head->next = NULL;
	
    }

    else
    {
				data->next = head;
        head = data;
     }
	
}

void other_flow(const u_char *packet)
{		
		struct sockaddr_in source,dest;
		unsigned short iphdrlen;
		struct iphdr *iph  =  (struct iphdr *)(packet +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
   
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    
    
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    data  =  (struct node *)malloc(sizeof (struct node));
    data->source = source.sin_addr;
    data->dest = dest.sin_addr;
    data->src_port = ntohs(tcph->source);
    data->dst_port = ntohs(tcph->dest);
    data->prtcl = 0;
    data->visited = 0;
	 
    if(head == NULL)
    {
			head = data;
			head->next = NULL;
    }

    else
    {
			data->next = head;
      head = data;

    }

}

int dump_live_packet(const u_char *packet, const struct pcap_pkthdr *header)
{
	const struct sniff_ip *ip;

	int size_ip;
	
	ip  =  (struct sniff_ip*)(packet + SIZE_ETHERNET);
     	size_ip = IP_HL(ip) * 4;
	
	if (size_ip < 20) {
		
		return -1; // -1 - means non IPv4 packet
	}
	
	switch(ip->ip_p) 
	{
		// TCP packet = 1
		case IPPROTO_TCP:
			 return 1; 
			break;
		// UDP packet = 2
		case IPPROTO_UDP:
			 return 2; 
			 break;
		// ICMP packet = 3
		case IPPROTO_ICMP:
			 return 3; 
			 break;
		default:
		// Illegal Value
			if(header->caplen < header->len)
			{
				return -1;
		// other packet = 4
			}	
			else
			{

				return 4; 
			}
			break;

	}
	
}

int main(int argc, char *argv[])
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int count;
	struct pcap_pkthdr *header;
	u_int pkCount = 0;
	char *dev;
	int res;
	long first_pkt_sec = 0;
	long first_pkt_usec = 0;
	long second_pkt_sec;
	long second_pkt_usec;
	const u_char *pkt_data;
	pcap_t *descr = NULL;
	bpf_u_int32 bytes=0;
	int prtcl;
	int tcp_count=0, udp_count=0, icmp_count=0, other_count=0;
	int tcp_flow = 0;
	float epoch = DEFAULT_EPOCH;
	int verbose = 0;
	int file = 0;
	char *filename = NULL;
	int interface;
	char *interface_name;
	int file_name=0;
	char *file_to_write;
	int tuple = 0;
	int udp_flow = 0;
	int total_flow = 0;
	
	

	 

	if (argc < 2)
	{
	fprintf(stderr, "Usage: %s -v [-r | --read filename] [-i | --int interface] [-T | --time epoch] [-w |--write filename] [-z |--track {2|5}]\n", argv[0]); 
		exit(1); 

	}

	else
	{
		  for (count = 1; count < argc; count++)
		  {
	  			// Time option
				if(strcmp(argv[count],"-T") == 0 || strcmp(argv[count],"--time") == 0) 
				{
						if(argv[++count] !=  NULL)
						{
							if(atof(argv[count]) > 0)
							{
								epoch = atof(argv[count]);
							}
							else
							{
								printf("Wrong time, defaults to 1 sec.\n");
								
							}
							
						}
						else
						{
							printf("Wrong time, defaults to 1 sec.\n");
						}
						count--;

				}

				else if(strcmp(argv[count],"-r")  ==  0 || strcmp(argv[count],"--read")  ==  0)  // R
				{
					
					if(argv[++count] != NULL)
						{
							file = 1; 
							filename = argv[count];
						}
						else
						{
							printf("File is missing.\n");
						}
						count--;
				}

				else if(strcmp(argv[count],"-v")  ==  0 || strcmp(argv[count],"--verbose")  ==  0) verbose = 1;
				else if(strcmp(argv[count],"-i")  ==  0 || strcmp(argv[count],"--int")  ==  0) 

				{ // I
					
			
					if(argv[++count] != NULL)
					{
						if(strcmp(argv[count],"-T")!= 0)
						{
							interface = 1; 
							interface_name = argv[count];
						}		
						
					}
					else
					{
						printf("No interface. Usage: %s  -v [-r | --read filename] [-i | --int interface] [-T | --time epoch] [-w |--write filename] [-z |--track {2|5}]\n", argv[0]);
						exit(1);
					}
					count--;
				}

				else if(strcmp(argv[count],"-z")  ==  0 || strcmp(argv[count],"--track")  ==  0)
				{
					if(argv[++count] !=  NULL)
					{
						if(strcmp(argv[count],"2")  ==  0 || strcmp(argv[count],"5")  ==  0)
						{
							tuple = atoi(argv[count]);

						}
						else
						{
							printf("Wrong z value.\n");
							exit(1);

						}

					}
					else
					{
							printf("No z parameter. Usage: %s  -v [-r | --read filename] [-i | --int interface] [-T | --time epoch] [-w |--write filename] [-z |--track {2|5}]\n", argv[0]);
						exit(1);
					}

					count--;
				}
				// W
				else if(strcmp(argv[count],"-w")  ==  0 || strcmp(argv[count],"--write")  ==  0)
				{

					if(argv[++count] != NULL)
					{	
									
						file_name = 1;
						file_to_write = argv[count];
					
					}

					else
					{
						printf("No File  = > Printing to console.\n");	

					}	
					
				}
			
		      }


		      if(file == 1)
		      {

				
				handle = pcap_open_offline(filename, errbuf);

				if (handle == NULL)
				{
					fprintf(stderr, "error reading pcap file: %s\n", errbuf);
					exit(1);
				}

				if((res = pcap_next_ex(handle, &header, &pkt_data)) >=  0)
				{
		
					first_pkt_sec = header->ts.tv_sec;
					first_pkt_usec = header->ts.tv_usec;
			
					pkCount = pkCount + 1;
					bytes = bytes + header->len;
					prtcl = dump_live_packet(pkt_data,header);

							if(prtcl == 1)
							{
							        flow_tcp(pkt_data);
								tcp_count = tcp_count + 1;
							}

							else if (prtcl == 2)
							{
								flow_udp(pkt_data);
								udp_count = udp_count +1;		
							}

							else if(prtcl == 3)
							{
								other_flow(pkt_data);
								icmp_count = icmp_count+1;
							}

							else if(prtcl == 4)
							{
							
								other_flow(pkt_data);
								other_count = other_count+1;

							}

							else if(prtcl  ==  -1)
							{
								pkCount = pkCount-1;
								bytes = bytes - header->len;
							}

							second_pkt_sec  =  ((first_pkt_sec * 1000000) + first_pkt_usec + (long)(epoch * 1000000))/1000000;
							second_pkt_usec  =  ((first_pkt_sec * 1000000) + first_pkt_usec +(long)(epoch * 1000000))%1000000;			
					
					while((res = pcap_next_ex(handle, &header, &pkt_data)) >=  0)
					{
						
			if(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) < 
				(second_pkt_sec * 1000000 + second_pkt_usec)) && 
				((header->ts.tv_sec * 1000000 + header->ts.tv_usec) > 
				(first_pkt_sec * 1000000 + first_pkt_usec)))
				{
						
							pkCount = pkCount + 1;						
							bytes = bytes + header->len;
							prtcl = dump_live_packet(pkt_data,header);

							if(prtcl == 1)
							{
								flow_tcp(pkt_data);
								tcp_count = tcp_count + 1;
							}

							else if (prtcl == 2)
							{
								flow_udp(pkt_data);
								udp_count = udp_count +1;		
							}

							else if(prtcl == 3)
							{
								other_flow(pkt_data);
								icmp_count = icmp_count+1;
							}

							else if(prtcl == 4)
							{
							
								other_flow(pkt_data);
								other_count = other_count+1;
							}

							else if(prtcl == -1)
							{
								pkCount = pkCount-1;
								bytes = bytes - header->len;
							}
							
				}
				else if(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
					(second_pkt_sec * 1000000 + second_pkt_usec)) && 
					((header->ts.tv_sec * 1000000 + header->ts.tv_usec) > 
					(first_pkt_sec * 1000000 + first_pkt_usec)))
			{
				if(tuple == 2)
				{
					
					tcp_flow = count_tcp();
					udp_flow = count_udp();
					total_flow = count_other() + tcp_flow + udp_flow;
					delete_list();
				}

				else if(tuple == 5)
				{

					tcp_flow = count_tcp_5_tuple();
					udp_flow = count_udp_5_tuple();
					total_flow = count_other_5_tuple() + tcp_flow + udp_flow;
					delete_list();
				}	

if(verbose == 1 && file_name == 0)
{
			printf("%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,first_pkt_usec, 
				pkCount, bytes,total_flow, 
				tcp_count,udp_count,icmp_count,
				other_count,tcp_flow,udp_flow);
}

else if(verbose == 1 && file_name == 1)
{
					write_file(file_to_write,first_pkt_sec,
						first_pkt_usec,pkCount, bytes,total_flow,
						 tcp_count,udp_count,icmp_count,other_count,
						 verbose,tcp_flow,udp_flow);
	
}

else if(verbose == 0 && file_name == 1)
{
					write_file(file_to_write,first_pkt_sec,first_pkt_usec,
						pkCount, bytes,total_flow, tcp_count,udp_count,
						icmp_count,other_count,verbose,tcp_flow,udp_flow);

}

else
{
		printf("%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,pkCount, bytes,total_flow);
}

					first_pkt_sec = second_pkt_sec;
					first_pkt_usec = second_pkt_usec;
					second_pkt_sec  =  ((first_pkt_sec * 1000000) + first_pkt_usec + (long)(epoch * 1000000))/1000000;
					second_pkt_usec  =  ((first_pkt_sec * 1000000) + first_pkt_usec +(long)(epoch * 1000000))%1000000;
			
							tcp_count = 0;
							udp_count = 0;
							icmp_count = 0;
							other_count = 0;
							pkCount = 0;	
							bytes = 0;
							tcp_flow = 0;
							udp_flow = 0;
							total_flow  = 0;
							
		while(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
			(second_pkt_sec * 1000000 + second_pkt_usec)) && 
			((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
				(first_pkt_sec * 1000000 + first_pkt_usec)))
{

if(verbose == 1 && file_name == 0)
{
	printf("%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,first_pkt_usec, 
		pkCount, bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
		tcp_flow,udp_flow);
}

else if(verbose == 1 && file_name == 1)
{
	write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount, 
		bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
		verbose,tcp_flow,udp_flow);
	
}

else if(verbose == 0 && file_name == 1)
{
	write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount,
	 bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
	 verbose,tcp_flow,udp_flow);

}

else
{
		printf("%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,pkCount, bytes,total_flow);
}


			first_pkt_sec = second_pkt_sec;
			first_pkt_usec = second_pkt_usec;
			second_pkt_sec  =  ((first_pkt_sec * 1000000) + 
				first_pkt_usec + (long)(epoch * 1000000))/1000000;
			second_pkt_usec  =  ((first_pkt_sec * 1000000) + 
				first_pkt_usec +(long)(epoch * 1000000))%1000000;
		}

		if(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) < 
			(second_pkt_sec * 1000000 + second_pkt_usec)) && 
			((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
				(first_pkt_sec * 1000000 + first_pkt_usec)))	
		{
							pkCount = pkCount + 1;						
							bytes = bytes + header->len;
							prtcl = dump_live_packet(pkt_data,header);

							if(prtcl == 1)
							{
								flow_tcp(pkt_data);
								tcp_count = tcp_count + 1;
							}

							else if (prtcl == 2)
							{
								flow_udp(pkt_data);
								udp_count = udp_count +1;		
							}

							else if(prtcl == 3)
							{
								other_flow(pkt_data);
								icmp_count = icmp_count+1;
							}

							else if(prtcl == 4)
							{
								other_flow(pkt_data);
								other_count = other_count+1;

							}

							else if(prtcl  ==  -1)
							{
								pkCount = pkCount-1;
								bytes = bytes - header->len;
							}


			  }
					
			}

		}
				if(tuple == 2)
				{
					tcp_flow = count_tcp();
					udp_flow = count_udp();
					total_flow = count_other() + tcp_flow + udp_flow;
					delete_list();
				}

				else if(tuple == 5)
				{
					tcp_flow = count_tcp_5_tuple();
					udp_flow = count_udp_5_tuple();
					total_flow = count_other_5_tuple() + tcp_flow + udp_flow;
					delete_list();
				}
	
if(verbose == 1 && file_name == 0)
{
	printf("%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,first_pkt_usec, 
		pkCount, bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
		tcp_flow,udp_flow);
}

else if(verbose == 1 && file_name == 1)
{
	write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount,
	 bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
	 verbose,tcp_flow,udp_flow);
	
}

else if(verbose == 0 && file_name == 1)
{
	write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount, 
		bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
		verbose,tcp_flow,udp_flow);

}

else
{
	printf("%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,
		pkCount, bytes,total_flow);		
}	

	}      
				
}
	else if(interface == 1)
	{
				
				
				dev = interface_name;
				
				
				if ((descr = pcap_open_live(dev, MAXBYTES,1,512,errbuf))  ==  NULL){
    				fprintf(stderr, "ERROR: %s\n", errbuf);
    				exit(1);
 				}
				
				while((res = pcap_next_ex(descr, &header, &pkt_data)) >=  0)
				{
					if(header->ts.tv_sec != 0)
					{
						first_pkt_sec = header->ts.tv_sec;
						first_pkt_usec = header->ts.tv_usec;	
						break;
					 
					}
					
				}
				
				bytes = bytes + header->len;
				prtcl = dump_live_packet(pkt_data,header);
							if(prtcl == 1)
							{
								flow_tcp(pkt_data);
								tcp_count = tcp_count + 1;
							}
							else if (prtcl == 2)
							{
								flow_udp(pkt_data);
								udp_count = udp_count +1;		
							}
							else if(prtcl == 3)
							{
								other_flow(pkt_data);
								icmp_count = icmp_count+1;
							}
							else if(prtcl == 4)
							{
							  other_flow(pkt_data);								
								other_count = other_count+1;

							}
							else if(prtcl  ==  -1)
							{
								pkCount = pkCount-1;
								bytes = bytes - header->len;
							}
					second_pkt_sec  =  ((first_pkt_sec * 1000000) + first_pkt_usec + (long)(epoch * 1000000))/1000000;
					second_pkt_usec  =  ((first_pkt_sec * 1000000) + first_pkt_usec +(long)(epoch * 1000000))%1000000;	
					

					while((res = pcap_next_ex(descr,&header,&pkt_data)) >=  0)
					{
						if(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) < 
							(second_pkt_sec * 1000000 + second_pkt_usec)) &&
							 ((header->ts.tv_sec * 1000000 + header->ts.tv_usec) > 
							 	(first_pkt_sec * 1000000 + first_pkt_usec)))
						{
							pkCount = pkCount + 1;
							bytes = bytes + header->len;
							prtcl = dump_live_packet(pkt_data,header);

							if(prtcl == 1)
							{
								flow_tcp(pkt_data);
								tcp_count = tcp_count + 1;
							}

							else if (prtcl == 2)
							{
								flow_udp(pkt_data);
								udp_count = udp_count +1;		
							}

							else if(prtcl == 3)
							{
								other_flow(pkt_data);
								icmp_count = icmp_count+1;
							}

							else if(prtcl == 4)
							{
								other_flow(pkt_data);
								other_count = other_count+1;

							}

						}
		else if(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
			(second_pkt_sec * 1000000 + second_pkt_usec)) && 
			((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
				(first_pkt_sec * 1000000 + first_pkt_usec)))
{

			       if(tuple == 2)
				{
					
					tcp_flow = count_tcp();
					udp_flow = count_udp();
					total_flow  =   count_other() + tcp_flow + udp_flow;
					delete_list();
				}

				else if(tuple == 5)
				{

					tcp_flow = count_tcp_5_tuple();
					udp_flow = count_udp_5_tuple();
					total_flow = count_other_5_tuple() + tcp_flow + udp_flow;
					delete_list();
				}

		if(verbose == 1 && file_name == 0)
		{
			printf("%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,
				first_pkt_usec, pkCount, bytes,total_flow,
				tcp_count,udp_count,icmp_count,other_count,tcp_flow,udp_flow);
		}

		else if(verbose == 1 && file_name == 1)
		{
			write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount, 
				bytes,total_flow, tcp_count,udp_count,icmp_count,
				other_count,verbose,tcp_flow,udp_flow);
	
		}

		else if(verbose == 0 && file_name == 1)
		{
			write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount, 
				bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
				verbose,tcp_flow,udp_flow);
		}

		else
		{
			printf("%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,pkCount, bytes,total_flow);
		}

					first_pkt_sec = second_pkt_sec;
					first_pkt_usec = second_pkt_usec;
					second_pkt_sec  =  ((first_pkt_sec * 1000000) + first_pkt_usec + (long)(epoch * 1000000))/1000000;
					second_pkt_usec  =  ((first_pkt_sec * 1000000) + first_pkt_usec +(long)(epoch * 1000000))%1000000;	
							tcp_count = 0;
							udp_count = 0;
							icmp_count = 0;
							other_count = 0;
							pkCount = 0;	
							bytes = 0;
							tcp_flow = 0;
							udp_flow = 0;
							total_flow  = 0;

while(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
	(second_pkt_sec * 1000000 + second_pkt_usec)) && 
	((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >=  
		(first_pkt_sec * 1000000 + first_pkt_usec)))
		{

if(verbose == 1 && file_name == 0)
{
	printf("%ld.%ld %d %d %d %d %d %d %d %d %d\n",first_pkt_sec,first_pkt_usec, 
		pkCount, bytes,total_flow, tcp_count,udp_count,
		icmp_count,other_count,tcp_flow,udp_flow);
}

else if(verbose == 1 && file_name == 1)
{
	write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount,
	 bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
	 verbose,tcp_flow,udp_flow);
	
}

else if(verbose == 0 && file_name == 1)
{
	write_file(file_to_write,first_pkt_sec,first_pkt_usec,pkCount,
	 bytes,total_flow, tcp_count,udp_count,icmp_count,other_count,
	 verbose,tcp_flow,udp_flow);

}

else
{
		printf("%ld.%ld %d %d %d\n",first_pkt_sec,first_pkt_usec,pkCount, bytes,total_flow);
}



			first_pkt_sec = second_pkt_sec;
			first_pkt_usec = second_pkt_usec;
			second_pkt_sec  =  ((first_pkt_sec * 1000000) + first_pkt_usec + (long)(epoch * 1000000))/1000000;
			second_pkt_usec  =  ((first_pkt_sec * 1000000) + first_pkt_usec +(long)(epoch * 1000000))%1000000;
		}

		if(((header->ts.tv_sec * 1000000 + header->ts.tv_usec) < 
			(second_pkt_sec * 1000000 + second_pkt_usec)) && 
			((header->ts.tv_sec * 1000000 + header->ts.tv_usec) >= 
			 (first_pkt_sec * 1000000 + first_pkt_usec)))	
		{
							pkCount = pkCount + 1;						
							bytes = bytes + header->len;
							prtcl = dump_live_packet(pkt_data,header);

							if(prtcl == 1)
							{
								flow_tcp(pkt_data);
								tcp_count = tcp_count + 1;
							}

							else if (prtcl == 2)
							{
								flow_udp(pkt_data);
								udp_count = udp_count +1;		
							}

							else if(prtcl == 3)
							{
								other_flow(pkt_data);
								icmp_count = icmp_count+1;
							}

							else if(prtcl == 4)
							{
								other_flow(pkt_data);
								other_count = other_count+1;
							}

							else if(prtcl  ==  -1)
							{
								pkCount = pkCount-1;
								bytes = bytes - header->len;
							}
					
				
					}
			}
		}
	}

	else
	{

		printf("No interface or file\n");

	}
     }
	return 0;
}



  
	

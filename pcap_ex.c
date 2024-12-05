#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef struct flow_key{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    
    u_int16_t src_port;
    u_int16_t dst_port;
    
    u_int8_t protocol;
    
    int header_length;
    int payload_length;
    const u_char *payload_addr;
    
    u_int32_t last_seq;
    u_int32_t last_ack;

    int isRet;
}flow;

typedef struct{
    int total_flows;
    int tcp_flows;
    int udp_flows;
    int total_packets;
    int tcp_packets;
    int udp_packets;
    long tcp_bytes;
    long udp_bytes;
}statistics;

statistics stats = {0};

FILE *fp = NULL;

/*****************Functions******************/
void print_flow(flow *f, FILE* file_p);
void print_stats(statistics *stats, FILE* file_p);
pcap_t *offline_packet_open(char* filename, char* errbuf);
pcap_t *online_packet_open(char* device, char* errbuf);
flow *decode_IPV4(struct iphdr *ip_header);
flow *decode_IPV6(struct ip6_hdr *ip6_header);
//int check_retransmission(struct tcphdr *tcp_header, flow* packet);
int decode_TCP(struct tcphdr *tcp_header, struct iphdr *ip_header, struct ip6_hdr *ipv6_header, int ip_header_length, flow *packet, const u_char* ptr, int filter);
int decode_UDP(struct udphdr *udp_header, flow *packet, const u_char* ptr, int filter);
void read_packets(char* device, char * pcap_file, int func, int filter);
void packet_handler(u_char* user, const struct pcap_pkthdr *header, const u_char *packet);
void help();
/********************************************/



void print_flow(flow *f, FILE *file_p) {
    
    if (f == NULL) {
        printf("Error printing flow.\n");
        return;
    }

    fprintf(file_p,"\nFlow Details:\n");
    fprintf(file_p,"  Source IP: %s\n", f->src_ip);
    fprintf(file_p,"  Destination IP: %s\n", f->dst_ip);
    fprintf(file_p,"  Source Port: %u\n", f->src_port);
    fprintf(file_p,"  Destination Port: %u\n", f->dst_port); 
    fprintf(file_p,"  Protocol: %u\n", f->protocol);
    fprintf(file_p,"  Header Length: %d bytes\n", f->header_length);
    fprintf(file_p,"  Payload Length: %d bytes\n", f->payload_length);
    fprintf(file_p,"  Payload Address: %p\n", f->payload_addr);
    //if(f->isRet)
        //fprintf(file_p,"  Retransmission: %d\n", f->isRet);

    fflush(file_p);
}

void print_stats(statistics *stats, FILE* file_p){
    fprintf(file_p,"\n================= Statistics =================\n");
    fprintf(file_p,"Total Flows      : %d\n", stats->total_flows);
    fprintf(file_p,"  TCP Flows      : %d\n", stats->tcp_flows);
    fprintf(file_p,"  UDP Flows      : %d\n", stats->udp_flows);
    fprintf(file_p,"---------------------------------------------\n");
    fprintf(file_p,"Total Packets    : %d\n", stats->total_packets);
    fprintf(file_p,"  TCP Packets    : %d\n", stats->tcp_packets);
    fprintf(file_p,"  UDP Packets    : %d\n", stats->udp_packets);
    fprintf(file_p,"---------------------------------------------\n");
    fprintf(file_p,"Total TCP Bytes  : %ld\n", stats->tcp_bytes);
    fprintf(file_p,"Total UDP Bytes  : %ld\n", stats->udp_bytes);
    fprintf(file_p,"=============================================\n");

    fflush(file_p);
}

pcap_t *offline_packet_open(char* filename, char* errbuf){
    pcap_t *packet;
    packet = pcap_open_offline(filename, errbuf);
    if(packet == NULL){
        printf("\npcap_open_offline() error: %s\n", errbuf);
        exit(EXIT_FAILURE);    
    }
    printf("pcap_open_offline() success.\n");
    return packet;
}

pcap_t *online_packet_open(char* device, char* errbuf){
    pcap_t *packet;
    packet = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if(packet == NULL){
        printf("\npcap_open_online() error: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    return packet;
}

flow *decode_IPV4(struct iphdr *ip_header){
    flow* packet;

    packet=(flow*)malloc(sizeof(flow));

    struct in_addr src_addr;
    struct in_addr dst_addr;

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dst_addr, 0, sizeof(dst_addr));

    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;

    strcpy(packet->src_ip, inet_ntoa(src_addr));
    strcpy(packet->dst_ip, inet_ntoa(dst_addr));

    packet->protocol = ip_header->protocol;

    return packet;
}

flow *decode_IPV6(struct ip6_hdr *ip6_header){
    flow *packet;
    packet = (flow*)malloc(sizeof(flow));

    struct in6_addr src_addr = ip6_header->ip6_src;
    struct in6_addr dst_addr = ip6_header->ip6_dst;

    char source[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src_addr, source, INET6_ADDRSTRLEN);
    char destination[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dst_addr, destination, INET6_ADDRSTRLEN);

    packet->protocol = ip6_header->ip6_nxt;

    return packet;
}

/* int check_retransmission(struct tcphdr *tcp_header, flow* packet){
    
    return packet->isRet;
} */

int decode_TCP(struct tcphdr *tcp_header, struct iphdr *ip_header, struct ip6_hdr *ipv6_header, int ip_header_length, flow *packet, const u_char* ptr, int filter){
    packet->src_port = ntohs(tcp_header->source);
    packet->dst_port = ntohs(tcp_header->dest);

    packet->header_length= (unsigned int)tcp_header->doff * 4;

    if(ip_header != NULL && ipv6_header == NULL){
        //printf("\nip4\n");
        packet->payload_length = ntohs(ip_header->tot_len) - ip_header_length - packet->header_length;
    }
    else if(ip_header == NULL && ipv6_header != NULL){
        //printf("\nip6\n");
        packet->payload_length = ipv6_header->ip6_plen - packet->header_length;
    }
    
    packet->payload_addr = ptr + packet->header_length;
    
    int filtering;

    if(filter !=0 && packet->src_port != filter && packet->dst_port != filter){
        filtering = 1;
    }
    else{
        filtering = 0;
        stats.tcp_flows++;
        stats.total_flows++;
    }

    //check_retransmission(tcp_header, packet);

    stats.tcp_packets++;
    stats.tcp_bytes += packet->header_length + packet->payload_length;

    return filtering;
}

int decode_UDP(struct udphdr *udp_header, flow *packet, const u_char* ptr, int filter){
    packet->src_port = ntohs(udp_header->source);
    packet->dst_port = ntohs(udp_header->dest);

    packet->header_length = 8;
    packet->payload_length = ntohs(udp_header->len) - packet->header_length;

    packet->payload_addr = ptr + packet->header_length;

    int filtering;
    if(filter !=0 && packet->src_port != filter && packet->dst_port != filter){
        filtering = 1;
    }
    else{
        filtering = 0;
        stats.udp_flows++;
        stats.total_flows++;
    }
    stats.udp_packets++;
    stats.udp_bytes += ntohs(udp_header->len);

    return filtering;
}

void read_packets(char* device, char * pcap_file, int func, int filter){
    pcap_t *packet_open;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(func == 0){ //online
        packet_open = online_packet_open(device, errbuf);
        fp = fopen("online_output.txt", "w");
    }
    else if(func == 1){ //offline
        packet_open = offline_packet_open(pcap_file, errbuf);
        fp = fopen("offline_output.txt", "w");
    }
    else{
        printf("Invalid func.");
        return;
    }

    if(fp == NULL){
        printf("Error opening output file.");
        exit(EXIT_FAILURE);
    }

    if(pcap_loop(packet_open, 0, packet_handler, (u_char*)&filter) < 0){
        printf("\npcap_loop() error: %s\n", pcap_geterr(packet_open));
        exit(EXIT_FAILURE);
    }
    print_stats(&stats, stdout);
    print_stats(&stats, fp);

}

void packet_handler(u_char* user, const struct pcap_pkthdr *header, const u_char *packet){
    stats.total_packets++;
    
    struct ether_header *eth = (struct ether_header*) packet;
    
    int filter = *((int*)user);
    //printf("\n%d\n", filter);
    
    if(ntohs(eth->ether_type) == ETHERTYPE_IP){
        
        struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
        struct ip6_hdr *ipv6_header = NULL;
        
        flow *n_packet = decode_IPV4(ip_header);

        int ip_header_length = ip_header->ihl*4;
        const u_char *transport_ptr = packet + sizeof(struct ether_header)+(ip_header_length);

        if(n_packet->protocol == 6){
            struct tcphdr* tcp_header = (struct tcphdr *)transport_ptr;
            int filtering = decode_TCP(tcp_header, ip_header, ipv6_header, ip_header_length, n_packet, transport_ptr, filter);
            
            if(filtering == 0){
                print_flow(n_packet, stdout);
                print_flow(n_packet, fp);
            }

        }
        if(n_packet->protocol == 17){
            struct udphdr *upd_header= (struct udphdr*)transport_ptr;
            int filtering = decode_UDP(upd_header, n_packet, transport_ptr, filter);
            //print_flow(n_packet);
            if(filtering == 0){
                print_flow(n_packet, stdout);
                print_flow(n_packet, fp);
            }
        }
    }
    if(ntohs(eth->ether_type) == ETHERTYPE_IPV6){
        struct iphdr *ip_header = NULL;
        struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

        flow *n_packet = decode_IPV6(ipv6_header);
        int ipv6_header_size = 40;

        const u_char *transport_ptr = packet + sizeof(struct ether_header)+ ipv6_header_size;

        if(n_packet->protocol == 6){
            struct tcphdr* tcp_header = (struct tcphdr *)transport_ptr;
            int filtering = decode_TCP(tcp_header, ip_header, ipv6_header, ipv6_header_size, n_packet, transport_ptr, filter);
            //print_flow(n_packet);
            if(filtering == 0){
                print_flow(n_packet, stdout);
                print_flow(n_packet, fp);
            }
        }
        if(n_packet->protocol == 17){
            struct udphdr *upd_header= (struct udphdr*)transport_ptr;
            int filtering = decode_UDP(upd_header, n_packet, transport_ptr, filter);
            //print_flow(n_packet);
            if(filtering == 0){
                print_flow(n_packet, stdout);
                print_flow(n_packet, fp);
            }
        }
    }
}

void help(){
    printf("Usage: ./pcap_ex [-i interface] [-r pcap_file] [-f filter] [-h]\n");
    printf("  -i  Select network interface (e.g., eth0)\n");
    printf("  -r  Read pcap file\n");
    printf("  -f  Filter expression (e.g., \"port 8080\")\n");
    printf("  -h  Show this help message\n");
}

int main(int argc, char **argv){
    char* pcap_file;
    char* device;
    char* filter_expression;

    int func = -1;

    //Arguements
    int c;
    while((c = getopt(argc, argv, "i:r:f:h")) != -1){
        switch(c){
            case 'i':
                device = optarg;
                func = 0;
                break;
            case 'r':
                pcap_file = optarg;
                func = 1;
                break;
            case 'f':
                filter_expression = optarg;
                break;
            case 'h':
            default:
                help();
        }
        
    }

    if(func == 1 && access(pcap_file, F_OK) != 0){
        printf("\nFile not found.\n");
        exit(EXIT_FAILURE);
    }

    int filter = 0;
    if (filter_expression != NULL) {
        if (sscanf(filter_expression, "port %d", &filter) != 1) {
            printf("\nInvalid filter expression: %s\n", filter_expression);
            exit(EXIT_FAILURE);
        }
    }
    read_packets(device, pcap_file, func, filter);

    fclose(fp);
    return 0;
}
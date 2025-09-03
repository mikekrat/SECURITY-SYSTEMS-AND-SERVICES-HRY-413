#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518
#define MAX_FLOWS 100000

// Statistics structure
typedef struct {
    int total_packets;
    int tcp_packets;
    int udp_packets;
    int other_packets;
    long tcp_bytes;
    long udp_bytes;
} stats_t;

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t last_seq;   // Last seen sequence number
    uint32_t last_ack;   // Last seen acknowledgment number
} tcp_flow;

// Structure to store flow information
typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    int packet_count;
    int byte_count;
    uint32_t last_seq;   // Last seen sequence number
    uint32_t last_ack;   // Last seen acknowledgment number
} network_flow;

tcp_flow tcp_flows[MAX_FLOWS];
stats_t stats = {0};
network_flow flows[MAX_FLOWS];
int flow_count = 0;
int tcp_flow_count = 0;
int udp_flow_count = 0;
FILE *file;


int find_tcp_flow(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port) {
    for (int i = 0; i < tcp_flow_count; i++) {
        if (strcmp(tcp_flows[i].src_ip, src_ip) == 0 &&
            strcmp(tcp_flows[i].dst_ip, dst_ip) == 0 &&
            tcp_flows[i].src_port == src_port &&
            tcp_flows[i].dst_port == dst_port) {
            return i;
        }
    }
    return -1; // Flow not found
}

// Find a flow in the list
int find_flow(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    for (int i = 0; i < flow_count; i++) {
        if (strcmp(flows[i].src_ip, src_ip) == 0 &&
            strcmp(flows[i].dst_ip, dst_ip) == 0 &&
            flows[i].src_port == src_port &&
            flows[i].dst_port == dst_port &&
            flows[i].protocol == protocol) {
            return i;
        }
    }
    return -1; // Flow not found
}
void add_tcp_flow(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack) {
    if (tcp_flow_count < MAX_FLOWS) {
        strcpy(tcp_flows[tcp_flow_count].src_ip, src_ip);
        strcpy(tcp_flows[tcp_flow_count].dst_ip, dst_ip);
        tcp_flows[tcp_flow_count].src_port = src_port;
        tcp_flows[tcp_flow_count].dst_port = dst_port;
        tcp_flows[tcp_flow_count].last_seq = seq;
        tcp_flows[tcp_flow_count].last_ack = ack;
        tcp_flow_count++;
    }
}

// Add a new flow to the list
void add_flow(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol, int packet_size) {
    if (flow_count < MAX_FLOWS) {
        strcpy(flows[flow_count].src_ip, src_ip);
        strcpy(flows[flow_count].dst_ip, dst_ip);
        flows[flow_count].src_port = src_port;
        flows[flow_count].dst_port = dst_port;
        flows[flow_count].protocol = protocol;
        flows[flow_count].packet_count = 1;
        flows[flow_count].byte_count = packet_size;
        flow_count++;
        if(protocol == IPPROTO_TCP){
        }else if(protocol == IPPROTO_UDP){
            udp_flow_count++;
        }
    }
}

// Update an existing flow
void update_flow(int index, int packet_size) {
    flows[index].packet_count++;
    flows[index].byte_count += packet_size;
}
// Function to process packets
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const int ethernet_header_len = 14; // Ethernet header is always 14 bytes
    struct ip *ip_header = (struct ip *)(packet + ethernet_header_len);
    int ip_header_len = ip_header->ip_hl * 4;   //byte words
    char src_ip[16], dst_ip[16];
    strcpy(src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));

    // Identify the protocol
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + ethernet_header_len + ip_header_len);
        int tcp_header_len = tcp_header->th_off * 4;
        const u_char *payload = packet + ethernet_header_len + ip_header_len + tcp_header_len;

        uint16_t src_port = ntohs(tcp_header->th_sport);
        uint16_t dst_port = ntohs(tcp_header->th_dport);
        uint32_t seq = ntohl(tcp_header->th_seq);
        uint32_t ack = ntohl(tcp_header->th_ack);
        // Find or add the flow
        int index = find_flow(src_ip, dst_ip, tcp_header->th_sport, tcp_header->th_dport, ip_header->ip_p);
        int index2 = find_tcp_flow(src_ip, dst_ip, src_port, dst_port);        
        if (index == -1) {
            add_flow(src_ip, dst_ip, tcp_header->th_sport, tcp_header->th_dport, ip_header->ip_p ,header->len);
            add_tcp_flow(src_ip, dst_ip, src_port, dst_port, seq, ack);
        } else {
            update_flow(index, header->len);

            if (seq == tcp_flows[index2].last_seq) {
                // Retransmission detected
                printf("Retransmission: %s:%u -> %s:%u, Seq: %u, Ack: %u\n", src_ip, src_port, dst_ip, dst_port, seq, ack);
            } else {
                // Update flow state
                tcp_flows[index2].last_seq = seq;
                tcp_flows[index2].last_ack = ack;
            }
        }   



        printf("TCP Packet:\n");
        printf("  Source IP: %s\n", src_ip);
        printf("  Destination IP: %s\n", dst_ip);
        printf("  Source Port: %d\n", src_port);
        printf("  Destination Port: %d\n", dst_port);
        printf("  TCP Header Length: %d bytes\n", tcp_header_len);
        printf("  Payload Length: %d bytes\n", ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len));
        printf("  Payload Memory Address: %p\n\n", payload);
        fprintf(file,"TCP Packet:\n");
        fprintf(file,"  Source IP: %s\n", src_ip);
        fprintf(file,"  Destination IP: %s\n", dst_ip);
        fprintf(file,"  Source Port: %d\n", src_port);
        fprintf(file,"  Destination Port: %d\n", dst_port);
        fprintf(file,"  TCP Header Length: %d bytes\n", tcp_header_len);
        fprintf(file,"  Payload Length: %d bytes\n", ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len));
        fprintf(file,"  Payload Memory Address: %p\n\n", payload);
        
        stats.tcp_packets++;
        stats.tcp_bytes +=  ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len);

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + ethernet_header_len + ip_header_len);
        const u_char *payload = packet + ethernet_header_len + ip_header_len + sizeof(struct udphdr);

        int index = find_flow(src_ip,dst_ip, udp_header->uh_sport, udp_header->uh_dport, ip_header->ip_p);
        if (index == -1) {
            add_flow(src_ip, dst_ip, udp_header->uh_sport, udp_header->uh_dport, ip_header->ip_p ,header->len);
        } else {
            update_flow(index, header->len);
        }   

        printf("UDP Packet:\n");
        printf("  Source IP: %s\n", src_ip);
        printf("  Destination IP: %s\n", dst_ip);
        printf("  Source Port: %d\n", ntohs(udp_header->uh_sport));
        printf("  Destination Port: %d\n", ntohs(udp_header->uh_dport));
        printf("  UDP Header Length: %ld bytes\n", sizeof(struct udphdr));
        printf("  Payload Length: %d bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));
        printf("  Payload Memory Address: %p\n\n", payload);
        fprintf(file,"UDP Packet:\n");
        fprintf(file,"  Source IP: %s\n", src_ip);
        fprintf(file,"  Destination IP: %s\n", dst_ip);
        fprintf(file,"  Source Port: %d\n", ntohs(udp_header->uh_sport));
        fprintf(file,"  Destination Port: %d\n", ntohs(udp_header->uh_dport));
        fprintf(file,"  UDP Header Length: %ld bytes\n", sizeof(struct udphdr));
        fprintf(file,"  Payload Length: %d bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));
        fprintf(file,"  Payload Memory Address: %p\n\n", payload);
        stats.udp_packets++;
        stats.udp_bytes += ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
    }else{
        stats.other_packets++;
    }

    stats.total_packets++;
    
}



void print_statistics() {
    printf("\n--- Statistics ---\n");
    printf("Total Network flows: %d\n", flow_count);
    printf("Total TCP flows: %d\n", tcp_flow_count);
    printf("Total UDP flows: %d\n", udp_flow_count);
    printf("Total Packets: %d\n", stats.total_packets);
    printf("TCP Packets: %d, Total TCP Bytes: %ld\n", stats.tcp_packets, stats.tcp_bytes);
    printf("UDP Packets: %d, Total UDP Bytes: %ld\n", stats.udp_packets, stats.udp_bytes);
    printf("Other Packets: %d\n", stats.other_packets);

}

void print_to_file_statistics(FILE *file) {
    fprintf(file,"\n--- Statistics ---\n");
    fprintf(file,"Total Network flows: %d\n", flow_count);
    fprintf(file,"Total TCP flows: %d\n", tcp_flow_count);
    fprintf(file,"Total UDP flows: %d\n", udp_flow_count);
    fprintf(file,"Total Packets: %d\n", stats.total_packets);
    fprintf(file,"TCP Packets: %d, Total TCP Bytes: %ld\n", stats.tcp_packets, stats.tcp_bytes);
    fprintf(file,"UDP Packets: %d, Total UDP Bytes: %ld\n", stats.udp_packets, stats.udp_bytes);
    fprintf(file,"Other Packets: %d\n", stats.other_packets);

}

void print_flows() {
    printf("\nNetwork Flows:\n");
    printf("------------------------------------------------------------\n");
    printf("Src IP\t\tDst IP\t\tSrc Port\tDst Port\tProtocol\tPackets\tBytes\n");
    for (int i = 0; i < flow_count; i++) {
        printf("%s\t%s\t%u\t\t%u\t\t%d\t\t%d\t%d\n",
               flows[i].src_ip, flows[i].dst_ip,
               flows[i].src_port, flows[i].dst_port,
               flows[i].protocol, flows[i].packet_count, flows[i].byte_count);
    }
}

int main(int argc, char *argv[]) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *filename = NULL;
    char *filter_exp = NULL;
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            dev = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0) {
            filename = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0) {
            filter_exp = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: ./pcap_ex -i <interface> | -r <file> [-f <filter>]\n");
            exit(0);
        }
    }

    if (dev) {
        printf("Capturing live traffic on interface: %s\n", dev);
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        file = fopen("online_output.txt", "w");
        if (file == NULL) {
            perror("Failed to redirect output to file");
            exit(EXIT_FAILURE);
        }
    } else if (filename) {
        printf("Reading packets from file: %s\n", filename);
        handle = pcap_open_offline(filename, errbuf);
        file = fopen("offline_output.txt", "w");
        if (file == NULL) {
            perror("Failed to redirect output to file");
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Error: No input source provided. Use -h for help.\n");
        exit(1);
    }

    if (!handle) {
        fprintf(stderr, "Couldn't open device/file: %s\n", errbuf);
        return 2;
    }

    // Process packets
    pcap_loop(handle, 0, process_packet, NULL);

    // Print final statistics
    print_statistics();
    print_to_file_statistics(file);
    //print_flows();
    // Close handle
    pcap_close(handle);
    return 0;
}

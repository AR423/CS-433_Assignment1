#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>  // Include the pcap.h library

void process_packet(const struct pcap_pkthdr *header, const unsigned char *packet);

int main() {
    int flow_count;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *file_path = "1.pcap";  // Replace with the path to your pcap file

    // Open the pcap file for reading
    handle = pcap_open_offline(file_path, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        exit(1);
    }

    while (1) {
        struct pcap_pkthdr header;
        const unsigned char *packet;

        // Read the next packet from the pcap file
        packet = pcap_next(handle, &header);

        if (packet == NULL) {
            break;  // End of file
        }

        // Process the received packet
        process_packet(&header, packet);
        flow_count++;
    }

    pcap_close(handle);
    printf("Total number of flows: %d", flow_count);
    return 0;
}

void process_packet(const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));

    // Extract source and destination IP addresses and ports
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("(Client IP: %s, ", src_ip);
    printf("Client Port: %u, ", ntohs(tcp_header->th_sport));
    printf("Server IP: %s, ", dst_ip);
    printf("Server Port: %u)\n", ntohs(tcp_header->th_dport));
}

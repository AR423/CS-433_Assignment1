#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

void process_packet(unsigned char* buffer, int size);

int main() {
    int raw_socket;
    struct sockaddr_in server;

    // Create a raw socket with IPPROTO_TCP to capture TCP packets
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_socket < 0) {
        perror("Socket creation error");
        exit(1);
    }

    while (1) {
        unsigned char buffer[65536];  // Maximum Ethernet frame size
        int data_size;

        data_size = recvfrom(raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);

        if (data_size < 0) {
            perror("Packet receive error");
            exit(1);
        }

        // Process the received packet, treating it as a client-server communication
        process_packet(buffer, data_size);
    }

    close(raw_socket);
    return 0;
}

void process_packet(unsigned char* buffer, int size) {
    struct ip *ip_header = (struct ip *)(buffer);
    struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ip_hl << 2));

    // Extract client (source) and server (destination) information
    char client_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), client_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), server_ip, INET_ADDRSTRLEN);

    printf("(Client IP: %s, ", client_ip);
    printf("Client Port: %u, ", ntohs(tcp_header->th_sport));
    printf("Server IP: %s, ", server_ip);
    printf("Server Port: %u)\n", ntohs(tcp_header->th_dport));
}

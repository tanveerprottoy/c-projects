#include <arpa/inet.h>
#include <linux/if_ether.h>  // ETH_P_ALL
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void process_packet(unsigned char*, int);

int main() {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_size, data_size;
    unsigned char* buffer = (unsigned char*)malloc(65536);  // 64KB buffer

    // Create a raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    printf("Starting packet capture...\n");

    while (1) {
        saddr_size = sizeof(saddr);
        // Receive a packet
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            perror("Recvfrom error");
            return 1;
        }
        process_packet(buffer, data_size);
    }

    close(sock_raw);
    return 0;
}

void process_packet(unsigned char* buffer, int size) {
    struct iphdr* iph = (struct iphdr*)(buffer + 14);  // skip Ethernet header
    struct sockaddr_in src, dest;

    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("\n");
    printf("IP Packet: %s -> %s | ", inet_ntoa(src.sin_addr), inet_ntoa(dest.sin_addr));

    switch (iph->protocol) {
        case 1:
            printf("ICMP\n");
            break;
        case 6: {
            printf("TCP | ");
            struct tcphdr* tcph = (struct tcphdr*)(buffer + 14 + iph->ihl * 4);
            printf("Src Port: %u -> Dst Port: %u\n", ntohs(tcph->source), ntohs(tcph->dest));
            break;
        }
        case 17: {
            printf("UDP | ");
            struct udphdr* udph = (struct udphdr*)(buffer + 14 + iph->ihl * 4);
            printf("Src Port: %u -> Dst Port: %u\n", ntohs(udph->source), ntohs(udph->dest));
            break;
        }
        default:
            printf("Other Protocol: %d\n", iph->protocol);
    }
}

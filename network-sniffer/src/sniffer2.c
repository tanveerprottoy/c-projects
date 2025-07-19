#include <arpa/inet.h>         // For inet_ntoa (converting IP addresses)
#include <netinet/if_ether.h>  // For Ethernet header structure
#include <netinet/ip.h>        // For IP header structure
#include <netinet/tcp.h>       // For TCP header structure
#include <netinet/udp.h>       // For UDP header structure
#include <pcap.h>              // For libpcap functions
#include <stdio.h>             // For standard I/O (printf)
#include <stdlib.h>            // For standard library functions (exit)
#include <string.h>            // For string manipulation (strerror)

// Define a maximum packet length to capture
#define SNAP_LEN 1518

// Function to print raw packet data in hexadecimal and ASCII
void print_hex_ascii_line(const u_char* payload, int len, int offset) {
    int i;
    int gap;
    const u_char* ch;

    // Print offset
    printf("%05d   ", offset);

    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        // Add an extra space after 8 bytes for readability
        if (i == 7)
            printf(" ");
    }
    // Fill in missing spaces if less than 16 bytes
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
        if (gap >= 8)
            printf(" ");
    }
    printf("   ");

    // Print ASCII representation
    ch = payload;
    for (i = 0; i < len; i++) {
        // Check if character is printable, otherwise print a dot
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return;
}

// Function to dump packet payload (data)
void dump_payload(const u_char* payload, int len) {
    int len_rem = len;
    int line_width = 16;  // Number of bytes per line
    int line_len;
    int offset = 0;  // Current offset in payload

    if (len <= 0)
        return;

    // Print lines of hex and ASCII
    for (;;) {
        line_len = line_width % len_rem;
        print_hex_ascii_line(payload + offset, line_len, offset);
        len_rem -= line_len;
        offset += line_len;
        if (len_rem <= 0)
            break;
    }
    return;
}

// Callback function that libpcap calls for each captured packet
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Cast the packet to an Ethernet header structure
    const struct ether_header* ethernet_header;
    const struct ip* ip_header;
    const struct tcphdr* tcp_header;
    const struct udphdr* udp_header;
    const u_char* payload;

    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;

    // Extract Ethernet header
    ethernet_header = (struct ether_header*)packet;

    // Check if it's an IP packet (Ethernet type 0x0800)
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        // IP header starts after the Ethernet header
        ip_header = (struct ip*)(packet + ETHER_HDR_LEN);
        size_ip = ip_header->ip_hl * 4;  // ip_hl is in 32-bit words

        if (size_ip < 20) {  // Minimum IP header size is 20 bytes
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        printf("\n--- Packet Captured ---\n");
        printf("Timestamp: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
        printf("Packet length: %d bytes\n", pkthdr->len);
        printf("Captured length: %d bytes\n", pkthdr->caplen);

        printf("--- Ethernet Header ---\n");
        printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               ethernet_header->ether_shost[0], ethernet_header->ether_shost[1],
               ethernet_header->ether_shost[2], ethernet_header->ether_shost[3],
               ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
        printf("   Dest MAC:   %02x:%02x:%02x:%02x:%02x:%02x\n",
               ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1],
               ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3],
               ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
        printf("   Type:       0x%04x (IP)\n", ntohs(ethernet_header->ether_type));

        printf("--- IP Header ---\n");
        printf("   Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("   Dest IP:   %s\n", inet_ntoa(ip_header->ip_dst));
        printf("   Protocol:  %d ", ip_header->ip_p);

        // Determine protocol and parse accordingly
        switch (ip_header->ip_p) {
            case IPPROTO_TCP:
                printf("(TCP)\n");
                tcp_header = (struct tcphdr*)(packet + ETHER_HDR_LEN + size_ip);
                size_tcp = tcp_header->th_off * 4;  // th_off is in 32-bit words

                if (size_tcp < 20) {  // Minimum TCP header size is 20 bytes
                    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                    return;
                }

                printf("--- TCP Header ---\n");
                printf("   Source Port: %d\n", ntohs(tcp_header->th_sport));
                printf("   Dest Port:   %d\n", ntohs(tcp_header->th_dport));
                printf("   Flags:       0x%x\n", tcp_header->th_flags);
                printf("     SYN: %d, ACK: %d, FIN: %d, RST: %d, PSH: %d, URG: %d\n",
                       (tcp_header->th_flags & TH_SYN) != 0,
                       (tcp_header->th_flags & TH_ACK) != 0,
                       (tcp_header->th_flags & TH_FIN) != 0,
                       (tcp_header->th_flags & TH_RST) != 0,
                       (tcp_header->th_flags & TH_PUSH) != 0,
                       (tcp_header->th_flags & TH_URG) != 0);

                payload = (u_char*)(packet + ETHER_HDR_LEN + size_ip + size_tcp);
                size_payload = ntohs(ip_header->ip_len) - (size_ip + size_tcp);
                break;

            case IPPROTO_UDP:
                printf("(UDP)\n");
                udp_header = (struct udphdr*)(packet + ETHER_HDR_LEN + size_ip);
                size_udp = 8;  // UDP header is always 8 bytes

                printf("--- UDP Header ---\n");
                printf("   Source Port: %d\n", ntohs(udp_header->uh_sport));
                printf("   Dest Port:   %d\n", ntohs(udp_header->uh_dport));
                printf("   Length:      %d\n", ntohs(udp_header->uh_ulen));

                payload = (u_char*)(packet + ETHER_HDR_LEN + size_ip + size_udp);
                size_payload = ntohs(ip_header->ip_len) - (size_ip + size_udp);
                break;

            case IPPROTO_ICMP:
                printf("(ICMP)\n");
                payload = (u_char*)(packet + ETHER_HDR_LEN + size_ip);
                size_payload = ntohs(ip_header->ip_len) - size_ip;
                break;

            default:
                printf("(Other)\n");
                payload = (u_char*)(packet + ETHER_HDR_LEN + size_ip);
                size_payload = ntohs(ip_header->ip_len) - size_ip;
                break;
        }

        if (size_payload > 0) {
            printf("--- Payload (%d bytes) ---\n", size_payload);
            dump_payload(payload, size_payload);
        }
        printf("-----------------------\n\n");

    } else {
        printf("\n--- Non-IP Packet Captured ---\n");
        printf("Timestamp: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
        printf("Packet length: %d bytes\n", pkthdr->len);
        printf("Captured length: %d bytes\n", pkthdr->caplen);
        printf("   Ethernet Type: 0x%04x\n", ntohs(ethernet_header->ether_type));
        printf("----------------------------\n\n");
    }
}

int main(int argc, char* argv[]) {
    pcap_t* handle;                 // Session handle
    char* dev;                      // The device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string
    struct bpf_program fp;          // The compiled filter expression
    char filter_exp[] = "";         // Filter expression (e.g., "port 80" or "tcp")
    bpf_u_int32 mask;               // Our netmask
    bpf_u_int32 net;                // Our IP

    // Check for command-line argument for device name
    if (argc == 2) {
        dev = argv[1];
    } else {
        // Find a suitable network device if not specified
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return (2);
        }
    }
    printf("Device: %s\n", dev);

    // Get network address and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Open the device for sniffing
    // PCAP_ERRBUF_SIZE: Size of error buffer
    // SNAP_LEN: Maximum number of bytes to capture per packet
    // 1: Promiscuous mode (capture all packets, not just those destined for us)
    // 1000: Read timeout in milliseconds
    // errbuf: Error buffer
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }

    // Make sure the link layer type is Ethernet
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return (2);
    }

    // Compile the filter expression (if any)
    if (strlen(filter_exp) > 0) {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }

        // Apply the compiled filter
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }
    }

    printf("Starting packet capture on device %s...\n", dev);
    printf("Press Ctrl+C to stop.\n");

    // Start the packet capture loop
    // -1: Loop forever (or until an error or pcap_breakloop is called)
    // packet_handler: Callback function for each packet
    // NULL: User data (not used in this example)
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup
    pcap_freecode(&fp);  // Free the compiled filter
    pcap_close(handle);  // Close the capture device

    printf("\nCapture finished.\n");

    return (0);
}

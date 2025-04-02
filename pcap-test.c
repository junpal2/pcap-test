#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(const u_int8_t* mac) {
    for(int i=0; i<6; i++){
	    printf("%02x", mac[i]);
	    if(i<5) printf(":");
    }
}

void print_payload(const u_char* data, int len) {
	printf("Payload (%d bytes) : ",len);
    for (int i = 0; i < len && i < 20; i++) {
	printf("%02x", data[i]);         
        if (i<len-1 && i<19) printf("|");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Ethernet
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
            continue;

        // IP
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ip_hdr->ip_p != IPPROTO_TCP)
            continue;

        int ip_hdr_len = ip_hdr->ip_hl * 4;
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((u_char*)ip_hdr + ip_hdr_len);
        int tcp_hdr_len = tcp_hdr->th_off * 4;

        const u_char* payload = (u_char*)tcp_hdr + tcp_hdr_len;
        int total_len = ntohs(ip_hdr->ip_len);
        int payload_len = total_len - ip_hdr_len - tcp_hdr_len;

        printf("\n");
        print_mac(eth_hdr->ether_shost);
        printf(" → ");
        print_mac(eth_hdr->ether_dhost);
        printf(", %s:%d → %s:%d,\n",
               inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport),
               inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));

        if (payload_len > 0)
            print_payload(payload, payload_len);

        printf("__________________________________________________\n");
    }

    pcap_close(pcap);
    return 0;
}


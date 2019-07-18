#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <format.h>
#include <typeinfo>

#pragma pack(push,1)
struct eth_header {
    u_int8_t dst_mac[ETH_ADDR_LENGTH];	//Destination Mac Address
    u_int8_t src_mac[ETH_ADDR_LENGTH];	// Source Mac Address
    u_int16_t type; // Protocol Type
};
struct ip_header {
    uint8_t version;
    uint8_t tos;
    uint16_t ip_len;
    uint16_t id;
    uint16_t ip_off;
    uint8_t ttl;
    uint8_t protocol_id;
    uint16_t header_check;
    in_addr src_ip;
    in_addr dst_ip;
    /*
    u_int32_t src_ip;
    u_int32_t dst_ip;
    */
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urg_pointer;
    uint *option;
};
#pragma pack(pop);

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}



void printHex(int length, const u_char* packet ) {
    for (int i =0;i<length;i++) {


        printf("%02x ", packet[i]);


        if(i%15==0) {
            printf("\n");
        }
    }

    printf("\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const eth_header* ethdr;
    const ip_header* ipdr;
    const tcp_header* tcpdr;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;


    ethdr = reinterpret_cast<const eth_header*>(packet);

    printf("\n");
    /*
    printf("DST MAC :");
    for(int i=0;i<ETH_ADDR_LENGTH;i++) {
        printf("%02x ", ethdr->dst_mac[i]);
    }
    printf("\n");

    printf("DST MAC :");
    for(int i=0;i<ETH_ADDR_LENGTH;i++) {
        printf("%02x ", ethdr->src_mac[i]);
    }
    printf("\n");

    printf("ETHERNET TYPE :");
    printf("%02x", ethdr->type);
    printf("\n");
    */

    //ipdr = reinterpret_cast<const ip_header*>(packet);
    ipdr = reinterpret_cast<const ip_header*>(packet+sizeof(struct eth_header));


    printf("\n");
    /*
    printf("VER : %02x\n", ipdr->version);
    printf("tos : %02x\n", ipdr->tos);
    printf("Packet Length : %d\n", ipdr->ip_len);
    printf("Packet Length : %u\n", ipdr->ip_len);
    printf("Packet Length : %x\n", ipdr->ip_len);
    printf("id : %02x\n", ipdr->id);
    printf("ttl : %02x\n", ipdr->ttl);
    */
    printf("src_ip : %s\n", inet_ntoa(ipdr->src_ip));
    printf("dst_ip : %s\n", inet_ntoa(ipdr->dst_ip));
    printf("\n");

    tcpdr = reinterpret_cast<const tcp_header*>(packet+sizeof(struct eth_header)+sizeof(ip_header));
    printf("src_port :%d\n", htons(tcpdr->src_port));
    printf("dst_port :%d\n", htons(tcpdr->dst_port));
    /*
    printf("SRC IP :");
    for(int j=0; j<IP_VERSION; j++)
    {
        printf("%d ", ipdr->version[j]);
    }
    */



    printf("%u bytes captured\n", header->caplen);
    printHex(header->caplen, packet);

    struct tm *req_time;
    req_time = localtime(&header->ts.tv_sec);
    printf( "%d-%d-%d %d:%d:%d\n" , req_time->tm_year + 1900 , req_time->tm_mon + 1 , req_time->tm_mday , req_time->tm_hour , req_time->tm_min , req_time->tm_sec );
  }

  pcap_close(handle);
  return 0;
}

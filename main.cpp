#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <format.h>
#include <typeinfo>
#include <iostream>
#include <sstream>

#pragma pack(push,1)


/*
class eth_header2 {
    uint8_t dst_mac[ETH_ADDR_LENGTH];
    uint8_t src_mac[ETH_ADDR_LENGTH];
    uint16_t type;

    public:
        eth_header2(const u_char*)
        {

        }

};
*/

struct eth_header {
    u_int8_t dst_mac[ETH_ADDR_LENGTH];	//Destination Mac Address
    u_int8_t src_mac[ETH_ADDR_LENGTH];	// Source Mac Address
    u_int16_t type; // Protocol Type
};

struct ip_header {
    uint8_t version;
    uint8_t tos;
    uint16_t packet_len;
    uint16_t id;
    uint16_t ip_off;
    uint8_t ttl;
    uint8_t protocol_id;
    uint16_t header_check;
    in_addr src_ip;
    in_addr dst_ip;
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t header_len;
    uint8_t flags;
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
    /*
    for (int i =0;i<length;i++) {


        printf("%02x ", packet[i]);


        if(i%15==0) {
            printf("\n");
        }
    }
    */

    int i=0;
    while(i<length) {
        printf("%02x ", packet[i]);

        ++i;
        if (i%8==0)
        {
            printf(" ");
        }
        if (i%16 == 0)
        {
            printf("\n");
        }
    }

    printf("\n");
}

bool ipCheck(u_int16_t type)
{
    if (type == 8)
    {
        return true;
    }

    return false;
}

bool tcpCheck(u_int8_t protocol)
{
    if (protocol == 6)
    {
        return true;
    }

    return false;
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
    uint packet_size = 0;
    int ip_size = 0;
    int tcp_data_size = 0;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;


    ethdr = reinterpret_cast<const eth_header*>(packet);
    if (ipCheck(ethdr->type) == false)
    {
        //printf("Not an IP HEader");
   }


    printf("\n");

    ipdr = reinterpret_cast<const ip_header*>(packet+sizeof(struct eth_header));
    packet_size = htons(ipdr->packet_len);
    ip_size = (ipdr->version&0x0F)*4;



    if (tcpCheck(ipdr->protocol_id))
    {
        //printf("Not TCP");
    }




    tcpdr = reinterpret_cast<const tcp_header*>(packet+sizeof(struct eth_header)+sizeof(ip_header));
    int tcp_size = ((tcpdr->header_len&0xF0)>>4)*4;
    int option_size = tcp_size - 20;
    int eth_size = sizeof(ethdr)*4;

    tcp_data_size = packet_size - (ip_size + tcp_size);


    for(int i=0;i<ETH_ADDR_LENGTH;i++) {
        printf("%02x", ethdr->src_mac[i]);
        if (i != ETH_ADDR_LENGTH-1)
        {
            printf(":");
        }
    }
    printf(" ");

    for(int i=0;i<ETH_ADDR_LENGTH;i++) {
        printf("%02x", ethdr->dst_mac[i]);
        if (i != ETH_ADDR_LENGTH-1)
        {
            printf(":");
        }
    }
    printf(" ");

    printf(" %s:%d", inet_ntoa(ipdr->dst_ip), htons(tcpdr->dst_port));
    printf(" ");
    printf(" %s:%d", inet_ntoa(ipdr->src_ip), htons(tcpdr->src_port));
    printf(" ");

    if (tcp_data_size > 0)
    {
        const unsigned char *tcp_data = reinterpret_cast<const unsigned char*>(packet+sizeof(struct eth_header)+sizeof(ip_header)+ tcp_size);
        if (tcp_data_size > 10)
        {
            tcp_data_size = 10;
        }

        for(int i=0;i<tcp_data_size;i++)
        {
            printf("%02x ", tcp_data[i]);
        }
    }
    printf("\n");


    struct tm *req_time;
    req_time = localtime(&header->ts.tv_sec);
    //printf( "%d-%d-%d %d:%d:%d\n" , req_time->tm_year + 1900 , req_time->tm_mon + 1 , req_time->tm_mday , req_time->tm_hour , req_time->tm_min , req_time->tm_sec );
  }

  pcap_close(handle);
  return 0;
}

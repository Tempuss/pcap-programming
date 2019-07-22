#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETH_ADDR_LENGTH 0x6

/**
 * @brief The eth_header struct
 * @detail Ethernet Header Format
 */
struct eth_header {
    u_int8_t dst_mac[ETH_ADDR_LENGTH];	//Destination Mac Address
    u_int8_t src_mac[ETH_ADDR_LENGTH];	// Source Mac Address
    u_int16_t type; // Protocol Type
};

/**
 * @brief The ip_header struct
 * @detail IP Header Format
 */
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

/**
 * @brief The tcp_header struct
 * @detail TCP Header Format
 */
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
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}



/**
 * @brief printHex
 * @detail Print Packet Data with Hex Format
 * @param length
 * @param packet
 */
void printHex(int length, const u_char* packet ) {

    int i=0;
    while(i<length) {
        printf("%02X ", packet[i]);

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

/**
 * @brief ipCheck
 * @param type
 * @return bool
 */
bool ipCheck(u_int16_t type) {
    if (type == 8)
    {
        return true;
    }

    return false;
}

/**
 * @brief tcpCheck
 * @param protocol
 * @return bool
 */
bool tcpCheck(u_int8_t protocol)
{
    if (protocol == 6)
    {
        return true;
    }

    return false;
}

/**
 * @brief printValue
 * @detail Print IP Format Data
 * @param in_addr ip
 */
void printValue(in_addr ip) {
    printf(" %s", inet_ntoa(ip));
}

/**
 * @brief printValue
 * @detail Print Int Format Data
 * @param int port
 */
void printValue(int port) {
    printf(":%d ", port);
}


/**
 * @brief printValue
 * @detail print Mac Address
 * @param uint8_t[] data
 */
void printValue(const uint8_t data[]) {
    int size = sizeof(data);
    for(int i=0;i<size;i++) {
        printf("%02X", data[i]);
        if (i != size-1)
        {
            printf(":");
        }
    }

    printf(" ");
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
    const unsigned char *tcp_data;

    int res = pcap_next_ex(handle, &header, &packet);
    int packet_size = 0;
    int ip_size = 0;
    int tcp_data_size = 0;
    int tcp_size = 0;
    int option_size = 0;
    int eth_size = 0;

    if (res == 0) continue;
    if (res == -1 || res == -2) break;


    //Get Ethernet Header From Packet
    ethdr = (eth_header*)(packet);

    //Get IP Header From Packet
    ipdr = (struct ip_header*)(packet+sizeof(struct eth_header));

    packet_size = htons(ipdr->packet_len);
    ip_size = (ipdr->version&0x0F)*4;

    printValue(ethdr->src_mac);
    printValue(ethdr->dst_mac);


    //Check Next IP Header
    if (ipCheck(ethdr->type) == true)
    {

        //Get TCP Header From Packet
        tcpdr = (struct tcp_header*)(packet+sizeof(struct eth_header)+sizeof(ip_header));

        //Calculate TCP Header Size to Print TCP Data
        tcp_size = ((tcpdr->header_len&0xF0)>>4)*4;

        //Check Next Tcp Header
        if (tcpCheck(ipdr->protocol_id) == true)
        {
            eth_size = sizeof(ethdr)*4;

            //Printable TCP Data Size
            tcp_data_size = packet_size - (ip_size + tcp_size);

            printValue(ipdr->src_ip);
            printValue(tcpdr->src_port);

            printValue(ipdr->dst_ip);
            printValue(tcpdr->dst_port);

            //Check TCP Data Exists
            if (tcp_data_size > 0)
            {
                //Get TCP Data from Packet
                tcp_data = (u_char*)(packet+sizeof(struct eth_header)+sizeof(ip_header)+ tcp_size);
                printValue(tcp_data);
            }
        }
        else {
            printValue(ipdr->src_ip);
            printValue(ipdr->dst_ip);
        }
    }
    printf("\n");

  }

  pcap_close(handle);
  return 0;
}

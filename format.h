#ifndef FORMAT_H
#define FORMAT_H
// https://en.wikipedia.org/wiki/Ethernet_frame
//Every Thing is Byte

/*
 * @brief Ethernet Header Format Length
 */
#define ETH_PREAM 7
#define ETH_SFD 1
#define ETH_ADDR_LENGTH 0x6
#define ETH_TAG 0x4
#define ETH_LENGTH 0x2
#define ETH_DATA_MIN_LENGTH 0x46
#define ETH_DATA_MAX_LENGTH 0x1500
#define ETH_CRC 0x4

/*
 * @brief IP Header Format Length
 */
#define IP_VERSION 1
#define IP_LENGTH 1
#define IP_TYPE 1;
#define IP_TOS 8
#define IP_TOTAL_LENGTH = 16;
#define IP_IDENTI = 16;
#define IP_FLAG = 3;
#define IP_FRAG_OFFSET = 13;
#define IP_TTL = 8;
#define IP_PROTOCOL = 8;
#define IP_HEAD_CHECK = 16;
#define IP_BOOK = 6;
#define IP_FLAG_BIT = 1;
#define IP_ADDRLENGTH 32;
#define IP_CHECK = 16;
#define IP_URGENT = 16;


/*
 * @brief TCP Header Format Length
 */
#define TCP_PORT_LENGTH = 16;
#define TCP_SEQ_NUMBER = 32;
#define TCP_ACK_NUMBER = 32;
#define TCP_HEADER_LENGTH = 4;
#define TCP_FLAG = 6;
#define TCP_WINDOW = 16;
#define TCP_DATA_MIN = 0;
#define TCP_DATA_MAX = 10;

/*
struct eth_header {
    u_int8_t dst_mac[ETH_ADDR_LENGTH];	//Destination Mac Address
    u_int8_t src_mac[ETH_ADDR_LENGTH];	// Source Mac Address
    u_int16_t type; // Protocol Type
};
*/






#endif // FORMAT_H

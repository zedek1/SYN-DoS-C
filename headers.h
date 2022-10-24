//#pragma once
#ifndef HEADERS_H
#define HEADERS_H

//#ifdef _WIN32 || _WIN64
    #include <WinSock2.h>
//else
//    #include <sys/socket.h>
//    #include <arpa/inet.h>
//#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>

//https://cdn.kastatic.org/ka-perseus-images/ec71832edb1f2ff1d2ad12da494033ce2b25aafa.svg
struct pseudo_header
{
    u_long src_addr;     // source address - unsigned long because of s_addr
    u_long dst_addr;     // destination address
    uint8_t zero;        // must be 0 - pad
    uint8_t proto;       // protocol
    uint16_t length;     // protocol length
} pseudohead;

//https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h
struct iphdr
{
    uint8_t ihl;        // header length
    uint8_t version;    // version = 4
    uint8_t tos;        // type of service
    uint16_t tot_len;   // total length
    uint16_t id;        // identification
    uint16_t frag_off;  // fragment offset
    uint8_t ttl;        // time to live - specified in seconds
    uint8_t protocol;   // protocol
    uint16_t check;     // checksum - error checking of the header
    u_long ip_src;      // source address
    u_long ip_dst;      // destination address
};

//https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h
struct tcphdr
{
    uint16_t source;    // source port
    uint16_t dest;      // destination port
    uint32_t seq;       // sequence number - for error handling (doesn't matter)
    uint32_t ack_seq;   // acknowledgement number - for error handling (doesn't matter)
    uint16_t doff;      // min is 5 which = 20 bytes <- all we need because no options set
    uint16_t fin;       // fin flag, if set it means last packet from the sender
    uint16_t syn;       // syn flag, synchronize sequence numbers
    uint16_t rst;       // rest flag, reset the connection
    uint16_t psh;       // push flag
    uint16_t ack;       // acknowledge flag
    uint16_t urg;       // indicates whether the urgent pointer field is significant
    uint16_t res1;      // res1 flag, kinda just an extra flag
    uint16_t res2;      // res2 flag, kinda just an extra flag
    uint16_t window;    // size of the receive window, how much im willing to receive
    uint16_t check;     // check tcp header
    uint16_t urg_ptr;   // used if urg flag is set, the last urgent byte from seq num
};

void header_setup(struct iphdr* iph, struct tcphdr* tcph);
uint16_t checksum(uint16_t* buffer, int count);
uint16_t tcp_checksum(struct iphdr* iph, struct tcphdr* tcph);

#endif //HEADERS_H
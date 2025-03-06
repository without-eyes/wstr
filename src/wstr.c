/**
    * @file: wstr.c
    * @author: without eyes
    *
    * This file contains definition of functions related
    * to Without eyeS's Traceroute(WSTR).
*/

#include "../include/wstr.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define WORD_LENGTH_IN_BYTES 16
#define MAX_HOPS 30
#define PACKET_SIZE 64
#define DOMAIN_NAME_SIZE 128

struct sockaddr_in resolve_host(const char *destinationHost) {
    const struct hostent *host = gethostbyname(destinationHost);

    struct sockaddr_in destinationAddress;
    destinationAddress.sin_family = AF_INET;
    destinationAddress.sin_port = 0;
    destinationAddress.sin_addr = *(struct in_addr *)host->h_addr_list[0];

    return destinationAddress;
}

unsigned short calculate_checksum(void *buffer, int length) {
    unsigned short *wordPointer = buffer;
    unsigned int sum = 0;

    for (sum = 0; length > 1; length -= 2) {
        sum += *wordPointer++;
    }

    if (length == 1) {
        sum += *(unsigned char *)wordPointer;
    }

    sum = (sum >> WORD_LENGTH_IN_BYTES) + (sum & 0xFFFF);
    sum += (sum >> WORD_LENGTH_IN_BYTES);

    return ~sum;
}

void set_icmp_echo_fields(struct icmp* icmpHeader, const int timeToLive) {
    memset(icmpHeader, 0, sizeof(*icmpHeader));
    icmpHeader->icmp_type = ICMP_ECHO;
    icmpHeader->icmp_code = 0;
    icmpHeader->icmp_id = getpid();
    icmpHeader->icmp_seq = timeToLive;
    icmpHeader->icmp_cksum = calculate_checksum(&*icmpHeader, sizeof(*icmpHeader));
}

void print_hop_info(const int timeToLive, const double roundTripTime, const struct sockaddr_in *replyAddress, const char *packet) {
    const struct ip *ipHeader = (struct ip *)packet;
    if (ipHeader->ip_p == IPPROTO_ICMP) {
        const struct icmp *icmpReply = (struct icmp *)(packet + (ipHeader->ip_hl << 2));
        if (icmpReply->icmp_type == ICMP_ECHOREPLY || icmpReply->icmp_type == ICMP_TIME_EXCEEDED) {
            char domainName[DOMAIN_NAME_SIZE];
            const int result = getnameinfo((struct sockaddr*)replyAddress, sizeof(*replyAddress), domainName, sizeof(domainName), NULL, 0, NI_NAMEREQD);
            if (result == 0) {
                printf("%d %.3fms %s (%s)\n", timeToLive, roundTripTime, inet_ntoa(replyAddress->sin_addr), domainName);
            } else {
                printf("%d %.3fms %s\n", timeToLive, roundTripTime, inet_ntoa(replyAddress->sin_addr));
            }
        }
    }
}

void wstr(const char *destinationHost) {
    const int socketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct sockaddr_in destinationAddress = resolve_host(destinationHost);

    struct icmp icmpHeader;
    for (int timeToLive = 1; timeToLive <= MAX_HOPS; timeToLive++) {
        set_icmp_echo_fields(&icmpHeader, timeToLive);

        struct timespec sendingTime;
        clock_gettime(CLOCK_MONOTONIC, &sendingTime);

        setsockopt(socketFileDescriptor, IPPROTO_IP, IP_TTL, &timeToLive, sizeof(timeToLive));
        sendto(socketFileDescriptor, &icmpHeader, sizeof(icmpHeader), 0, (struct sockaddr *)&destinationAddress, sizeof(destinationAddress));

        char packet[PACKET_SIZE];
        struct sockaddr_in replyAddress;
        socklen_t replyAddressLength = sizeof(replyAddress);
        recvfrom(socketFileDescriptor, packet, sizeof(packet), 0, (struct sockaddr *)&replyAddress, &replyAddressLength);

        struct timespec receivingTime;
        clock_gettime(CLOCK_MONOTONIC, &receivingTime);
        const double roundTripTime = (receivingTime.tv_sec - sendingTime.tv_sec) * 1000.0 +
                                    (receivingTime.tv_nsec - sendingTime.tv_nsec) / 1000000.0;

        print_hop_info(timeToLive, roundTripTime, &replyAddress, packet);

        if (replyAddress.sin_addr.s_addr == destinationAddress.sin_addr.s_addr) {
            break;
        }
    }

    close(socketFileDescriptor);
}
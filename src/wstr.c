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
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

unsigned short calculate_checksum(void *buffer, int length) {
    unsigned short *wordPointer = buffer;
    unsigned int sum = 0;

    for (sum = 0; length > 1; length -= 2) {
        sum += *wordPointer++;
    }

    if (length == 1) {
        sum += *(unsigned char *)wordPointer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

void wstr(const char *destinationHost) {
    const struct hostent *host = gethostbyname(destinationHost);
    const int socketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct sockaddr_in destinationAddress;
    destinationAddress.sin_family = AF_INET;
    destinationAddress.sin_port = 0;
    destinationAddress.sin_addr = *(struct in_addr *)host->h_addr_list[0];

    struct icmp icmpHeader;
    for (int timeToLive = 1; timeToLive <= 30; timeToLive++) {
        memset(&icmpHeader, 0, sizeof(icmpHeader));
        icmpHeader.icmp_type = ICMP_ECHO;
        icmpHeader.icmp_code = 0;
        icmpHeader.icmp_id = getpid();
        icmpHeader.icmp_seq = timeToLive;
        icmpHeader.icmp_cksum = calculate_checksum(&icmpHeader, sizeof(icmpHeader));

        setsockopt(socketFileDescriptor, IPPROTO_IP, IP_TTL, &timeToLive, sizeof(timeToLive));
        sendto(socketFileDescriptor, &icmpHeader, sizeof(icmpHeader), 0, (struct sockaddr *)&destinationAddress, sizeof(destinationAddress));

        char packet[64];
        struct sockaddr_in replyAddress;
        socklen_t replyAddressLength = sizeof(replyAddress);
        recvfrom(socketFileDescriptor, packet, sizeof(packet), 0, (struct sockaddr *)&replyAddress, &replyAddressLength);

        const struct ip* ipHeader = (struct ip*)packet;
        if (ipHeader->ip_p == IPPROTO_ICMP) {
            const struct icmp *icmpReply = (struct icmp *)(packet + (ipHeader->ip_hl << 2));
            if (icmpReply->icmp_type == ICMP_ECHOREPLY || icmpReply->icmp_type == ICMP_TIME_EXCEEDED) {
                printf("%d %s\n", timeToLive, inet_ntoa(replyAddress.sin_addr));
            }
        }

        if (replyAddress.sin_addr.s_addr == destinationAddress.sin_addr.s_addr) {
            break;
        }
    }

    close(socketFileDescriptor);
}
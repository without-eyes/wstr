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
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define WORD_LENGTH_IN_BYTES 16
#define PACKET_SIZE 64
#define DOMAIN_NAME_SIZE 128

struct Options parse_arguments(const int argc, char *argv[]) {
    int currentOption;
    struct Options options = {
        .destinationHost = NULL,
        .interface = NULL,
        .fqdnFlag = 0,
        .maxTimeToLive = 30
    };
    const struct option longOptions[] = {
        {"domain", no_argument, NULL, 'd'},
        {"interface", required_argument, NULL, 'i'},
        {"ttl", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    while ((currentOption = getopt_long(argc, argv, "di:t:h", longOptions, NULL)) != -1) {
        switch (currentOption) {
        case 'd': // FQDN
            options.fqdnFlag = 1;
            break;

        case 'i': // interface
            options.interface = optarg;
            break;

        case 't': // TTL
            options.maxTimeToLive = atoi(optarg);
            break;

        case 'h': // help
            printf("Usage: sudo wstr [-d] [-i name] [-t number] destination\n");
            printf("  -d, --domain      Turn on displaying FQDN\n");
            printf("  -i, --interface   Set network interface\n");
            printf("  -t, --ttl         Set TTL for network packets\n");
            printf("  -h, --help        Show this help message\n");
            exit(0);

        default:
            fprintf(stderr, "Invalid option. Use -h for help.\n");
            exit(-1);
        }
    }

    if (optind == argc) {
        fprintf(stderr, "Destination host is required!\n");
        exit(-1);
    }
    options.destinationHost = argv[optind];

    return options;
}

void handle_getaddrinfo_errors(const int errorValue) {
    switch (errorValue) {
        case EAI_BADFLAGS:  printf("Invalid value for `ai_flags' field"); break;
        case EAI_NONAME:    printf("NAME or SERVICE is unknown."); break;
        case EAI_AGAIN:     printf("Temporary failure in name resolution."); break;
        case EAI_FAIL:      printf("Non-recoverable failure in name res."); break;
        case EAI_FAMILY:    printf("`ai_family' not supported."); break;
        case EAI_SOCKTYPE:  printf("`ai_socktype' not supported."); break;
        case EAI_SERVICE:   printf("SERVICE not supported for `ai_socktype'."); break;
        case EAI_MEMORY:    printf("Memory allocation failure."); break;
        case EAI_SYSTEM:    printf("System error returned in `errno'."); break;
        case EAI_OVERFLOW:  printf("Argument buffer overflow."); break;
        default:            __builtin_unreachable();
    }
}

struct sockaddr_in resolve_host(const char *destinationHost) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    const int result = getaddrinfo(destinationHost, NULL, &hints, &res);
    if (result != 0) {
        freeaddrinfo(res);
        handle_getaddrinfo_errors(result);
        exit(1);
    }

    const struct sockaddr_in destinationAddress = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

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
    icmpHeader->icmp_cksum = calculate_checksum(icmpHeader, sizeof(*icmpHeader));
}

void print_hop_info(const struct Options *options, const int timeToLive, const double roundTripTime, const struct sockaddr_in *replyAddress) {
    char domainName[DOMAIN_NAME_SIZE];
    const int result = getnameinfo((struct sockaddr*)replyAddress, sizeof(*replyAddress), domainName, sizeof(domainName), NULL, 0, NI_NAMEREQD);
    if (options->fqdnFlag == 1 && result == 0) {
        printf("%2d  %7.3lfms   %-15s (%s)\n", timeToLive, roundTripTime, inet_ntoa(replyAddress->sin_addr), domainName);
    } else {
        printf("%2d  %7.3lfms   %-15s\n", timeToLive, roundTripTime, inet_ntoa(replyAddress->sin_addr));
    }
}

double calculate_round_trip_time(const struct timespec sendingTime, const struct timespec receivingTime) {
    return (double)(receivingTime.tv_sec - sendingTime.tv_sec) * 1000.0 +
            (double)(receivingTime.tv_nsec - sendingTime.tv_nsec) / 1000000.0;
}

void wstr(const struct Options* options) {
    const int socketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketFileDescriptor == -1) {
        perror("Socket creation failed!");
        exit(1);
    }

    struct sockaddr_in destinationAddress = resolve_host(options->destinationHost);

    struct icmp icmpHeader;
    for (int timeToLive = 1; timeToLive <= options->maxTimeToLive; timeToLive++) {
        struct timespec sendingTime, receivingTime;
        struct sockaddr_in replyAddress;
        char packet[PACKET_SIZE];

        set_icmp_echo_fields(&icmpHeader, timeToLive);
        clock_gettime(CLOCK_MONOTONIC, &sendingTime);

        if (setsockopt(socketFileDescriptor, IPPROTO_IP, IP_TTL, &timeToLive, sizeof(timeToLive)) == -1) {
            perror("Function setsockopt failed while setting TTL!");
            exit(1);
        }

        if (options->interface != NULL && setsockopt(socketFileDescriptor, SOL_SOCKET, SO_BINDTODEVICE, options->interface, sizeof(options->interface)) == -1) {
            perror("Function setsockopt failed while binding socket to interface!");
            exit(1);
        }

        if (sendto(socketFileDescriptor, &icmpHeader, sizeof(icmpHeader), 0, (struct sockaddr *)&destinationAddress, sizeof(destinationAddress)) == -1) {
            perror("Function sendto failed!");
            exit(1);
        }

        socklen_t replyAddressLength = sizeof(replyAddress);
        if (recvfrom(socketFileDescriptor, packet, sizeof(packet), 0, (struct sockaddr *)&replyAddress, &replyAddressLength) == -1) {
            perror("Function recvfrom failed!");
            exit(1);
        }

        clock_gettime(CLOCK_MONOTONIC, &receivingTime);

        const struct ip *ipHeader = (struct ip *)packet;
        if (ipHeader->ip_p != IPPROTO_ICMP) {
            break;
        }

        const struct icmp *icmpReply = (struct icmp *)(packet + (ipHeader->ip_hl << 2));
        if (icmpReply->icmp_type != ICMP_ECHOREPLY && icmpReply->icmp_type != ICMP_TIME_EXCEEDED) {
            break;
        }

        print_hop_info(options, timeToLive, calculate_round_trip_time(sendingTime, receivingTime), &replyAddress);

        if (replyAddress.sin_addr.s_addr == destinationAddress.sin_addr.s_addr) {
            break;
        }
    }

    close(socketFileDescriptor);
}
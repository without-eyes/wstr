/**
    * @file: wstr.c
    * @author: without eyes
    *
    * This file contains definition of functions related
    * to Without eyeS's Traceroute(WSTR).
*/

#include "wstr.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#define WORD_LENGTH_IN_BYTES 16
#define PACKET_SIZE 64
#define DOMAIN_NAME_SIZE 128
#define ERROR_MESSAGE_SIZE 256

struct Options parse_arguments(const uint8_t argc, char *argv[]) {
    int currentOption;
    struct Options options = {
        .destinationHost = NULL,
        .interface = NULL,
        .fqdnFlag = 0,
        .maxTimeToLive = 30,
        .timeout = 3
    };
    const struct option longOptions[] = {
        {"domain", no_argument, NULL, 'd'},
        {"interface", required_argument, NULL, 'i'},
        {"ttl", required_argument, NULL, 't'},
        {"timeout", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    while ((currentOption = getopt_long(argc, argv, "di:t:o:h", longOptions, NULL)) != -1) {
        switch (currentOption) {
        case 'd': // FQDN
            options.fqdnFlag = 1;
            break;

        case 'i': // interface
            options.interface = optarg;
            break;

        case 't': // TTL
            char *ttlEndPointer;
            const long ttl = strtol(optarg, &ttlEndPointer, 10);

            if (*ttlEndPointer != '\0') {
                handle_error(1, "Invalid TTL value: %s\n", optarg);
            }

            if (ttl < 0 || ttl > UINT8_MAX) {
                handle_error(1, "TTL value is out of range(0-255): %s\n", optarg);
            }
            options.maxTimeToLive = (uint8_t) ttl;
            break;

        case 'o': // Timeout
            char *timeoutEndPointer;
            const long timeout = strtol(optarg, &timeoutEndPointer, 10);

            if (*timeoutEndPointer != '\0') {
                handle_error(1, "Invalid timeout value: %s\n", optarg);
            }

            if (timeout < 1 || timeout > UINT8_MAX) {
                handle_error(1, "Timeout value is out of range(1-255): %s\n", optarg);
            }
            options.timeout = (uint8_t) timeout;
            break;

        case 'h': // help
            printf("Usage: sudo wstr [-d] [-i name] [-t number] destination\n");
            printf("  -d, --domain      Turn on displaying FQDN\n");
            printf("  -i, --interface   Set network interface\n");
            printf("  -t, --ttl         Set TTL(0-255) for network packets\n");
            printf("  -o  --timeout     Sets timeout (in seconds, 1-255) for network packets.\n");
            printf("  -h, --help        Show this help message\n");
            exit(EXIT_SUCCESS);

        default:
            handle_error(1, "Invalid option. Use -h for help.");
        }
    }

    if (optind == argc) {
        handle_error(1, "Destination host is required!");
    }
    options.destinationHost = argv[optind];

    return options;
}

struct sockaddr_in resolve_host(const char *destinationHost) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(destinationHost, NULL, &hints, &res) != 0) {
        handle_error(1, "Failed to resolve host");
    }

    if (res == NULL) {
        handle_error(1, "No valid address found for host %s", destinationHost);
    }

    const struct sockaddr_in destinationAddress = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

    return destinationAddress;
}

uint32_t calculate_checksum(void *buffer, uint16_t length) {
    uint16_t *wordPointer = buffer;
    uint32_t sum = 0;

    for (sum = 0; length > 1; length -= 2) {
        sum += *wordPointer++;
    }

    if (length == 1) {
        sum += *(uint8_t*)wordPointer;
    }

    sum = (sum >> WORD_LENGTH_IN_BYTES) + (sum & 0xFFFF);
    sum += sum >> WORD_LENGTH_IN_BYTES;

    return ~sum;
}

void set_icmp_echo_fields(struct icmp* icmpHeader, const uint8_t timeToLive) {
    if (icmpHeader == NULL) {
        handle_error(1, "ICMP header pointer is NULL");
    }
    memset(icmpHeader, 0, sizeof(*icmpHeader));
    icmpHeader->icmp_type = ICMP_ECHO;
    icmpHeader->icmp_code = 0;
    icmpHeader->icmp_id = (uint16_t)getpid();
    icmpHeader->icmp_seq = timeToLive;
    icmpHeader->icmp_cksum = (uint16_t)calculate_checksum(icmpHeader, sizeof(*icmpHeader));
}

void print_hop_info(const struct Options *options, const uint8_t timeToLive, const double roundTripTime,
                    const struct sockaddr_in *replyAddress) {
    if (replyAddress == NULL) {
        handle_error(1, "Reply address is NULL");
        return;
    }

    char domainName[DOMAIN_NAME_SIZE];
    const int result = getnameinfo((struct sockaddr*)replyAddress, sizeof(*replyAddress), domainName,
                                    sizeof(domainName), NULL, 0, NI_NAMEREQD);
    if (options->fqdnFlag != 1 || result != 0) {
        printf("%2d  %7.3lfms   %-15s\n", timeToLive, roundTripTime, inet_ntoa(replyAddress->sin_addr));
    } else {
        printf("%2d  %7.3lfms   %-15s (%s)\n", timeToLive, roundTripTime, inet_ntoa(replyAddress->sin_addr),
                                                    domainName);
    }
}

double calculate_round_trip_time(const struct timespec sendingTime, const struct timespec receivingTime) {
    return (double)(receivingTime.tv_sec - sendingTime.tv_sec) * 1000.0 +
            (double)(receivingTime.tv_nsec - sendingTime.tv_nsec) / 1000000.0;
}

int create_socket(const struct Options *options) {
    const int socketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketFileDescriptor == -1) {
        handle_error(1, "Socket creation failed");
    }

    if (options->interface != NULL &&
        setsockopt(socketFileDescriptor, SOL_SOCKET, SO_BINDTODEVICE, options->interface,
                    sizeof(options->interface)) == -1) {
        handle_error(1, "Failed to bind socket to interface '%s'", options->interface);
    }

    return socketFileDescriptor;
}

void handle_error(const uint8_t exitFlag, const char *message, ...) {
    char errorMessage[ERROR_MESSAGE_SIZE];
    strcpy(errorMessage, "Error: ");
    strcat(errorMessage, message);

    const char* strerrorResult = strerror(errno);
    if (strcmp(strerrorResult, "Success") != 0) {
        strcat(errorMessage, ". Reason: ");
        strcat(errorMessage, strerrorResult);
    }
    strcat(errorMessage, "\n");

    va_list arg;
    va_start(arg, message);
    vfprintf(stdout, errorMessage, arg);
    va_end(arg);

    if (exitFlag) {
        exit(EXIT_FAILURE);
    }
}

void set_socket_ttl(const int socketFileDescriptor, const uint8_t timeToLive) {
    if (setsockopt(socketFileDescriptor, IPPROTO_IP, IP_TTL, &timeToLive,
                sizeof(timeToLive)) == -1) {
        handle_error(1, "Failed to set TTL (setsockopt)");
    }
}

void send_icmp_packet(const int socketFileDescriptor, const struct icmp *icmpHeader,
                      const struct sockaddr_in *destinationAddress, const uint8_t timeToLive) {
    if (sendto(socketFileDescriptor, icmpHeader, sizeof(*icmpHeader), 0,
                (struct sockaddr *)destinationAddress, sizeof(*destinationAddress)) == -1) {
        handle_error(1, "Packet send failed (sendto). Destination: %s, TTL: %d",
                      inet_ntoa(destinationAddress->sin_addr), timeToLive);
    }
}

void receive_icmp_packet(const int socketFileDescriptor, char *packet, struct sockaddr_in *replyAddr) {
    socklen_t addrLen = sizeof(*replyAddr);
    if (recvfrom(socketFileDescriptor, packet, PACKET_SIZE, 0, (struct sockaddr *)replyAddr,
                  &addrLen) == -1) {
        handle_error(1, "Packet receive failed (recvfrom)");
    }
}

uint8_t is_valid_icmp_reply(const char *packet) {
    const struct ip *ipHeader = (const struct ip *)packet;
    if (ipHeader->ip_p != IPPROTO_ICMP) {
        handle_error(0, "Unexpected protocol %d. Expected ICMP.", ipHeader->ip_p);
        return 0;
    }

    const struct icmp *icmpReply = (const struct icmp *)(packet + (ipHeader->ip_hl << 2));
    if (icmpReply->icmp_type != ICMP_ECHOREPLY && icmpReply->icmp_type != ICMP_TIME_EXCEEDED) {
        handle_error(0, "Unexpected ICMP type %d", icmpReply->icmp_type);
        return 0;
    }

    return 1;
}

void set_socket_timeout(const struct Options* options, const int socketFileDescriptor) {
    const struct timespec timeout = {options->timeout, 0};
    if (setsockopt(socketFileDescriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        handle_error(1, "Failed to set socket receive timeout");
    }
}

void wstr(const struct Options* options) {
    const int socketFileDescriptor = create_socket(options);

    const struct sockaddr_in destinationAddress = resolve_host(options->destinationHost);

    struct icmp icmpHeader;
    for (uint8_t timeToLive = 1; timeToLive <= options->maxTimeToLive; timeToLive++) {
        struct timespec sendingTime, receivingTime;
        struct sockaddr_in replyAddress;
        char packet[PACKET_SIZE];

        set_icmp_echo_fields(&icmpHeader, timeToLive);

        clock_gettime(CLOCK_MONOTONIC, &sendingTime);
        set_socket_ttl(socketFileDescriptor, timeToLive);
        set_socket_timeout(options, socketFileDescriptor);
        send_icmp_packet(socketFileDescriptor, &icmpHeader, &destinationAddress, timeToLive);
        receive_icmp_packet(socketFileDescriptor, packet, &replyAddress);
        clock_gettime(CLOCK_MONOTONIC, &receivingTime);

        if (is_valid_icmp_reply(packet)) {
            print_hop_info(options, timeToLive, calculate_round_trip_time(sendingTime, receivingTime), &replyAddress);
        }

        if (replyAddress.sin_addr.s_addr == destinationAddress.sin_addr.s_addr) {
            break;
        }
    }

    close(socketFileDescriptor);
}
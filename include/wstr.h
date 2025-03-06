/**
    * @file: wstr.h
    * @author: without eyes
    *
    * This file contains declaration of functions related
    * to Without eyeS's Traceroute(WSTR).
*/

#ifndef WSTR_H
#define WSTR_H

#include <netinet/ip_icmp.h>

/**
    * Resolves the given hostname to an IP address.
    *
    * @param[in] destinationHost The hostname to resolve.
    *
    * @return Returns a sockaddr_in structure containing
    * the resolved IP address.
*/
struct sockaddr_in resolve_host(const char *destinationHost);

/**
    * Computes the Internet checksum for a given buffer.
    *
    * @param[in] buffer The pointer to data buffer.
    * @param[in] length The length of the buffer in bytes.
    *
    * @return Returns computed cheksum.
*/
unsigned short calculate_checksum(void *buffer, int length);

/**
    * Initializes an ICMP Echo Request packet.
    *
    * @param[in] icmpHeader Pointer to the ICMP header structure
    * to initialize.
    * @param[in] timeToLive The time to live of icmp packet.
*/
void set_icmp_echo_fields(struct icmp* icmpHeader, int timeToLive);

/**
    * Prints the hop information during a traceroute operation.
    *
    * @param[in] timeToLive The current TTL value used in the
    * ICMP request.
    * @param [in]roundTripTime The time taken for hope to respond.
    * @param[in] replyAddress The address of the replying host.
    * @param[in] packet The packet received from the reply,
    * containing the ICMP response data.
    *
    * @note This function requires raw socket privileges, so
    * it need to be executed with root permissions.
*/
void print_hop_info(int timeToLive, double roundTripTime, const struct sockaddr_in *replyAddress, const char *packet);

/**
    * Performs a traceroute to the specified destination host.
    *
    * @param[in] destinationHost The destination host's domain
    * name or IP address.
    *
    * @note This function requires raw socket privileges, so
    * it need to be executed with root permissions.
*/
void wstr(const char *destinationHost);

#endif //WSTR_H
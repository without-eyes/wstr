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
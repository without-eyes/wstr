/**
    * @file: wstr.h
    * @author: without eyes
    *
    * This file contains declaration of functions related
    * to Without eyeS's Traceroute(WSTR).
*/

#ifndef WSTR_H
#define WSTR_H

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
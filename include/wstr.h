/**
    * @file: wstr.h
    * @author: without eyes
    *
    * This file contains declaration of functions related
    * to Without eyeS's Traceroute(WSTR).
*/

#ifndef WSTR_H
#define WSTR_H

unsigned short calculate_checksum(void *buffer, int length);

void wstr(const char *destinationHost);

#endif //WSTR_H
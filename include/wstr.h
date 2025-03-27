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
#include <time.h>

struct Options {
    char* destinationHost;
    char* interface;
    uint8_t fqdnFlag;
    uint8_t maxTimeToLive;
    uint8_t timeout;
};

/**
    * Performs a traceroute to the specified destination host.
    *
    * @param[in] options The options of wstr passed as arguments
    * to program.
    *
    * @note This function requires raw socket privileges, so
    * it need to be executed with root permissions.
*/
void wstr(const struct Options* options);

/**
    * Processes the command-line arguments passed to the program.
    *
    * @param[in] argc The number of arguments passed to the program
    * (including the program name).
    * @param[in] argv An array of strings representing the
    * command-line arguments.
    *
    * This function updates the program's global settings based on
    * the provided arguments:
    * - `-d` or `--domain` turn on displaying FQDN.
    * - `-i` or `--interface` specifies the network interface to use.
    * - `-t` or `--ttl` sets the Time to Live (TTL) for network packets.
    * - `-o` or `--timeout` sets timeout (in seconds) for network packets.
    * - `-h` or `--help` displays the help message with usage instructions.
    *
    * @note If invalid options are provided, the function will display an
    * error message and exit the program. The `-h` or `--help` option will
    * display the available options.
    *
    * @return Returns parsed arguments as struct Options.
*/
struct Options parse_arguments(uint8_t argc, char *argv[]);

/**
    * Handles errors by printing a message and exiting the program.
    *
    * @param exitFlag If 1, the function exits the program; if 0, it
    * only prints the error.
    * @param[in] message The error message format string (like printf).
    * @param[in] ... Additional arguments corresponding to the format
    * specifiers in message.
*/
void handle_error(uint8_t exitFlag, const char *message, ...);

/**
    * Creates a socket file descriptor and binds it to an interface
    * if specified.
    *
    * @param[in] options The options of wstr passed as arguments
    * to the program.
    *
    * @return The socket file descriptor.
    *
    * @note This function requires raw socket privileges,
    * so it must be executed with root permissions.
*/
int create_socket(const struct Options *options);

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
    * Initializes an ICMP Echo Request packet.
    *
    * @param[out] icmpHeader Pointer to the ICMP header structure
    * to initialize.
    * @param[in] timeToLive The time to live of icmp packet.
*/
void set_icmp_echo_fields(struct icmp* icmpHeader, uint8_t timeToLive);

/**
    * Computes the Internet checksum for a given buffer.
    *
    * @param[in] buffer The pointer to data buffer.
    * @param[in] length The length of the buffer in bytes.
    *
    * @return Returns computed cheksum.
*/
uint16_t calculate_checksum(void *buffer, uint16_t length);

/**
    * Sets the Time To Live option on the socket.
    *
    * @param[in] socketFileDescriptor The socket file descriptor.
    * @param[in] timeToLive The Time To Live value to set.
*/
void set_socket_ttl(int socketFileDescriptor, uint8_t timeToLive);

/**
    * Sets the timeout value for the socket.
    *
    * @param[in] options The options of wstr passed as arguments
    * to program.
    * @param[in] socketFileDescriptor The socket file descriptor..
*/
void set_socket_timeout(const struct Options* options, int socketFileDescriptor);

/**
    * Sends an ICMP packet to the specified destination address.
    *
    * @param[in] socketFileDescriptor The socket file descriptor.
    * @param[in] icmpHeader Pointer to the ICMP header to send.
    * @param[in] destinationAddress Pointer to the destination address structure.
    * @param[in] timeToLive The Time To Live value.
*/
void send_icmp_packet(int socketFileDescriptor, const struct icmp *icmpHeader,
                      const struct sockaddr_in *destinationAddress, uint8_t timeToLive);

/**
    * Receive an ICMP packet from the socket.
    *
    * @param[in] socketFileDescriptor The socket file descriptor.
    * @param[out] packet Buffer to store the received packet.
    * @param[out] replyAddress Pointer to store the sender's address.
*/
void receive_icmp_packet(int socketFileDescriptor, char *packet, struct sockaddr_in *replyAddress);

/**
    * Checks if an ICMP packet is valid.
    *
    * @param[in] packet The received packet.
    *
    * @return Returns 1 if true, 0 if false.
*/
uint8_t is_valid_icmp_reply(const char *packet);

/**
    * Prints the hop information during a traceroute operation.
    *
    * @param[in] options The options of wstr passed as arguments
    * to program.
    * @param[in] timeToLive The current TTL value used in the
    * ICMP request.
    * @param[in] roundTripTime The time taken for hope to respond.
    * @param[in] replyAddress The address of the replying host.
    *
    * @note This function requires raw socket privileges, so
    * it need to be executed with root permissions.
*/
void print_hop_info(const struct Options *options, uint8_t timeToLive, double roundTripTime,
                    const struct sockaddr_in *replyAddress);

/**
    * Calculates the round trip time (RTT) between sending and
    * receiving an ICMP Echo Request packet.
    *
    * @param[in] sendingTime The timestamp when the ICMP packet
    * was sent.
    * @param[in] receivingTime The timestamp when the ICMP Echo
    * Reply was received.
    *
    * @return The round-trip time in milliseconds.
*/
double calculate_round_trip_time(struct timespec sendingTime, struct timespec receivingTime);

#endif //WSTR_H
# WSTR - Without eyeS's Traceroute

## Overview
`wstr` is a network diagnostic utility designed to analyze and troubleshoot network connections.

## Installation
### Requirements
- Linux-based operating system
- C compiler (GCC)

### Build Instructions
```sh
# Clone the repository
git clone https://github.com/without-eyes/wstr.git
cd wstr

# Compile the source code
make

# Run the utility
sudo ./build/wstr
```

## Usage
Basic command-line usage:
```sh
sudo wstr [-d] [-i interface] [-t ttl] [-o timeout] destination
```
where:
- -d, --domain: Turn on displaying FQDN
- -i, --interface: Set network interface
- -t, --ttl: Set TTL(0-255) for network packets
- -o  --timeout: Sets timeout (in seconds, 1-255) for network packets
- -h, --help: Show this help message
  
## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


#include <netinet/in.h>  // Internet address family (for sockaddr_in, htons, htonl)
#include <stdio.h>       // Standard input/output library (for printf, perror)
#include <stdlib.h>      // Standard library (for exit)
#include <string.h>      // String manipulation functions (for strlen, memset)
#include <sys/socket.h>  // Socket API definitions (for socket, bind, listen, accept)
#include <unistd.h>      // POSIX operating system API (for close)

#define BUFFER_SIZE 1024;
const int PORT = 8080;

void main_loop(int server_fd, struct sockaddr_in address, int addr_len, char buffer[BUFFER_SIZE], const char* message) {
}

int main() {
    // define variables
    int server_fd;                               // file descriptor for server socket
    struct sockaddr_in address;                  // container to store server address info
    int addr_len = sizeof(address);              // Size of the address structure
    char buffer[BUFFER_SIZE] = {0};              // Buffer to store incoming data, initialized to zeros
    const char* message = "Hello from server!";  // Message to send back to client

    // create socket file descriptor
    // AF_INET: Address Family - IPv4
    // SOCK_STREAM: Socket Type - TCP (stream-oriented)
    // 0: Protocol - IP (default for TCP)
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // check if socket was created
    if (server_fd == 0) {
        // failed to create socket
        perror("failed to create socket");
        exit(EXIT_FAILURE);  // exit the program
    }

    // Optional: Set socket options to reuse address and port
    // This helps in quickly restarting the server after it's been stopped,
    // preventing "Address already in use" errors.
    int opt = 1;
    if 

    return EXIT_SUCCESS
}
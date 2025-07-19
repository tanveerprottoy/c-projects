#include <arpa/inet.h>   // Functions for manipulating IP addresses (for inet_ntoa)
#include <netinet/in.h>  // Internet address family (for sockaddr_in, htons, htonl)
#include <stdio.h>       // Standard input/output library (for printf, perror)
#include <stdlib.h>      // Standard library (for exit)
#include <string.h>      // String manipulation functions (for strlen, memset)
#include <sys/socket.h>  // Socket API definitions (for socket, bind, listen, accept)
#include <unistd.h>      // POSIX operating system API (for close)

#define PORT 8080         // The port number on which the server will listen
#define BUFFER_SIZE 1024  // Size of the buffer for receiving data

// main_loop contains the server's main loop
void main_loop(int server_fd, struct sockaddr_in address, int addr_len, char buffer[BUFFER_SIZE], const char* message) {
    int new_socket;  // this contains the socket/file descriptor for each client connection

    // 4. Accept incoming connections in a loop
    while (1) {
        printf("\nWaiting for a new connection...\n");

        // accept(): Blocks until a client connects.
        // It returns a new socket file descriptor for the accepted connection.
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addr_len)) < 0) {
            perror("accept failed");  // Print error message if accept fails
            // Continue to the next iteration instead of exiting, to keep the server running
            continue;
        }

        // Print client information
        printf("Connection accepted from %s:%d\n",
               inet_ntoa(address.sin_addr),  // Convert IP address to string
               ntohs(address.sin_port));     // Convert port to host byte order

        // 5. Read data from the client
        // read(): Reads up to BUFFER_SIZE bytes from the client socket into the buffer.
        // The return value is the number of bytes read.
        ssize_t bytes_read = read(new_socket, buffer, BUFFER_SIZE);
        if (bytes_read < 0) {
            perror("read failed");
            close(new_socket);  // Close the client socket on error
            continue;
        }

        // Null-terminate the received data to treat it as a string
        buffer[bytes_read] = '\0';
        printf("Client message: %s\n", buffer);

        // 6. Send a response back to the client
        // send(): Sends the specified message to the client socket.
        // MSG_NOSIGNAL: Prevent SIGPIPE signal if client closes connection prematurely
        if (send(new_socket, message, strlen(message), MSG_NOSIGNAL) < 0) {
            perror("send failed");
        } else {
            printf("Sent response: %s\n", message);
        }

        // 7. Close the client socket
        // It's crucial to close the client socket when done with it.
        close(new_socket);
        printf("Client disconnected.\n");
    }
}

int init_server() {
    int server_fd;                               // File descriptors for the server socket
    struct sockaddr_in address;                  // Structure to hold server address information
    int addr_len = sizeof(address);              // Size of the address structure
    char buffer[BUFFER_SIZE] = {0};              // Buffer to store incoming data, initialized to zeros
    const char* message = "Hello from server!";  // Message to send back to client

    // 1. Create socket file descriptor
    // AF_INET: Address Family - IPv4
    // SOCK_STREAM: Socket Type - TCP (stream-oriented)
    // 0: Protocol - IP (default for TCP)
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // check if socket was created successfully
    if (server_fd == 0) {
        perror("socket failed");  // Print error message if socket creation fails
        exit(EXIT_FAILURE);       // Exit the program
    }

    // Optional: Set socket options to reuse address and port
    // This helps in quickly restarting the server after it's been stopped,
    // preventing "Address already in use" errors.
    int opt = 1;

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);  // close the socket
        exit(EXIT_FAILURE);
    }

    // Configure server address structure
    // AF_INET: IPv4 address family
    // INADDR_ANY: Listen on all available network interfaces
    // htons(PORT): Convert port number to network byte order (Host TO Network Short)
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 2. Bind the socket to the specified IP address and port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");  // Print error message if binding fails
        close(server_fd);       // close the socket
        exit(EXIT_FAILURE);     // Exit the program
    }

    // 3. Listen for incoming connections
    // 10: Maximum number of pending connections in the queue
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");  // Print error message if listen fails
        close(server_fd);         // close the socket
        exit(EXIT_FAILURE);       // Exit the program
    }

    printf("Server listening on port %d\n", PORT);

    // init main loop
    main_loop(server_fd, address, addr_len, buffer, message);

    // Close the listening server socket (this part will typically not be reached
    // in an infinite loop, but good practice for proper shutdown if loop breaks)
    close(server_fd);

    return EXIT_SUCCESS;  // Indicate successful execution
}

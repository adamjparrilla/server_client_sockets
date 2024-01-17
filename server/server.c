#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>

// Enumeration for TCP flags
enum FLAGS {
  FIN,
  SYN_FLAG,  // Renamed from SYN to avoid conflict
  RST,
  PSH,
  ACK_FLAG,
  URG
};

// Enum for the states
enum STATES {
  LISTEN_STATE,  // Renamed from SYN to avoid conflict
  SYN,
  SYN_ACK_STATE,
  ACK_STATE
};

// Structure for the TCP header
struct tcp_header {
  uint16_t source_port;
  uint16_t destination_port;
  uint32_t sequence_number;
  uint32_t acknowledgment_number;
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
};

// Initialize the TCP header
void initialize_tcp_header(struct tcp_header *header, uint16_t src_port, uint16_t dest_port, uint32_t seq_num, uint8_t flags, uint16_t window_size, uint16_t checksum, uint16_t urgent_pointer) {
  header->source_port = htons(src_port);
  header->destination_port = htons(dest_port);
  header->sequence_number = htonl(seq_num);
  header->acknowledgment_number = htonl(seq_num + 1);
  header->flags = flags;
  header->window_size = htons(window_size);
  header->checksum = htons(checksum);
  header->urgent_pointer = htons(urgent_pointer);
}

// Sets the TCP flags
void set_flags(struct tcp_header *header, int state) {
  header->flags = 0x00;
  uint16_t temp_port = header->source_port;
  header->source_port = header->destination_port;
  header->destination_port = temp_port;
  header->sequence_number = htonl(ntohl(header->acknowledgment_number));
  header->acknowledgment_number = htonl(ntohl(header->acknowledgment_number) + 1);  

  switch(state) {
  case LISTEN_STATE:
    // No changes for LISTEN_STATE state
    break;
  case SYN:
    header->flags |= (1 << SYN_FLAG);
    break;
  case SYN_ACK_STATE:
    header->flags |= (1 << SYN_FLAG) | (1 << ACK_FLAG);
    break;
  case ACK_STATE:
    header->flags |= (1 << ACK_FLAG);
    break;
  default:
    fprintf(stderr, "Invalid state\n");
    exit(1);
  }
}

// Print TCP header information
void print_header(const struct tcp_header *header, const char *step) {
  printf("-------- %s --------\n", step);
  printf("Source Port: %d\n", ntohs(header->source_port));
  printf("Destination Port: %d\n", ntohs(header->destination_port));
  printf("Sequence Number: %u\n", ntohl(header->sequence_number));
  printf("Acknowledgment Number: %u\n", ntohl(header->acknowledgment_number));

  printf("Flags: ");
  if (header->flags & (1 << SYN_FLAG)) printf("SYN ");
  if (header->flags & (1 << ACK_FLAG)) printf("ACK ");
  printf("\n");

  printf("Window Size: %d\n", ntohs(header->window_size));
  printf("Checksum: 0x%04x\n", ntohs(header->checksum));
  printf("Urgent Pointer: %d\n", ntohs(header->urgent_pointer));
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    exit(1);
  }

  int port = atoi(argv[1]);
  struct sockaddr_in server_address;

  // Create the server socket
  int server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket == -1) {
    perror("Error creating socket");
    exit(1);
  }
  printf("Server Socket has been created\n");

  // Set up server address structure
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port);
  server_address.sin_addr.s_addr = INADDR_ANY;

  // Bind the server socket
  if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
    perror("Error binding socket");
    exit(1);
  }

  // Listen for incoming connections
  if (listen(server_socket, 1) == -1) {
    perror("Error listening for connections");
    exit(1);
  }
  printf("Server is listening on port %d...\n", port);

  // Accept a client connection
  struct sockaddr_in client_address;
  socklen_t client_address_len = sizeof(client_address);
  int client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_address_len);
  if (client_socket == -1) {
    perror("Error accepting connection");
    exit(1);
  }

  printf("Accepted connection from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

  // Declare handshake_header here
  struct tcp_header handshake_header;

  // Simulate 3-way handshake
  initialize_tcp_header(&handshake_header, port, ntohs(client_address.sin_port), rand(), 0, 17520, 0xffff, 0);
  
  set_flags(&handshake_header, LISTEN_STATE); // No output for LISTEN_STATE state

  set_flags(&handshake_header, SYN);
  print_header(&handshake_header, "SYN State");

  set_flags(&handshake_header, SYN_ACK_STATE);
  print_header(&handshake_header, "SYN_ACK State");

  set_flags(&handshake_header, ACK_STATE);
  print_header(&handshake_header, "ACK State");

  // Close sockets
  close(client_socket);
  close(server_socket);

  return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // Include arpa/inet.h for inet_addr function
#include <unistd.h>
#include <stdint.h>
#include <time.h> // Added for time functions

// Enumeration for TCP flags
enum FLAGS {
  FIN,
  SYN_FLAG,
  RST,
  PSH,
  ACK_FLAG,
  URG
};

// Enum for the states
enum STATES {
  LISTEN,
  SYN_STATE,
  SYN_ACK_STATE,
  ACK_STATE,
  FINAL_ACK_STATE
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
  case LISTEN:
    // No changes for LISTEN state
    break;
  case SYN_STATE:
    header->flags |= (1 << SYN_FLAG);
    break;
  case SYN_ACK_STATE:
    header->flags |= (1 << SYN_FLAG) | (1 << ACK_FLAG);
    break;
  case ACK_STATE:
    header->flags |= (1 << ACK_FLAG);
    break;
  case FINAL_ACK_STATE:
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

  // Create the client socket
  int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  printf("Client Socket has been created\n");

  // Connect to the server
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port);
  server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); // Use inet_addr function
  connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address));
  printf("Connected to server\n");

  // Declare client_address here
  struct sockaddr_in client_address;
  socklen_t client_address_len = sizeof(client_address);
  getsockname(client_socket, (struct sockaddr*)&client_address, &client_address_len);

  // Declare handshake_header here
  struct tcp_header handshake_header;

  // Simulate 3-way handshake
  initialize_tcp_header(&handshake_header, ntohs(client_address.sin_port), port, rand(), 0, 17520, 0xffff, 0);
  set_flags(&handshake_header, LISTEN); // No output for LISTEN state

  set_flags(&handshake_header, SYN_STATE);
  print_header(&handshake_header, "Step 1: SYN sent");

  set_flags(&handshake_header, SYN_ACK_STATE);
  print_header(&handshake_header, "Step 2: SYN ACK received");

  set_flags(&handshake_header, ACK_STATE);
  print_header(&handshake_header, "Step 3: ACK sent");

  set_flags(&handshake_header, FINAL_ACK_STATE);
  print_header(&handshake_header, "Step 3: FINAL ACK received");

  // Close the socket
  close(client_socket);

  return 0;
}

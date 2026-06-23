#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/sha.h> // for hashing
#include <openssl/evp.h> // for base64 encoding
#include <stdint.h>
#include <time.h> // for latency
#include <sys/resource.h>

#define MAX_CLIENTS 10

// SOCKET OP CONSTANTS 
#define WS_OP_TEXT 0x1
#define WS_OP_BIN 0x2
#define WS_OP_CLOSE 0x8
#define WS_OP_PING 0x9
#define WS_OP_PONG 0xA

void get_resource_usage() {
    time_t raw_time;
    time(&raw_time);
    struct tm *utc_time;
    char curr_time[100];
    utc_time = gmtime(&raw_time);
    strftime(curr_time, 100, "%Y-%m-%d %H:%M:%S UTC", utc_time);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("Memory usage at time %s GMT: %ld KB.\n", curr_time, usage.ru_maxrss);
        printf("Time spent executing in user mode: %ld seconds.\n", usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0);
        printf("Time spent executing in kernel mode: %ld seconds.\n", usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0);
    } else {
        fprintf(stderr, "Couldn't get resource usage at time: %s GMT.\n", curr_time);
    }
}

char* str_to_JSON(char* text, int user) {
    time_t raw_time;
    struct tm *utc_time;
    char time_buffer[100];

    time(&raw_time);
    utc_time = gmtime(&raw_time);
    strftime(time_buffer, 100, "%Y-%m-%d %H:%M:%S UTC", utc_time);

    char* res = malloc(BUFSIZ);
    snprintf(res, BUFSIZ, "{\"user\": %d, \"text\": \"%s\", \"time\": \"%s\"}", user, text, time_buffer);
    return res;
}

int remove_socket(struct pollfd *fds, int i, int* num_clients) {
    if (close(fds[i].fd) < 0) {
        return -1;
    }
    fds[i] = fds[(*num_clients)--];
    return 0;
}

int handshake(int client_fd) {
    // get upgrade request from connected socket
    char buffer[BUFSIZ];
    int bytes_recv = 0;
    
    if ((bytes_recv = recv(client_fd, buffer, BUFSIZ - 1, 0)) <= 0) {
        fprintf(stderr, "Could not perform handshake for client with file descriptor: %d\n", client_fd);
        return -1;
    }
    buffer[bytes_recv] = '\0';

    char *key = NULL, header[] = "Sec-WebSocket-Key";
    key = strstr(buffer, header);
    if (!key) return -1;
    key = strchr(key, ' ');
    if (!key) return -1;
    key++;
    if (key) {
        // key ptr now points to the start of the key
        char* val[25]; // the key is 16 bytes raw, 24 chars in Base64
        int idx = 0;

        while (idx < 24 && !(key[idx] == '\r' || key[idx] == '\n')) {
            val[idx++] = key[idx];
        }
        if (idx < 24) return -1; // 24 char key needed
        val[idx] = '\0';

        char GUID[] = "258EAFA5-E914-47DA-95CA-C5ABDC257861";
        char to_hash[strlen(GUID) + strlen(val) + 1], encoded[BUFSIZ];

        snprintf(to_hash, sizeof(to_hash), "%s%s", val, GUID);

        // SHA-1 mapping
        unsigned char sha1_result[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)to_hash, strlen(to_hash), sha1_result);

        // Base64
        int bytes_written = EVP_EncodeBlock(encoded, sha1_result, SHA_DIGEST_LENGTH);
        encoded[bytes_written] = '\0';

        // send handshake confirmation string

        char confirmation[BUFSIZ];
        snprintf(confirmation, BUFSIZ, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Accept: %s\r\n\r\n", encoded);
        if (send(client_fd, confirmation, strlen(confirmation), 0) < 0) {
            fprintf(stderr, "Could not perform handshake for client with file descriptor: %d\n", client_fd);
            return -1;
        }

    } else {
        fprintf(stderr, "Could not perform handshake for client with file descriptor: %d\n", client_fd);
        return -1;
    }
}

int send_pong(int fd, char* payload) {
    if (strlen(payload) > 125) {
        payload[124] = '\0';
    }
    int payload_len = strlen(payload);

    char frame_header[2];
    frame_header[0] = 0x80 + WS_OP_PONG;
    frame_header[1] = payload_len;

    int status;
    if ((status = send(fd, frame_header, 2, 0)) < 0) {
        return -1;
    }
    if ((status = send(fd, payload, payload_len, 0)) < 0) {
        return -1;
    }
    return 0;
}

// SENDING & RECEIVING LOGIC FOLLOWS RFC 6455 (https://datatracker.ietf.org/doc/html/rfc6455)
int send_sock(int fd, int sender_fd, char* payload) {
    // SENDING TO A CLIENT WITH FD=FD FROM FD=SENDER_FD (payload is the string of text to be sent)
    int status;
    char buffer[BUFSIZ];
    char frame[10];
    payload = str_to_JSON(payload, sender_fd);
    int payload_len = strlen(payload), header_len = 1;

    frame[0] = 0x80 + WS_OP_TEXT; // FIN + OPCODE

    /*
        Here, FIN = 1, RSV1 = RSV2 = RSV3 = 0, OPCODE = WS_OP_TEXT
    */
    if (payload_len <= 125) {
        frame[1] = payload_len;
        header_len = 2;
    } else if (payload_len <= UINT16_MAX) {
        frame[1] = 126;
        frame[2] = (payload_len >> 8) & 0xFF;
        frame[3] = payload_len & 0xFF;
        header_len = 4;
    } else {
        frame[1] = 127;
        frame[2] = (payload_len >> 56) & 0xFF;
        frame[3] = (payload_len >> 48) & 0xFF;
        frame[4] = (payload_len >> 40) & 0xFF;
        frame[5] = (payload_len >> 32) & 0xFF;
        frame[6] = (payload_len >> 24) & 0xFF;
        frame[7] = (payload_len >> 16) & 0xFF;
        frame[8] = (payload_len >> 8) & 0xFF;
        frame[9] =  payload_len & 0xFF;
        header_len = 10;
    }

    // MSG_NOSIGNAL returns -1 in case the client abruptly closes the browser tab
    if ((status = send(fd, frame, header_len, MSG_NOSIGNAL)) < 0) {
        free(payload);
        return -1;
    }
    
    if ((status = send(fd, payload, payload_len, MSG_NOSIGNAL)) < 0) {
        free(payload);
        return -1;
    }
    free(payload);
    return header_len + payload_len;
}

int recv_full(int fd, char* buffer, int len) {
    /*
        Each subsequent payload will contain its own headers, masking key, etc.
    */
    return 0;
}

int closing_handshake(int fd) {

}

int recv_sock(int fd, char* buffer, char** res) {
    // RECEVING FROM A CLIENT
    int len, fin = 0, opcode;

    if ((len = recv(fd, buffer, BUFSIZ - 1)) < 0) return -1;
    buffer[len] = '\0';
    int offset = 0; // processed bytes

    // buffer now contains a masked value
    // FIRST BYTE: FIN, RSV1, RSV2, RSV3, OPCODE(4)
    fin = buffer[offset] >> 7;

    if (!fin) {
        return -1;
        // int status = recv_full(fd, buffer, len);
        // if (status < 0) return -1;
    }

    // 0x40 = 01000 0000
    int rsv1 = buffer[offset] & 0x40, rsv2 = buffer[offset] & 0x20, rsv3 = buffer[offset] & 0x10;
    if (rsv1 || rsv2 || rsv3) return -1; // they should be 0
    opcode = buffer[offset] & 0x0F;

    if (opcode == WS_OP_CLOSE) {
        closing_handshake(fd);
        while (remove_socket(fd) < 0);
        return -10;
    }

    offset = 1; 

    // SECOND BYTE: MASK, PAYLOAD_LENGTH(7)
    int has_mask = buffer[offset] >> 7;
    if (!has_mask) return -1; // all data from client to server must be masked

    int payload_length = buffer[1] & 0x7F; // 0111 1111
    offset = 2;
    if (payload_length == 126) {
        // next 2 bytes
        payload_length = (buffer[offset] << 8) + buffer[offset + 1]; 
        offset += 2;
    }
    else if (payload_length == 127) {
        // next 8 bytes
        payload_length = 0;
        for (int i = offset; i < offset + 8; i++)
            payload_length = (payload_length << 8) | buffer[i];
        offset += 8;
    }

    if (len < offset + 4) {
        // masking key not found
        return -1;
    }

    char* mask = &buffer[offset]; // there are four mask keys, to be alternated with MOD 4
    offset += 4;

    if (len < offset + payload_length) {
        // the length of the text should match the actual payload received for malloc-ing
        return -1;
    }
    char* payload = &buffer[offset];

    *res = malloc(payload_length + 1);

    for (int i = 0; i < payload_length; i++) {
        (*res)[i] = (char)(payload[i] ^ mask[i % 4]);
    }
    (*res)[payload_length] = '\0';

    if (opcode == WS_OP_PING) {
        while (send_pong(fd, res) < 0);
        return -10;
    }

    return len;
}

int main() {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_PASSIVE;
    int status, fd;
    
    if ((status = getaddrinfo(NULL, "6767", &hints, &res)) != 0) {
        fprintf(stderr, "Error occurred: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    int bound = 0;
    for (struct addrinfo *p = res; p != NULL; p = p->next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) continue;
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(fd, (struct sockaddr*)(p->ai_addr), p->ai_addrlen) == 0) {
            bound = 1;
            break;
        }
        close(fd); // can't bind
    }

    freeaddrinfo(res);
    if (!bound) {
        fprintf(stderr, "Could not bind socket.\n");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, SOMAXCONN) < 0) {
        fprintf(stderr, "Could not assign server to listen to port.\n");
        exit(EXIT_FAILURE);
    }

    int num_clients = 0;
    struct pollfd *fds = malloc(sizeof(struct pollfd) * (MAX_CLIENTS + 1)); // one for listening fd
    fds[0] = (struct pollfd){fd, POLLIN};

    int total_handshake = 0, handshake_failure = 0;
    int total_frame_recv = 0, frame_recv_errors = 0;

    while (1) {
        int num_events = poll(fds, (MAX_CLIENTS + 1), 500);
        if (num_events > 0) {
            get_resource_usage();
            for (int i = 0; i < num_clients + 1; i++) {
                int events = fds[i].revents & (POLLIN | POLLHUP);
                if (!events) continue;
                if (fds[i].fd == fd) {
                    // client handling logic
                    int client_fd = accept(fd, NULL, NULL);
                    if (client_fd == -1) continue; // couldn't get client fd

                    // handshake + latency
                    struct timespec start, end;
                    clock_gettime(CLOCK_MONOTONIC, &start);
                    status = handshake(client_fd);
                    total_handshake++;
                    if (status < 0) {
                        close(client_fd);
                        handshake_failure++;
                        continue;
                    }
 
                    clock_gettime(CLOCK_MONOTONIC, &end);
                    double handshake_latency = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
                    printf("Handshake latency for socket %d: %f seconds.\n", fd, handshake_latency);
                    printf("Handshake failure rate: %f\n", float(handshake_failure)/float(total_handshake));

                    if (num_clients >= MAX_CLIENTS) {
                        char error_msg[] = "Maximum client limit reached, cannot connect.";
                        send_sock(client_fd, 0, error_msg);
                        close(client_fd);
                    } else {
                        fds[++num_clients] = (struct pollfd){client_fd, POLLIN};
                    }
                }
                else if (fds[i].revents & POLLHUP) { // connection terminated
                    // remove socket connection to add page to bfcache
                    while (remove_socket(fds, i, &num_clients) < 0);
                } else {
                    char buffer[BUFSIZ], *res = NULL;
                    int buf_size;

                    struct timespec start, end;
                    clock_gettime(CLOCK_MONOTONIC, &start);
                    total_frame_recv++;
                    if ((buf_size = recv_sock(fds[i].fd, buffer, &res)) < 0 && buf_size != -10) {
                        fprintf(stderr, "Couldn't receive data from client with file descriptor: %d\n", fds[i].fd);
                        frame_recv_errors++;
                        continue;
                    }
                    if (buf_size == -10) continue; // PING PONG logic | CLOSE logic
                    if (buf_size == 0) {
                        while (remove_socket(fds, i, &num_clients) < 0);
                        continue;
                    }

                    for (int j = 1; j < num_clients + 1; j++) {
                        if (j == i) continue; // don't send msg to same user
                        send_sock(fds[j].fd, fds[i].fd, res);
                    }
                    
                    clock_gettime(CLOCK_MONOTONIC, &end);
                    double server_latency = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
                    printf("Server latency for socket %d: %f seconds.\n", fds[i].fd, server_latency);
                    printf("Frame reception failure rate: %f\n", float(frame_recv_errors)/float(total_frame_recv));
                    free(res);
                }
            }
        }
    }

    free(fds);
}
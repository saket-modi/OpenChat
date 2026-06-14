#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/sha.h> // for hashing
#include <openssl/evp.h> // for base64 encoding

#define MAX_CLIENTS 10

int remove_socket(struct pollfd *fds, int i, int* num_clients) {
    close(fds[i].fd);
    fds[i] = fds[--(*num_clients)];
}

int handshake(int client_fd) {
    // get upgrade request from connected socket
    char buffer[BUFSIZ];
    int bytes_recv = 0;
    
    if ((bytes_recv = recv(client_fd, buffer, BUFSIZ, 0)) < 0) {
        fprintf(stderr, "Could not perform handshake for client with file descriptor: %d", client_fd);
        return;
    }

    char *key, header[] = "Sec-WebSocket-Key";
    key = strstr(buffer, header);
    if (key) {
        while (*key != ' ') key++;
        key++;

        // key ptr now points to the start of the key
        char* val = malloc(32); // the key is 16 bytes raw, 24 chars in Base64
        int idx = 0;

        while (!(key[idx] == '\r' || key[idx] == '\n')) {
            val[idx++] = key[idx];
        }
        val[idx] = '\0';

        char GUID[] = "258EAFA5-E914-47DA-95CA-C5ABDC257861";
        char to_hash[strlen(GUID) + strlen(val) + 1], encoded[BUFSIZ];

        snprintf(to_hash, sizeof(to_hash), "%s%s", val, GUID);

        // SHA-1 mapping
        unsigned char sha1_result[SHA_DIGEST_LENGTH];
        SHA1((unsigned char*)to_hash, strlen(to_hash), sha1_result);

        // Base64
        int bytes_written = EVP_EncodeBlock(encoded, to_hash, strlen(to_hash));
        encoded[bytes_written] = '\0';
        
        free(val);

        // send handshake confirmation string

        char confirmation[BUFSIZ];
        snprintf(confirmation, BUFSIZ, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Accept: %s\r\n\r\n", encoded);
        if (send(client_fd, confirmation, strlen(confirmation), 0) < 0) {
            fprintf(stderr, "Could not perform handshake for client with file descriptor: %d", client_fd);
            free(confirmation);
            free(encoded);
            return;
        }
        free(confirmation);
        free(encoded);
    } else {
        fprintf(stderr, "Could not perform handshake for client with file descriptor: %d", client_fd);
        return;
    }
}

int main() {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_PASSIVE;
    int status, fd;
    
    if ((status = getaddrinfo(NULL, "80", &hints, &res)) != 0) {
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
        fprintf(stderr, "Could not assign server to listen to port.");
        exit(EXIT_FAILURE);
    }

    int num_clients = 0;
    struct pollfd *fds = malloc(sizeof(struct pollfd) * (MAX_CLIENTS + 1)); // one for listening fd
    fds[0] = (struct pollfd){fd, POLLIN};

    while (1) {
        int num_events = poll(fds, (MAX_CLIENTS + 1), 500);
        if (num_events > 0) {
            for (int i = 0; i < num_clients + 1; i++) {
                int events = fds[i].revents & (POLLIN | POLLHUP);
                if (!events) continue;
                if (fds[i].fd == fd) {
                    // client handling logic
                    int client_fd = accept(fd, NULL, NULL);
                    if (client_fd == -1) continue; // couldn't get client fd
                    handshake(client_fd);

                    if (num_clients >= MAX_CLIENTS) {
                        char error_msg[] = "Maximum client limit reached, cannot connect.";
                        send(client_fd, error_msg, strlen(error_msg), 0);
                        close(client_fd);
                    } else {
                        fds[++num_clients] = (struct pollfd){client_fd, POLLIN};
                    }
                }
                else if (fds[i].revents & POLLHUP) { // connection terminated
                    // remove socket connection to add page to bfcache
                    remove_socket(fds, i, &num_clients);
                } else {
                    char buffer[BUFSIZ];
                    int buf_size;

                    if ((buf_size = recv(fds[i].fd, buffer, BUFSIZ, 0)) < 0) {
                        fprintf(stderr, "Couldn't receive data from client with file descriptor: %d", fds[i].fd);
                    }
                    if (buf_size == 0) {
                        remove_socket(fds, i, &num_clients);
                        continue;
                    }

                    // close string recv'd
                    buffer[buf_size] = '\0';

                    for (int j = 1; j < num_clients + 1; j++) {
                        if (j == i) continue; // don't send msg to same user
                        send(fds[j].fd, buffer, strlen(buffer), 0);
                    }
                }
            }
        }
    }

    free(fds);
}
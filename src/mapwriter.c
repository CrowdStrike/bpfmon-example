// SPDX-License-Identifier: BSD-3-Clause
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/socket.h>
#include "mapwriter.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct mapwriter_bpf *prog;
    int err;

    // Make BPF debug logs go to to stderr
    libbpf_set_print(libbpf_print_fn);

    // Open and log BPF Program
    prog = mapwriter_bpf__open();
    if (!prog) {
        printf("Failed to open BPF skeleton\n");
        return 1;
    }
    err = mapwriter_bpf__load(prog);
    if (err) {
        printf("Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Create socket and attack bpf program to it
    int sockets[2];
    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)) {
        printf("failed to create socket pair '%s'\n", strerror(errno));
        goto cleanup;
    }
    int prog_fd[1] = { bpf_program__fd(prog->progs.my_socket_prog) };
    if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, prog_fd, sizeof(prog_fd[0])) < 0) {
        printf("setsockopt '%s'\n", strerror(errno));
        return -1;
    }

    // Start data generating loop
    int key = 0;
    int value = 286331153;  // "11 11 11 11"
    printf("-----------------------\n");
    printf("Writing data into a Map from user and kernel\n");
    while (1) {
        // Write value into map
        bpf_map_update_elem(bpf_map__fd(prog->maps.my_map), &key, &value, BPF_ANY);
        sleep(1);

        // Write arbitrary data to socket to trigger bpf program
        char buffer[4] = {'a', 'b', 'c', 'd'};
        size_t socket_n = write(sockets[0], buffer, sizeof(buffer));
        if (socket_n < 0) {
            perror("write");
            return -1;
        }
        if (socket_n != sizeof(buffer)) {
            printf("short write: %zd\n", socket_n);
            return -1;
        }
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    mapwriter_bpf__destroy(prog);
    return -err;
}

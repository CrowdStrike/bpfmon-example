// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bpfmon.h"
#include "bpfmon.skel.h"

static volatile bool SHOULD_EXIT = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    SHOULD_EXIT = true;
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
    struct map_update_data *map_data = (struct map_update_data*)data;
    char out_val;
    if (map_data->updater == UPDATER_KERNEL) {
        printf("Map Updated From Kernel:\n");
    }
    else if (map_data->updater == UPDATER_USERMODE) {
        printf("Map Updated From User:\n");
    }
    else if (map_data->updater == UPDATER_SYSCALL_GET) {
        printf("Syscall used to get a map handle:\n");
    }
    else if (map_data->updater == UPDATER_SYSCALL_UPDATE) {
        printf("Syscall used to get a update map using handle:\n");
    }
    printf("  PID:   %d\n",  map_data->pid);
    if (map_data->updater == UPDATER_SYSCALL_UPDATE) {
        printf("  FD:    %d\n",  map_data->map_id);
    }
    else {
        printf("  ID:    %d\n",  map_data->map_id);
    }
    if (map_data->name[0] != '\x00')
        printf("  Name:  %s\n",  map_data->name);
    if (map_data->key_size > 0) {
        printf("  Key:   ");
        for (int i = 0; i < map_data->key_size; i++) {
            out_val = map_data->key[i];
            printf("%02x ", out_val);
        }
        printf("\n");
    }
    if (map_data->value_size > 0) {
        printf("  Value: ");
        for (int i = 0; i < map_data->value_size; i++) {
            out_val = map_data->value[i];
            printf("%02x ", out_val);
        }
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    struct bpfmon_bpf *prog;
    int err;

    // Make BPF debug logs go to to stderr
    libbpf_set_print(libbpf_print_fn);

    // Add handlers for ctrl+c signals
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load eBPF Program
    prog = bpfmon_bpf__open();
    if (!prog) {
        printf("Failed to open and load BPF skeleton\n");
        return 1;
    }
    err = bpfmon_bpf__load(prog);
    if (err) {
        printf("Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attach the various kProbes
    err = bpfmon_bpf__attach(prog);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Setup Pef buffer to process events from kernel
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb;
    pb_opts.sample_cb = print_bpf_output;
    pb = perf_buffer__new(bpf_map__fd(prog->maps.map_events), 8, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        printf("failed to setup perf_buffer: %d\n", err);
        goto cleanup;
    }

    // Start processing events in a loop
    printf("-----------------------\n");
    while (!SHOULD_EXIT) {
        err = perf_buffer__poll (pb, 1000);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    bpfmon_bpf__destroy(prog);
    return err < 0 ? -err : 0;
}

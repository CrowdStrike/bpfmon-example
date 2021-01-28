// SPDX-License-Identifier: BSD-3-Clause
#ifndef BPFMON_H
#define BPFMON_H

#define MAX_KEY_SIZE 10
#define MAX_VALUE_SIZE 10
#define BPF_NAME_LEN 16U

enum map_updater{
    UPDATER_KERNEL,
    UPDATER_USERMODE,
    UPDATER_SYSCALL_GET,
    UPDATER_SYSCALL_UPDATE,
}map_updater;

typedef struct map_update_data {
    unsigned int map_id;
    char name[BPF_NAME_LEN];
    enum map_updater updater;
    unsigned int pid;
    unsigned int key_size;
    unsigned int value_size;
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
} map_update_data;

#endif /* BPFMON_H */

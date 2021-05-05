# BPFMon Proof of Concept

This is a proof-of-concept example of using eBPF to Monitor for changes
to eBPF Maps from user and kernel programs. This was written to accompany the blog [Mapping It Out: Analyzing the Security of eBPF Maps](https://www.crowdstrike.com/blog/analyzing-the-security-of-ebpf-maps)

This is **not** intended to be used in production, but to instead demonstrate
the challenge of monitoring for eBPF Map tampering.

# Building
BPFMon has been tested on `Ubuntu 20.10`, running kernel `5.8.3-050803`.
Other kernels and distros should work, but no other testing was done.

BPFMon has the same prerequisite packages as [libbpf](https://github.com/libbpf/libbpf/):
- clang 11+
- libelf (`libelf-dev` on Ubuntu)
- zlib (`zlib1g-dev` on Ubuntu)

Occasianly, I've found the `llvm-strip` program not to have been installed correctly, so
if something goes wrong you might need to run something like this to make `llvm-strip` point to the version-specific binary:
```bash
sudo ln -s "$(which llvm-strip-11)" "$(dirname $(which llvm-strip-11))/llvm-strip"
```


Once these are installed, ensure the `libbpf` submodule is initialised, then run `make` from the `src` directory:
```bash
cd bpfmon-example
git submodule update --init --recursive

cd src
make
```

# Running
The build will generate two programs:

## MapWriter
This is an example user mode+eBPF program, that will continually call `bpf_map_update_elem` from
both kernel and userland to update an eBPF Map, once per second. To run:
```bash
./mapwriter
```

## BPFMon
This is the main monitoring program. It creates a number of KProbes to look for Map Writing
from user or eBPF programs (see '[How it works](#How-it-works)' below). It also looks
for usermode programs getting a new handle to a map.
To run:
```bash
sudo ./bpfmon
```

# How it works
As covered in the blog [Mapping it out: Analysing the security of eBPF Maps](https://www.crowdstrike.com/blog/tbd), programs that use eBPF often store configuration inside eBPF Maps. A privileged attacker can alter the values in these maps to tamper with the program, which is non-trivial to detect.

`BPPMon` demonstrates one approach at tamper detection, by using KProbes to inspect calls to a number of kernel functions used in updating values inside eBPF Maps. The functions it attaches to are:

## BPF Syscall
The `bpf` syscall is the main way usermode applications interact with eBPF programs and maps.

When a user mode program wants to alter data inside a map, it must first get a handle to it by calling this syscall with the `BPF_MAP_GET_FD_BY_ID` option, passing in the global ID of the Map it wishes to alter. The kernel will return a handle ID, that is meaningless to everyone else except that process.

It then calls the syscall again, this time with `BPF_MAP_UPDATE_ELEM`, passing in the data to update, along with the handle from the first call.

Linking these 2 events together is difficult, as you must keep track of the process+handle pairings for each process. Additionally, processes can fork (creating new processes with the same handles), duplicate handles (create a new handle that refers to the Map), or even send the handle to another process, all of which makes it harder for a monitor to audit the system as a whole.

Finally, Map alterations can be made by the kernel eBPF programs, which don't use the syscall but instead access to maps directly using a memory pointer.

As such, in order to get the complete picture, this can't be the only function to inspect, so `BPFMon` attaches 2 more KProbes:


## bpf_map_update_value
```c
static int bpf_map_update_value(
   struct bpf_map *map, struct fd f,
   void *key, void *value, __u64 flags
)
```

This is an internal kernel function that is run after the `bpf` syscall, after the kernel has looked up the process-specific handle, and retrieved the correct eBPF Map kernel object. This object contains vital information to log, such as:
- The global Map ID
- The Name of the Map
- The size of the keys
- The size of the values

Additionally, as we know the size of the keys and values, we can read them out of the process' memory, and so together we can log "Process `P` updated Map `M` with Key `K` and Value `V`".

This however only works for user mode processes altering Maps. To also log when another eBPF Program alters a map, we need one more KProbe:

## array_map_update_elem
```c
static int array_map_update_elem(
   struct bpf_map *map, void *key,
   void *value, u64 map_flags
)
```
This function is called whenever an eBPF program calls the `bpf_map_update_value()` function to update a value in a Map.

Due to how Map objects are created, attaching to `bpf_map_update_value` itself doesn't work, but we can attach the type-specific functions it calls to do the actual update. `array_map_update_elem` is only called when updating maps of type `BPF_MAP_TYPE_ARRAY`, but there are other functions for each of the different map types. As this is a proof-of-concept, `BPFMon` only attaches to the Array type. Like `bpf_map_update_value`, the function is called with the pointer to the eBPF Map kernel object, so we get all the information necessary to log.

We can't tell which BPF Program is doing the updating, but we can tell which process it is running in.


# Limitations
As this is only meant as a small demonstration, there are a number of limitations.

- BPFMon has only been tested on Ubuntu running a 5.8.3 kernel.
- It only detects writes from the kernel if the map type is `BPF_MAP_TYPE_ARRAY`
- Testing write detections to/from eBPF maps was only done using `bpftool`, and our `mapwriter` program.
- 2 of the KProbes are attached to kernel functions that may change signature, be removed, etc., at any future kernel update.

# Other Notes
The Makefile of this project is heavily based upon the one in [LibBPF Bootstrap](https://github.com/libbpf/libbpf-bootstrap).

For more details, see the related blog [Mapping It Out: Analyzing the Security of eBPF Maps](https://www.crowdstrike.com/blog/analyzing-the-security-of-ebpf-maps).

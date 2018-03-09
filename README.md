# ish(d)

ish(d), or "indiscriminent shell", is comprised of a client and server program
that provides a simple remote shell.

## Installation

### Requirements

ish(d) is built following the C99 standard. Make is the build tool for ish(d).

### Building

#### Targets

By default all targets will be built. Build artifacts will be located in
`build` and binary outputs will be in `bin`.

* ish
* ishd
* plugin-icmp

#### Options

* `ISH_DEBUGH` will enable debug settings and print statements; the default is
OFF
* `ISH_TIMEOUT` will set the default timeout; the default is 10 seconds

### Running

ish(d) uses raw sockets so only the user ID of 0 (root) or the CAP_NET_RAW
capability are allowed to open raw sockets. Due to this you should run ish(d)
with `sudo`. For more information see `man 7 raw`.

ish(d) supports the `-h` and `--help` options.

#### ishd

    sudo ./ishd ./plugin-icmp.so

#### ish

    sudo ./ish localhost "ls -la"

### Testing

ish(d) has currently only been tested locally. 

    $ uname -a
    Linux box-codeanywhere 2.6.32-042stab112.15 #1 SMP Tue Oct 20 17:22:56 MSK 2015 x86_64 x86_64 x86_64 GNU/Linux
    $ gcc --version | sed -n 1p
    gcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2
    
#### Valgrind

Results:

    $ sudo valgrind ./ish localhost ls -la
    ...
    ==1329== HEAP SUMMARY:
    ==1329==     in use at exit: 0 bytes in 0 blocks
    ==1329==   total heap usage: 50 allocs, 50 frees, 10,073 bytes allocated
    ==1329==
    ==1329== All heap blocks were freed -- no leaks are possible
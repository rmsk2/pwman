# pwman

This program is my plan B if I lose interest in maintaining `rustpwman`. This could happen if I either lose interest in Rust 
programming or if at some point in time it becomes too tedious to migrate to newer versions of the over 200 dependencies
that `rustpwman` has accumulated. Files created with `pwman` can be used with `rustpwman` and vice versa.

The main component can be found in the `clitool` subdirectory. It implements a command line interface that allows to 
access a password manager file as described in the `rustpwman` documentation. The following commands are provided.

```
The following commands are available: 
     clp: Adds/modifies an entry by setting its contents through the clipboard
     dec: Decrypts a file
     del: Deletes an entry from a file
     enc: Encrypts a file
     get: Get an entry from a file
     init: Creates an empty password safe
     list: Lists keys of entries in a file
     put: Adds/modifies an entry by setting its contents through a file
     pwd: Checks the password and transfers it to pwserv
     ren: Renames an entry in a file
     rst: Deletes the password from pwserv
     ver: Print version information
```

You can get additional help for any given command by calling `clitool <command> -h `. There is a second optional component which resides in the 
`pwserv` subdirectory. It implements a socket based server which allows to cache passwords.  You can instruct `clitool` to cache a verified 
password via `pwserv` by using the `pwd` command and you can make `pwserv` forget a password by issuing the `rst` command.

The `enc` and `dec` commands are not password manager specific. They can be used to encrypt or decrypt any file which has the format described
in the `rustpwman` documentation.

# Setup

While you can use `clitool` without `pwserv` it is way more comfortable to use it in conjuction with `pwserv` in most cases. To do that you
obviously have to start `pwserv` before `clitool` can access it. In the default configuration `pwserv` creates a UNIX domain socket
named `"/tmp/${username}.pwman"` on UNIX and `"%HOMEPATH%\pwman.sock"` on Windows which can only by accessed by the user who started 
`pwserv`. `pwserv` can also alternatively use the loopback device (or any other TCP socket) but without the additional access restrictions 
afforded by a UNIX domain socket. In order to switch to the loopback device change the calls to `Serve()` in `pwserv.go` and `NewContext()` 
in `pwman.go` accordingly. 

Interestingly enough Windows implements UNIX domain sockets since around 2017/2018.  The corresponding routines can be found in 
`windomainsock.go`. UNIX domain sockets not only allow additional access control but on Windows they are also noticebly faster than 
TCP over the loopback device.

I have added `pwserv` to my startup programs in Ubuntu to eliminate the hassle to remeber to start it before using `clitool`. Another way
to simplify calls to `clitool` is to set the environment variable `PWMANFILE` to the file system location of the password safe file. If this
variable is set and `-i` is not specified then `clitool` uses the value from the environment. If `-i` is present this value takes precedence.

If you want to be able to replace the contents of an entry by the contents of the clipboard through the `clp` command you can set the environment
variable `PWMANCLIP` to the value you would give to the `-c` option. If the `-c` option is present it takes precedence over the value of the
environment variable.

If you set the environment variable `PWMANCIPHER` to the value `AES192` then `pwman` will use AES-192 GCM any other value makes `pwman` using
ChaCha20Poly1305` instead of AES-256-GCM for en- and decryption of the password data.

# Building

There are build scripts `buildall.sh` (for Linux and MacOS) and `buildall.bat` (for Windwos) which allow building the two binaries mentioned 
above. 

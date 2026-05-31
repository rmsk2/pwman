# pwman

This program is my plan B if I lose interest in maintaining [`rustpwman`](https://github.com/rmsk2/rustpwman). This could happen 
if I either lose interest in Rust programming or if at some point in time it becomes too tedious to migrate to newer versions of the
~~about 200~~ 340 dependencies that `rustpwman` has accumulated. Files created with `pwman` can be used with `rustpwman` and vice versa.

The main component can be found in the `clitool` subdirectory. It implements a command line interface that allows to 
access a password manager file as described in the `rustpwman` documentation. The following commands are provided.

```
The following commands are available: 
     bkp: Store a backup of the given password safe
     chg: Change current password
     clp: Adds/modifies an entry by setting its contents through the clipboard
     dec: Decrypts a file
     del: Deletes an entry from a file
     enc: Encrypts a file
     gen: Generate one or more passwords
     get: Get one or more entries from a file
     init: Creates an empty password safe
     list: Lists keys of entries in a file
     obf: Obfuscate WebDAV password and create corresponding config
     otp: Calculate TOTP codes from an entry
     put: Adds/modifies an entry by setting its contents through a file
     pwd: Checks the password and transfers it to pwserv
     qrc: Create a QR code from an entry
     ren: Renames an entry in a file
     rst: Deletes the password from pwserv
     ver: Print version information
```

You can get additional help for any given command by calling `clitool <command> -h `. There is a second optional component which resides in the 
`pwserv` subdirectory. It implements a socket based server which allows to cache passwords.  You can instruct `clitool` to cache a verified 
password via `pwserv` by using the `pwd` command and you can make `pwserv` forget a password by issuing the `rst` command. Beginning with version
1.3.3 of the `clitool` you can delete all cached passwords by using the password file name `*` (do not forget to quote this on your Linux/macOS
machine).

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
`windomainsock.go`. UNIX domain sockets not only allow additional access control but on Windows they are also noticeably faster than 
TCP over the loopback device.

I have added `pwserv` to my startup programs in Ubuntu to eliminate the hassle to remember to start it before using `clitool`. Another way
to simplify calls to `clitool` is to set the environment variable `PWMANFILE` to the file system location of the password safe file. If this
variable is set and `-i` is not specified then `clitool` uses the value from the environment. If `-i` is present this value takes precedence.

When using the Windows build script `buildall.bat` the program `pwserv.exe` is built as a Windows GUI application. This means it does not own
a console and if you start it in a DOS box or a Powershell window the program immediately "returns" but is started in the background. You
can also put it in the autostart folder, which still exists in Windows 11 and can be accessed by entering `shell:startup` after pressing `Win + r`
on the keyboard, or start it automatically after logon in any other way you see fit. If you want to stop it you have to use the Task manager
for the moment. Remove `-ldflags="-H windowsgui"` to build `pwserv.exe` as a console application for instance during development.

If you set the environment variable `PWMANCIPHER` to the value `AES192` or `AES256` then `pwman` will use AES-192 or AES-256 GCM for en- and
decryption of the password data. Any other value makes `pwman` using ChaCha20Poly1305.

`pwman` is also able to access files containing encrypted password data via WebDAV. For this to work a config file `.rustpwman` has to exist 
in the users home directory which contains the entries `webdav_user` and `webdav_pw` where the WebDAV password has to be obfuscated in the
way described in the `rustpwan` [documentation](https://github.com/rmsk2/rustpwman?tab=readme-ov-file#webdav-support). The command 
`clitool obf` can be used to create the corresponding configuration file when you do not make use of `rustpwman`. 

Here an overview of the environment variables that `pwman` uses

|Name | Intended use |
|-|-
|`PWMANFILE`| File name or WebDAV address of preferred password file |
|`PWMANCIPHER`| If present then the values `AES192` and `AES256` select AES-192 GCM or AES-256 GCM as a cipher. Any other value selects ChaCha20-Poly1305. If not set AES-256 GCM is used|
|`PWMANCLIP`| Command to use when "pasting" the clipboard contents during a `clp` command|
|`PWMANBKP`| File name to store backup in if no `-o` parameter has been given at the command line of a `bkp` command|
|`RUSTPWMAN_OBFUSCATION`| Key used to obfuscate WebDAV access data|
|`RUSTPWMAN_VIEWER`| Prefix for the command to start an image viewer to which the file name of the image (containing a QR code) is appended |
|`PWMAN_CONFIG`| Path to alternative config file |

# Additional info about specific commands

The `clp` command allows you to replace the contents of an entry by the contents of the clipboard or to create a new entry holding the contents 
of the clipboard. By setting the environment variable `PWMANCLIP` to the value you would give to the `-c` option you can specify a default for
that value. It is then used whenever the `-c` option is omitted. If the `-c` option is present it takes precedence over the value of the 
environment variable.

The `bkp` command can be used  to store a local backup of any password safe. When the password safe is stored at a WebDAV location `bkp` allows
you to perform the backup without first explcitly mounting the WebDAV share as a local drive.

The `otp` command can be used to calculate TOTP token values from an entry, if that entry contains a valid TOTP-URL. The token is recacalculated
each second. You can suppress recalculation by adding the option `-oneshot`.

The `qrc` command allows to represent the contents of an entry as a QR code. For this pupose a new file is created which is subsequently
displayed using the viewer program specified in the `RUSTPWMAN_VIEWER` environment variable. You probably want to delete the file after you have
scanned the QR code.

In addition the Python script `totp.py` in this repo can be used to determine the contents of a QR code stored in an image file and to print that
contents to stdout. For reasons of symmetry it also works the other way round, i.e. data read from stdin can be represented as an image file
containing a QR-code.

# Building

There are build scripts `buildall.sh` (for Linux and MacOS) and `buildall.bat` (for Windows) which allow building the two binaries mentioned 
above. 

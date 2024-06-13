# Introduction

**This system has been merged into OpenBSD base.  If you'd like to
contribute to openrsync, please mail your patches to tech@openbsd.org.
This repository is simply the OpenBSD version plus some glue for
portability.**

This is an implementation of [rsync](https://rsync.samba.org/) with a
BSD (ISC) license.  It's compatible with a modern rsync (3.1.3 is used
for testing, but any supporting protocol 27 will do), but accepts only a
subset of rsync's command-line arguments.

Its officially-supported operating system is OpenBSD, but it will
compile and run on other UNIX systems.  See [Portability](#Portability)
for details.

The canonical documentation for openrsync is its manual pages.  See
[rsync(5)](https://github.com/kristapsdz/openrsync/blob/master/rsync.5)
and
[rsyncd(5)](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5)
for protocol details or utility documentation in
[openrsync(1)](https://github.com/kristapsdz/openrsync/blob/master/openrsync.1).
If you'd like to write your own rsync implementation, the protocol
manpages should have all the information required.

The [Architecture](#Architecture) and [Algorithm](#Algorithm) sections
on this page serve to introduce developers to the source code.  They are
non-canonical.

## Project background

openrsync is written as part of the
[rpki-client(1)](https://medium.com/@jobsnijders/a-proposal-for-a-new-rpki-validator-openbsd-rpki-client-1-15b74e7a3f65)
project, an
[RPKI](https://en.wikipedia.org/wiki/Resource_Public_Key_Infrastructure)
validator for OpenBSD.  openrsync was funded by
[NetNod](https://www.netnod.se), [IIS.SE](https://www.iis.se),
[SUNET](https://www.sunet.se) and [6connect](https://www.6connect.com).

# Installation

On an up-to-date UNIX system, simply download and run:

```
% ./configure
% make
# make install
```

This will install the openrsync utility and manual pages.
It's ok to have an installation of rsync at the same time: the two will
not collide in any way.

If you upgrade your sources and want to re-install, just run the same.
If you'd like to uninstall the sources:

```
# make uninstall
```

If you'd like to interact with the openrsync as a server, you can run
the following:

```
% rsync --rsync-path=openrsync src/* dst
% openrsync --rsync-path=openrsync src/* dst
```

If you'd like openrsync and rsync to interact, it's important to use
command-line flags available on both.
See
[openrsync(1)](https://github.com/kristapsdz/openrsync/blob/master/openrsync.1)
for a listing.

# Algorithm

For a robust description of the rsync algorithm, see "[The rsync
algorithm](https://rsync.samba.org/tech_report/)", by Andrew Tridgell
and Paul Mackerras.
Andrew Tridgell's PhD thesis, "[Efficient Algorithms for Sorting and
Synchronization](https://www.samba.org/~tridge/phd_thesis.pdf)", covers the
topics in more detail.
This gives a description suitable for delving into the source code.

The rsync algorithm has two components: the *sender* and the *receiver*.
The sender manages source files; the receiver manages the destination.
In the following invocation, first the sender is host *remote* and the
receiver is the localhost, then the opposite.

```
% openrsync -lrtp remote:foo/bar ~/baz/xyzzy
% openrsync -lrtp ~/foo/bar remote:baz/xyzzy
```

The algorithm hinges upon a file list of names and metadata (e.g., mode,
mtime, etc.) shared between components.
The file list describes all source files of the update and is generated
by the sender.
The sharing is implemented in
[flist.c](https://github.com/kristapsdz/openrsync/blob/master/flist.c).

After sharing this list, both the receiver and sender independently sort
the entries by the filenames' lexicographical order.
This allows the file list to be sent and received out of order.
The ordering preserves a directory-first order, so directories are
processed before their contained files.
Moreover, once sorted, both sender and receiver may refer to file
entries by their position in the sorted array.

After the receiver reads the list, it iterates through each file in
the list, passing information to the sender so that the sender may send
back instructions to update the file.
This is called the "block exchange" and is the maintstay of the rsync
algorithm.
During the block exchange, the sender waits to receive a request for
update or end of sequence message; once a request is received, it scans
for new blocks to send to the receiver.

Once the block exchange is complete, the files are all up to date.

The receiver is implemented in
[receiver.c](https://github.com/kristapsdz/openrsync/blob/master/receiver.c);
the sender, in
[sender.c](https://github.com/kristapsdz/openrsync/blob/master/sender.c).
A great deal of the block exchange happens in
[blocks.c](https://github.com/kristapsdz/openrsync/blob/master/blocks.c).

## Block exchange

The block exchange sequence is different for whether the file is a
directory, symbolic link, or regular file.

For symbolic links, the information required by the receiver is already
encoded in the file list metadata.
The symbolic link is updated to point to the correct target.
No update is requested from the sender.

For directories, the directory is created if it does not already exist.
No update is requested from the sender.

Regular files are handled as follows.
First, the file is checked to see if it's up to date.
This happens if the file size and last modification time are the same.
If so, no update is requested from the sender.

Otherwise, the receiver examines each file in blocks of a fixed size.
See [Block sizes](#block-sizes) for details.
(The terminal block may be smaller if the file size is not divisible by
the block size.)
If the file is empty or does not exist, it will have zero blocks.
Each block is hashed twice: first, with a fast Adler-32 type 4-byte
hash; second, with a slower MD4 16-byte hash.
These hashes are implemented in
[hash.c](https://github.com/kristapsdz/openrsync/blob/master/hash.c).
The receiver sends the file's block hashes to the sender.

Once accepted, the sender examines the corresponding file with the given
blocks.
For each byte in the source file, the sender computes a fast hash given
the block size.
It then looks for matching fast hashes in the sent block information.
If it finds a match, it then computes and checks the slow hash.
If no match is found, it continues to the next byte.
The matching (and indeed all block operation) is implemented in
[block.c](https://github.com/kristapsdz/openrsync/blob/master/block.c).

When a match is found, the data prior to the match is first sent as a
stream of bytes to the receiver.
This is followed by an identifier for the found block, or zero if no
more data is forthcoming.

The receiver writes the stream of bytes first, then copies the data in
the identified block if one has been specified.
This continues until the end of file, at which point the file has been
fully reconstituted.

If the file does not exist on the receiver side---the basis case---the
entire file is sent as a stream of bytes.

Following this, the whole file is hashed using an MD4 hash.
These hashes are then compared; and on success, the algorithm continues
to the next file.

## Block sizes

The block size algorithm plays a crucial role in the protocol
efficiency.
In general, the block size is the rounded square root of the total file
size.
The minimum block size, however, is 700 B.
Otherwise, the square root computation is simply
[sqrt(3)](https://man.openbsd.org/sqrt.3) followed by
[ceil(3)](https://man.openbsd.org/ceil.3) 

For reasons unknown, the square root result is rounded up to the nearest
multiple of eight.

# Architecture

Each openrsync session is divided into a running *server* and *client*
process.
The client openrsync process is executed by the user.

```
% openrsync -rlpt host:path/to/source dest
```

The server openrsync is executed on a remote host either on-demand over
[ssh(1)](https://man.openbsd.org/ssh.1) or as a persistent network
daemon.
If executed over [ssh(1)](https://man.openbsd.org/ssh.1), the server
openrsync is distinguished from a client (user-started) openrsync by the
**--server** flag.

Once the client or server openrsync process starts, it examines the
command-line arguments to determine whether it's in *receiver* or
*sender* mode.
(The daemon is sent the command-line arguments in a protocol-specific
way described in
[rsyncd(5)](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5),
but otherwise does the same thing.)
The receiver is the destination for files; the sender is the origin.
There is always one receiver and one sender.

The server process is explicitly instructed that it is a sender with the
**--sender** command-line flag, otherwise it is a receiver.
The client process implicitly determines its status by looking at the
files passed on the command line for whether they are local or remote.

```
openrsync path/to/source host:destination
openrsync host:source path/to/destination
```

In the first example, the client is the sender: it *sends* data from
itself to the server.
In the second, the opposite is true in that it *receives* data.

The client's command-line files may have any of the following host
specifications that determine locality.

- local: *../path/to/source ../another*
- remote server: *host:path/to/source :path/to/another*
- remote daemon: *rsync://host/module/path ::another*

Host specifications must be consistent: sources must all be local or all
be remote on the same host.  Both may not be remote.  (**Aside**: it's
technically possible to do this.  I'm not sure why the GPL rsync is
limited to one or the other.)

If the source or destination is on a remote server, the client then
[fork(2)](https://man.openbsd.org/fork.2)s and starts the server
openrsync on the remote host over
[ssh(1)](https://man.openbsd.org/ssh.1).
The client and the server subsequently communicate over
[socketpair(2)](https://man.openbsd.org/socketpair.2) pipes.
If on a remote daemon, the client does *not* fork, but instead connects
to the standalone server with a network
[socket(2)](https://man.openbsd.org/socket.2).

The server's command-line, whether passed to an openrsync spawned on-demand
over an [ssh(1)](https://man.openbsd.org/ssh.1) session or passed to the daemon, 
differs from the client's.

```
openrsync --server [--sender] . files...
```

The files given are either the single destination directory when in receiver
mode, or the list of sources when in sender mode.
The standalone full-stop is a mystery to me.

Locality detection and routing to client and server run-times are
handled in
[main.c](https://github.com/kristapsdz/openrsync/blob/master/main.c).
The client for a server is implemented in
[client.c](https://github.com/kristapsdz/openrsync/blob/master/client.c)
and the server in
[server.c](https://github.com/kristapsdz/openrsync/blob/master/server.c).
The client for a network daemon is in
[socket.c](https://github.com/kristapsdz/openrsync/blob/master/socket.c).
Invocation of the remote server openrsync is managed in
[child.c](https://github.com/kristapsdz/openrsync/blob/master/child.c).

Once the client and server begin, they start to negotiate the transfer
of files over the connected socket.
The protocol used is specified in
[rsync(5)](https://github.com/kristapsdz/openrsync/blob/master/rsync.5).
For daemon connections, the
[rsyncd(5)](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5)
protocol is also used for handshaking.

The receiver side is managed in
[receiver.c](https://github.com/kristapsdz/openrsync/blob/master/receiver.c)
and the sender in
[sender.c](https://github.com/kristapsdz/openrsync/blob/master/sender.c).

The receiver side technically has two functions: not only must it upload
block metadata to the sender, it must also handle data writes as they
are sent by the sender.
The rsync protocol is designed so that the sender receives block
requests and continuously sends data to the receiver.

To accomplish this, the receiver multitasks as the *uploader* and
*downloader*.  These roles are implemented in
[uploader.c](https://github.com/kristapsdz/openrsync/blob/master/uploader.c).
and
[downloader.c](https://github.com/kristapsdz/openrsync/blob/master/downloader.c),
respectively.
The multitasking takes place by a finite state machine driven by data
coming from the sender and files on disc are they are ready to be
checksummed and uploaded.

The uploader scans through the list of files and asynchronously opens
files to process blocks.
While it waits for the files to open, it relinquishes control to the
event loop.
When files are available, it hashes and checksums blocks and uploads to
the sender.

The downloader waits on data from the sender.
When data is ready (and prefixed by the file it will update), the
downloader asynchronously opens the existing file to perform any block
copying.
When the file is available for reading, it then continues to read data
from the sender and copy from the existing file.

## Differences from rsync

The design of rsync involves another mode running alongside the
receiver: the generator.
This is implemented as another process
[fork(2)](https://man.openbsd.org/fork.2)ed from the receiver, and
communicating with the receiver and sender.

In openrsync, the generator and receiver are one process, and an event
loop is used for speedy responses to read and write requests.

# Security

Besides the usual defensive programming, openrsync makes significant use
of native security features.

The system operations available to executing code are foremost limited
by OpenBSD's [pledge(2)](https://man.openbsd.org/pledge.2).  The pledges
given depend upon the operating mode.  For example, the receiver needs
write access to the disc---but only when not in dry-run mode (**-n**).
The daemon client needs DNS and network access, but only to a point.
[pledge(2)](https://man.openbsd.org/pledge.2) allows available resources
to be limited over the course of operation.

The second tool is OpenBSD's
[unveil(2)](https://man.openbsd.org/unveil.2), which limits access to
the file-system.  This protects against rogue attempts to "break out" of
the destination.  It's an attractive alternative to
[chroot(2)](https://man.openbsd.org/chroot.2) because it doesn't require
root permissions to execute.

On the receiver side, the file-system is 
[unveil(2)](https://man.openbsd.org/unveil.2)ed at and beneath the
destination directory.
After the creation of the destination directory, only targets within
that directory may be accessed or modified.

Lastly, the MD4 hashs are seeded with
[arc4random(3)](https://man.openbsd.org/arc4random.3) instead of with
[time(3)](https://man.openbsd.org/time.3).  (This function is provided
on a number of operating systems.) This is only applicable when running
openrsync in server mode, as the server generates the seed.

# Portability

Many have asked about portability.

The only officially-supported operating system is OpenBSD, as this has
considerable security features.  openrsync does, however, use
[oconfigure](https://github.com/kristapsdz/oconfigure) for compilation
on non-OpenBSD systems.  This is to encourage porting.

The actual work of porting is matching the security features provided by
OpenBSD's [pledge(2)](https://man.openbsd.org/pledge.2) and
[unveil(2)](https://man.openbsd.org/unveil.2).  These are critical
elements to the functionality of the system.  Without them, your system
accepts arbitrary data from the public network.

This is possible (I think?) with FreeBSD's
[Capsicum](https://man.freebsd.org/capsicum(4)), but Linux's security
facilities are a mess, and will take an expert hand to properly secure.

**rsync has specific running modes for the super-user**.
It also pumps arbitrary data from the network onto your file-system.
openrsync is about 10 000 lines of C code: do you trust me not to make
mistakes?

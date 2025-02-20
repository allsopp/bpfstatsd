# bpfstatsd

## Synopsis

    $ bpfstatsd [options...] <command> [arguments...]

## Description

`bpfstatsd` is a background daemon that runs an arbitrary command for every N
packets received on a network interface, using statistics gathered from the
[Berkeley Packet Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter),
which on BSD systems is the `/dev/bpf` device.

For example, to output a message for every 100 packets on `em0`:

    $ bpfstatsd -c 100 -i em0 /bin/sh -c 'echo "Hello, World!"'

The number of packets required to trigger the command and the interface to
measure statistics for are configurable using command-line arguments but, if
omitted, default to 1 and `pflog0`, respectively. For full documentation, run:

    $ bpfstatsd -h

Although this software is a general-purpose packet counter, the author
anticipates that it will be most useful when combined with dedicated `pflog(4)`
interfaces that log specific firewall rules. For example, this software could
be used to run a command when connections are blocked or established through a
firewall using a particular address, protocol, or port. More comprehensive
examples are documented in later sections.

## Caveats

This program depends on the `/dev/bpf` interface and is currently only
supported on [OpenBSD](https://www.openbsd.org/), although it may be ported to
other operating systems in the future. See the `bpf(4)` manual page for more
information.

The minimum (and default) wait period for packet statistics comparison is once
per second; this value is configurable with the `-w` command-line argument but
can only be increased. This means that the command will be triggered, at most,
once per wait period. You can think of the `count` argument as a minimum
threshold required to trigger the command. A possible improvement to this
software would be to forgo the wait period entirely and run the command exactly
once per `count` packets.

The `bpfstatsd` binary requires, and is therefore installed with, `root` setuid
privileges which are necessary to open the `/dev/bpf` device. These privileges
are dropped at the earliest opportunity to mitigate any vulnerabilities.
Additional security measures employed include the `pledge(2)` and `unveil(2)`
system calls to limit system call and filesystem access, respectively, although
these mitigations are not implemented for the command run by `bpfstatsd` which
runs in a separate child process via `execve(2)`.

## Building and installation

To build and install the binary to `/usr/local/bin/bpfstatsd`, run:

    $ make && doas make install

An example file suitable for `rc.d(8)` is provided in the `rc` directory of
this distribution.

## Example 1: Home automation

In this example, `bpfstatsd` is used to automatically turn on an unattended
device (for example, an IP camera) when clients attempt to connect to it.

### Prerequisites

Connections to the device must be made through a `pf(4)` firewall so they can
be logged to a `pflog(4)` interface that this software uses to measure
statistics. It is technically possible to use the `bpf(4)` device to detect the
connections directly on the receiving interface, without any `pflog(4)`
involvement, but that is beyond the intended scope of this software, which is
to be a simple packet counter for a particular interface.

This example assumes the device is connected to a smart plug and controllable
via [Zigbee2MQTT](https://www.zigbee2mqtt.io/), although this example should,
in theory, work with any home automation system that exposes a suitable
interface. The [cURL](https://curl.se/) binary must be installed to send the
message to the MQTT broker to turn on the device. The actual command depends on
the home automation system used.

### Configuration

Create a dedicated `pflog(4)` interface, e.g.

    # echo "up" > /etc/hostname.pflog1
    # sh /etc/netstat pflog1

Configure `pf(4)` to log packets that create state to this interface (refer to
the `pf.conf(5)` manual page for full details), e.g.

    pass in log (to pflog1) quick on lan inet proto tcp to $camera port 9000

### Running the daemon

Run `bpfstatsd` to send an MQTT message for each packet on `pflog1`, e.g.

    $ bpfstatsd -i pflog1 /usr/local/bin/curl \
        -d '{"state": "ON"}' \
        mqtt://localhost/zigbee2mqtt/plug1/set

If this is all working as intended, then a connection to the device will turn
the device on if it was previously turned off. Automatically turning _off_ the
device is out of scope for this documentation and is left as an exercise for
the reader.

---

# Work In Progress

This software is still under development and should be considered experimental.
It is currently developed for x86-64 and has not been built or tested for ARM
targets.

---

# VSOCK module for Xen/Argo

[vsock(7)](http://man7.org/linux/man-pages/man7/vsock.7.html) is an address
family to facilitate communication between virtual machines.
[Argo](https://xenbits.xenproject.org/docs/unstable/designs/argo.html) is an
interdomain communication mechanism for Xen.

This module implements Argo primitives under the Vsock address family to allow
socket communication between Xen domains.

## Getting started

### Linux module

Building `vsock_argo_transport` will require your Linux kernel headers. It can
be built as an out-of-tree module. A convenience Makefile is provided:
```bash
 $ make -C module
```

The module itself will require VSock support in the kernel:
```bash
 $ zgrep CONFIG_VSOCKETS /proc/config.gz
CONFIG_VSOCKETS=m
CONFIG_VSOCKETS_DIAG=m
 $ sudo modprobe vsock
```

It is possible that another VSock transport driver was already loaded, you will
need to remove it, e.g:
```bash
 $ lsmod | grep vsock
vmw_vsock_vmci_transport    32768  0
vmw_vmci               77824  1 vmw_vsock_vmci_transport
vsock                  40960  1 vmw_vsock_vmci_transport
 $ sudo rmmod vmw_vsock_vmci_transport
```
Then load the module and confirm the operation succeeded.
```bash
 $ sudo insmod module/vsock_argo_transport.ko
 $ dmesg -H | grep argo
[  +0.000017] vsock_argo_transport registered.
```

### Test client

A test `netcat` like utility is provided to simplify send and receive operation
using VSock datagram over Argo, the tool is call `hatch` and roughly follows
the `netcat` usage.

<sup><sub>Ship cargo, packets, are usualy passed through a `hatch`, hence the
name... Since Argo is an old mythological ship.</sub></sub>

It builds using autotools:
```bash
 $ cd test/hatch
 $ autoreconf -i
 $ mkdir dist ; ./configure --prefix=$(pwd)/dist
 ...
 $ make install
 $ ./dist/bin/hatch -h
Basic usage:
        hatch domid port
        hatch -r -p local_port
Options:
        -r, --recv      receive mode, wait for incoming packets.
        -p, --port      set local port number.
        -D              enable debug output on stderr.
```

## Testing

Argo was released with Xen 4.12.0, but is still experimental feature. You will
likely need to rebuild Xen to enable argo and change its cmdline. I recommend
following the way your distribution packages Xen (PKGBUILD, sbuild, etc) and
amend with the changes described below. The following is only provided as an
example:
```bash
 $ git clone git://xenbits.xen.org/xen.git
 $ cd xen
 $ git checkout -b stable-4.12 origin/stable-4.12
 $ echo 'CONFIG_ARGO=y' >> xen/.config
 $ PYTHON=/usr/bin/python2 ./configure --prefix=/usr --sbindir=/usr/bin --with-sysconfig-leaf-dir=conf.d --with-rundir=/run --enable-systemd--with-extra-qemuu-configure-args="--disable-bluez --disable-gtk --disable-vte --disable-werror --disable-virglrenderer --disable-libnfs --disable-glusterfs --disable-numa --disable-smartcard --disable-fdt --enable-spice --enable-usb-redir --with-sdlabi=1.2"
 $ yes "" | make XEN_CONFIG_EXPERT=y -C xen oldconfig
 $ make XEN_CONFIG_EXPERT=y LANG=C PYTHON=python2 dist
```

Install and configure the previously built Xen to suit your distribution. This
is beyond the scope of this document.

Add `argo=true,mac-permissive=1` to your Xen cmdline and reboot on the freshly
built Xen with Argo support.

You will need at least 1 Xen guest, other than dom0, to test
`vsock_argo_transport.ko`. No guest specific guest configuration is required,
e.g:
```
type = "pvh"
kernel="/var/lib/machines/vm0/boot/vmlinuz-linux"
ramdisk="/var/lib/machines/vm0/boot/initramfs-linux.img"
root="/dev/xvda"
extra="earlyprintk=xen console=tty0 console=hvc0,115200n8 rw quiet"
name = "vm0.pvh"
memory = 512
maxmem = 512
vcpus = 2
vfb = [ "type=vfb, vnc=1, vnclisten=0.0.0.0, vncdisplay=1" ]
vif = [ 'mac=00:16:3e:01:01:01, bridge=br0' ]
disk = [ '/dev/vg0/vm0,raw,xvda,rw' ]
```

Start and log into the guest to load `vsock_argo_transport.ko`. `hatch` can be
used as netcat using the domain-id as address and a port.
```bash
user@dom0 $ hatch -r -p 1234 > /tmp/file
 ^C
user@dom0 $ md5sum file
b061b7954fbcb8b17cc7e2e8a5754269  file
```
```bash
user@vm0 $ md5sum file
b061b7954fbcb8b17cc7e2e8a5754269  file
user@vm0 $ hatch 0 1234 < file
```

#
# Copyright (c) 2012 Citrix Systems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

V4V_VERSION=1.0
obj-m += v4v.o 
KVERSION := $(shell uname -r)

# 6-args hypercall will use ebp for the 6th argument on x86.
ccflags-$(CONFIG_X86_32) += -fomit-frame-pointer

all:
	make -C /lib/modules/${KVERSION}/build M=$(PWD) modules -I$(PWD) EXTRA_CFLAGS="-g -I$(PWD)/include -I$(PWD)"

install:
	install -d ${DESTDIR}/usr/include/xen
	install -m 0644 include/xen/v4v.h ${DESTDIR}/usr/include/xen
	
	install -d ${DESTDIR}/usr/include/linux
	install -m 0644 linux/v4v_dev.h ${DESTDIR}/usr/include/linux

module_install:
	install -d ${DESTDIR}/lib/modules/${KVERSION}/kernel/driver/xen
	install -m 0644 v4v.ko ${DESTDIR}/lib/modules/${KVERSION}/kernel/driver/xen
	depmod -a

modules:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules EXTRA_CFLAGS="-DXC_KERNEL=1 -I$(PWD)/include -I$(PWD)"
modules_install:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules_install
clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean

dkms.conf: dkms/dkms.conf.in
control: dkms/control.in
	sed -re 's/%V4V_VERSION%/${V4V_VERSION}/g' $< > $@

dpkg-build: dkms.conf control

dpkg_data="tmp-deb/data"
dpkg_control="tmp-deb/control"
v4v-dkms_${V4V_VERSION}_all.deb: dpkg-build
	rm -rf tmp-deb
	mkdir -p ${dpkg_data} ${dpkg_control} ${dpkg_data}/usr/src/v4v-${V4V_VERSION}
	
	cp -r dkms.conf Makefile include linux v4v.c ${dpkg_data}/usr/src/v4v-${V4V_VERSION}
	install -m 0644 -D dkms/lintian ${dpkg_data}/usr/share/lintian/overrides/v4v-dkms
	install -m 0755 -d ${dpkg_data}/usr/share/doc/v4v-dkms
	(cd ${dpkg_data}/usr/share/doc/v4v-dkms && ln -s ../../common-licenses/GPL-2 copyright)
	( cd tmp-deb/data && find . -type f -exec md5sum {} \;) | sed -re 's| ./||g' > ${dpkg_control}/md5sums
	tar  --create --owner=root --group=root --gzip --file=tmp-deb/data.tar.gz --directory=tmp-deb/data .
	
	cp dkms/debian-binary tmp-deb
	cp dkms/postinst dkms/prerm ${dpkg_control}
	cp control ${dpkg_control}
	tar  --create --owner=root --group=root --gzip --file=tmp-deb/control.tar.gz --directory=tmp-deb/control .
	
	( cd tmp-deb && ar rcD ../$@ debian-binary control.tar.gz data.tar.gz)
dpkg: v4v-dkms_${V4V_VERSION}_all.deb

lintian: v4v-dkms_${V4V_VERSION}_all.deb
	lintian $<

dkms_init: dkms.conf
	sudo rm -rf /usr/src/v4v*
	sudo mkdir /usr/src/v4v-${V4V_VERSION}
	sudo cp -r $(PWD)/* /usr/src/v4v-${V4V_VERSION}

dkms_add:
	sudo dkms add -m v4v -v ${V4V_VERSION}

dkms_remove:
	sudo dkms remove -m v4v -v ${V4V_VERSION} --all

dkms_build:
	sudo dkms build -m v4v -v ${V4V_VERSION}

dkms_mkdeb:
	sudo dkms mkdeb -m v4v -v ${V4V_VERSION}

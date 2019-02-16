Name: libargo
Summary: libargo
Source0: libargo.tar.gz
BuildArch: i686 x86_64
Version: 1.0
Release: 1%{?dist}
License: LGPL2.1

%description
libargo

%prep
%setup -q

%build
autoreconf -i
./configure \
	--prefix=%{_prefix} \
	--libdir=%{_libdir} \
	--includedir=%{_includedir} \
	--enable-silent-rules \
	CFLAGS="-I./src/" CPPFLAGS="-I./src/"
%make_build

%install
make LIBTOOLFLAGS=--silent DESTDIR=%{buildroot} -C src install 2>&1 | sed "s/libtool: install: [w]arning:/libtool: install: info:/"
make LIBTOOLFLAGS=--silent DESTDIR=%{buildroot} install-data-am

%files
%{_libdir}/libargo-1.0.so.0
%{_libdir}/libargo-1.0.so.0.0.0
%{_libdir}/libargo_nointerposer-1.0.so.0
%{_libdir}/libargo_nointerposer-1.0.so.0.0.0

%package devel
Summary: libargo-devel

%description devel
libargo-devel

%files devel
%{_includedir}/libargo.h
%{_libdir}/libargo.a
%{_libdir}/libargo.la
%{_libdir}/libargo.so
%{_libdir}/libargo_nointerposer.a
%{_libdir}/libargo_nointerposer.la
%{_libdir}/libargo_nointerposer.so
%{_libdir}/pkgconfig/libargo.pc

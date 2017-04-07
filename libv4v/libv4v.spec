Name: libv4v
Summary: libv4v
Source0: libv4v.tar.gz
BuildArch: i686 x86_64
Version: 1.0
Release: 1%{?dist}
License: LGPL2.1

%description
libv4v

%prep
%setup -q

%build
mkdir -p m4
autoreconf -i
./configure \
	--prefix=%{_prefix} \
	--libdir=%{_libdir} \
	--includedir=%{_includedir} \
	CFLAGS="-I./src/" CPPFLAGS="-I./src/"
%make_build

%install
make DESTDIR=%{buildroot} -C src install
make DESTDIR=%{buildroot} install-data-am

%files
%{_libdir}/libv4v-1.0.so.0
%{_libdir}/libv4v-1.0.so.0.1.1
%{_libdir}/libv4v_nointerposer-1.0.so.0
%{_libdir}/libv4v_nointerposer-1.0.so.0.1.1

%package devel
Summary: libv4v-devel

%description devel
libv4v-devel

%files devel
%{_includedir}/libv4v.h
%{_libdir}/libv4v.a
%{_libdir}/libv4v.la
%{_libdir}/libv4v.so
%{_libdir}/libv4v_nointerposer.a
%{_libdir}/libv4v_nointerposer.la
%{_libdir}/libv4v_nointerposer.so
%{_libdir}/pkgconfig/libv4v.pc

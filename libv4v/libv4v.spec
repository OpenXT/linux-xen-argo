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
./configure --prefix=/usr/local CFLAGS="-I./src/" CPPFLAGS="-I./src/"
make

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install

%files
/usr/local/*

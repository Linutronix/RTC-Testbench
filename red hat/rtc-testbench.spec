# Copyright (C) 2024,2025 Red Hat
# Author Pablo Iranzo Gómez <Pablo.Iranzo@redhat.com>
# SPDX-License-Identifier: BSD-2-Clause

Name: RTC-Testbench
Version: %{version}
Release: 1%{?dist}
Summary: Time-Sensitive Networks Testbench is a set of tools for validating the networks with different protocols
License: BSD-2
%undefine _disable_source_fetch
URL: https://github.com/Linutronix/RTC-Testbench
Source0: https://github.com/%{myrepo}/archive/refs/tags/%{version}.tar.gz


BuildRequires: clang
BuildRequires: cmake
BuildRequires: libxdp-devel
BuildRequires: libyaml-devel
BuildRequires: llvm
BuildRequires: mosquitto-devel
BuildRequires: openssl-devel
BuildRequires: python3-sphinx
BuildRequires: python3-sphinx_rtd_theme
BuildRequires: texinfo

%description
The RTC Testbench is a real-time and non-real-time traffic validation tool for converged TSN networks. PROFINET as well as OPC/UA PubSub and other configurable protocols are supported.

%prep
cd %{_topdir}/BUILD
rm -rf %{name}-%{version}
git clone https://github.com/%{myrepo} %{name}-%{version}
cd %{name}-%{version}
git checkout %{version}

%build
cd %{_topdir}/BUILD/%{name}-%{version}
cmake -DCMAKE_BUILD_TYPE=Release
make DESTDIR=${RPM_BUILD_ROOT} install

# Build documentation
make -C Documentation   man

%install

mkdir -p %{buildroot}/usr/bin/
install -m 755 /usr/local/bin/reference %{buildroot}/usr/bin/reference
install -m 755 /usr/local/bin/mirror %{buildroot}/usr/bin/mirror


mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8
install -m  644 %{_topdir}/BUILD/%{name}-%{version}/Documentation/_build/man/linuxrealtimecommunicationtestbench.1  $RPM_BUILD_ROOT/usr/share/man/man8/%{name}.1

mkdir -p %{buildroot}/usr/local/testbench/ebpf/
install -m 755 -d /usr/local/share/testbench/ebpf/
cp -a /usr/local/share/testbench/ebpf/* %{buildroot}/usr/local/testbench/ebpf/

mkdir -p %{buildroot}/usr/local/testbench/tests/
install -m 755 -d /usr/local/share/testbench/tests/
cp -a /usr/local/share/testbench/tests/* %{buildroot}/usr/local/testbench/tests/

%files
/usr/share/man/man8/%{name}.1.gz
/usr/bin/reference
/usr/bin/mirror
/usr/local/testbench/tests/
/usr/local/testbench/ebpf/

%changelog
* Wed Sep 11 2024 Pablo Iranzo Gómez <Pablo.Iranzo@redhat.com>
- first packaging

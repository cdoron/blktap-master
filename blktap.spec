Summary: blktap user space utilities
Name: blktap
Version: master
Release: 1.0
License: BSD
Group: System/Hypervisor
URL: https://github.com/xapi-project/blktap
Source0: https://code.citrite.net/rest/archive/latest/projects/XSU/repos/%{name}/archive?at=v%{version}&format=tar.gz&prefix=%{name}-%{version}#/%{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{release}-buildroot
Obsoletes: xen-blktap
BuildRequires: e2fsprogs-devel, libaio-devel, systemd, autogen, autoconf, automake, libtool, libuuid-devel
BuildRequires: xen-devel, kernel-headers, xen-dom0-libs-devel, zlib-devel, xen-libs-devel, libcmocka-devel, lcov, git
Requires(post): systemd
Requires(post): /sbin/ldconfig
Requires(preun): systemd
Requires(postun): systemd
Requires(postun): /sbin/ldconfig

%description
Blktap creates kernel block devices which realize I/O requests to
processes implementing virtual hard disk images entirely in user
space.

Typical disk images may be implemented as files, in memory, or
stored on other hosts across the network. The image drivers included
with tapdisk can map disk I/O to sparse file images accessed through
Linux DIO/AIO and VHD images with snapshot functionality.

This packages includes the control utilities needed to create
destroy and manipulate devices ('tap-ctl'), the 'tapdisk' driver
program to perform tap devices I/O, and a number of image drivers.

%package devel
Summary: BlkTap Development Headers and Libraries
Requires: blktap = %{version}
Group: Development/Libraries
Obsoletes: xen-blktap

%description devel
Blktap and VHD development files.

%prep
%autosetup -p1 -S git

%build
echo -n %{version} > VERSION
sh autogen.sh
%configure
%{?cov_wrap} make %{?coverage:GCOV=true}

%check
make check || (find mockatests -name \*.log -print -exec cat {} \; && false)
./collect-test-results.sh %{buildroot}/testresults

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}%{_localstatedir}/log/blktap
%if 0%{?coverage:1}
cd ../ && find -name "*.gcno" | grep -v '.libs/' | xargs -d "\n" tar -cvjSf %{buildroot}/%{name}-%{version}.gcno.tar.bz2
%endif

%triggerin -- mdadm
echo 'KERNEL=="td[a-z]*", GOTO="md_end"' > /etc/udev/rules.d/65-md-incremental.rules
cat /usr/lib/udev/rules.d/65-md-incremental.rules >> /etc/udev/rules.d/65-md-incremental.rules

%files
%defattr(-,root,root,-)
%docdir /usr/share/doc/%{name}
/usr/share/doc/%{name}
%{_libdir}/*.so
%{_libdir}/*.so.*
%{_bindir}/vhd-util
%{_bindir}/vhd-update
%{_bindir}/vhd-index
%{_bindir}/tapback
%{_bindir}/cpumond
%{_sbindir}/cbt-util
%{_sbindir}/lvm-util
%{_sbindir}/tap-ctl
%{_sbindir}/td-util
%{_sbindir}/td-rated
%{_sbindir}/part-util
%{_sbindir}/vhdpartx
%{_libexecdir}/tapdisk
%{_sysconfdir}/logrotate.d/blktap
%{_sysconfdir}/xensource/bugtool/tapdisk-logs.xml
%{_sysconfdir}/xensource/bugtool/tapdisk-logs/description.xml
%{_localstatedir}/log/blktap
%{_unitdir}/tapback.service
%{_unitdir}/cpumond.service

%files devel
%defattr(-,root,root,-)
%doc
%{_libdir}/*.a
%{_libdir}/*.la
%{_includedir}/vhd/*
%{_includedir}/blktap/*
%if 0%{?coverage:1}
/%{name}-%{version}.gcno.tar.bz2
%endif

%post
/sbin/ldconfig
%systemd_post tapback.service
%systemd_post cpumond.service

%preun
%systemd_preun tapback.service
%systemd_preun cpumond.service

%postun
/sbin/ldconfig
%systemd_postun tapback.service
%systemd_postun cpumond.service
if [ $1 -eq 0 ]; then
    rm -f %{_sysconfdir}/udev/rules.d/65-md-incremental.rules
fi

# The posttrans invocation of ldconfig is needed because older
# versions of blktap did not have ldconfig in their postun script.
%posttrans -p /sbin/ldconfig

%changelog
* Mon Aug 06 2018 Mark Syms <mark.syms@citrix.com> - 3.12.0-1
- CA-227096 Allow stashed passed fds to overwrite with the same name

* Wed Jul 25 2018 Mark Syms <mark.syms@citrix.com> - 3.11.0-1
- CA-294079 Revert "CA-205513: Removing bad fds from the fdset passed to select call."

* Thu Jul 19 2018 Tim Smith <tim.smith@citrix.com> - 3.10.0-2.0
- Add ldconfig in posttrans to support update from older versions

* Mon Jul 16 2018 Mark Syms <mark.syms@citrix.com> - 3.10.0-1
- valve: fix duplicated forwarding

* Wed Jul 11 2018 Mark Syms <mark.syms@citrix.com> - 3.9.0-1
- XOP-944 Fix crashes and errors in stats
- CP-24318: Closed resource leak in vhd_macx_decode_location()
- CA-293563 prevent race when creating blktap/control device node
- Update coverage profile dirs so that product and test code match
- make O_DIRECT optional

* Thu Jun 28 2018 Tim Smith <tim.smith@citrix.com> - 3.8.0-2.0
- Run ldconfig on install/uninstall

* Mon Jun 18 2018 Mark Syms <mark.syms@citrix.com> - 3.8.0-1
- Update specfile template
- Remove VERSION and WHATS_NEW files, this information is in git history and tags
- Remove WHATS_NEW from Makefile.am

* Fri May 25 2018 marksy <mark.syms@citrix.com> - 3.7.0-1.0
- CA-285194: ensure that tapdisk logs if it exits and also on opening its control

* Fri May 25 2018 marksy <mark.syms@citrix.com> - 3.6.0-1.0
- Release 3.6.0

* Tue Apr 10 2018 marksy <mark.syms@citrix.com> - 3.5.0-1.17
- CA-277128: remove redundant, broken RRD code from tapdisk

* Tue Mar 27 2018 marksy <mark.syms@citrix.com> - 3.5.0-1.16
- Gather the gcov coverage files during build

* Fri Feb 16 2018 marksy <mark.syms@citrix.com> - 3.5.0-1.15
- CP-26852: Support building with upstream Linux

* Tue Jan 30 2018 marksy <mark.syms@citrix.com> - 3.5.0-1.14
- Convert patch to use tabs for merge to github
- Reorder patchqueue with patches commited to github
- CA-220042: Add missing half of pull request 191 to patchqueue
- Update patchqueue patch to match the github pull request

* Wed Dec 06 2017 marksy <mark.syms@citrix.com> - 3.5.0-1.13
- CP-20541 Enable conditional coverage build

* Thu Oct 12 2017 marksy <mark.syms@citrix.com> - 3.5.0-1.12
- Patch cleanup

* Wed Oct 11 2017 marksy <mark.syms@citrix.com> - 3.5.0-1.11
- CA-268288: Send logpath as an additional write

* Wed Sep 27 2017 marksy <mark.syms@citrix.com> - 3.5.0-xs.1+1.10
- CP-23545: Extend tap-ctl create to consider CBT parameters
- CP-23920: [Unit test] Increase test coverage for cbt-util coalesce
- CP-24547: [Unit test] Increase test coverage for cbt-util set


%package testresults
Group:    System/Hypervisor
Summary:  test results for blktap package

%description testresults
The package contains the build time test results for the blktap package

%files testresults
/testresults

Name: argus-gsi-pep-callout

Version: 1.2.3
Release: 1%{?dist}

Summary: Argus PEP callout for globus GSI

License: ASL 2.0
Group: System Environment/Libraries
URL: https://twiki.cern.ch/twiki/bin/view/EGEE/AuthorizationFramework

Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: globus-gridmap-callout-error-devel
BuildRequires: globus-gssapi-gsi
BuildRequires: pkgconfig
BuildRequires: globus-gssapi-gsi-devel
BuildRequires: globus-gridmap-callout-error
BuildRequires: globus-gssapi-error-devel
BuildRequires: globus-gss-assist-devel
BuildRequires: libtool
BuildRequires: argus-pep-api-c-devel
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: argus-pep-api-c
BuildRequires: chrpath

Requires: argus-pep-api-c
Requires: globus-gridmap-callout-error
Requires: globus-gssapi-gsi


%description
Argus PEP client callout module for globus GSI (EMI)

%prep
%setup -q


%build
%configure

# The following two lines were suggested by
# https://fedoraproject.org/wiki/Packaging/Guidelines to prevent any
# RPATHs creeping in.
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'
strip -s -v %{buildroot}%{_libdir}/*.so

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libgsi_pep_callout.so.1.0.0
%{_libdir}/libgsi_pep_callout.so.1
%{_libdir}/libgsi_pep_callout.so

%doc COPYRIGHT LICENSE README etc/gsi-pep-callout.conf etc/gsi-authz.conf CHANGELOG

%changelog
* Fri Aug 3 2012 Valery Tschopp <valery.tschopp@switch.ch> 1.2.3-1
- Self managed packaging with spec file.

* Tue Apr 3 2012 Valery Tschopp <valery.tschopp@switch.ch> 1.2.2-1
- Initial GSI Argus PEP callout plugin for GT4 for EMI 2.




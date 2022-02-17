%define install_base        /usr/lib/kibana
%define archive_base        %{install_base}/archive
%define scripts_base        %{archive_base}/kibana-scripts
%define config_base         /etc/kibana/archive

#Version variables set by automated scripts
%define perfsonar_auto_version 5.0.0
%define perfsonar_auto_relnum 0.0.a1

Name:			kibana-archive
Version:		%{perfsonar_auto_version}
Release:		%{perfsonar_auto_relnum}%{?dist}
Summary:		Install and configure Kibana for Opendistro
License:		ASL 2.0
Group:			Development/Libraries
URL:			http://www.perfsonar.net
Source0:		kibana-archive-%{version}.%{perfsonar_auto_relnum}.tar.gz
BuildRoot:		%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:		noarch
Requires:       	opendistroforelasticsearch-kibana

%description
A package that installs and configure Kibana for Opendistro.

%pre
/usr/sbin/groupadd -r perfsonar 2> /dev/null || :
/usr/sbin/useradd -g perfsonar -r -s /sbin/nologin -c "perfSONAR User" -d /tmp perfsonar 2> /dev/null || :

%prep
%setup -q -n kibana-archive-%{version}.%{perfsonar_auto_relnum}

%build

%install
make KIBANA-ROOTPATH=%{buildroot}/%{archive_base} KIBANA-CONFIGPATH=%{buildroot}/%{config_base} install

%clean
rm -rf %{buildroot}

%post
#create config directory
mkdir -p %{config_base}

#Restart/enable kibana 
%systemd_post kibana.service
if [ "$1" = "1" ]; then
    #if new install, then enable
    systemctl daemon-reload
    systemctl enable kibana.service
    #run kibana pre startup script
    bash %{scripts_base}/kibana_secure_pre.sh
    #start kibana
    systemctl start kibana.service
    #run kibana post startup script
    bash %{scripts_base}/kibana_secure_pos.sh
fi

%preun
%systemd_preun kibana.service

%postun
%systemd_postun_with_restart kibana.service

%files
%defattr(0644,perfsonar,perfsonar,0755)
%license LICENSE
%attr(0755, perfsonar, perfsonar) %{scripts_base}/*

%changelog
* Sun Mar 21 2021 andy@es.net 4.4.0-0.0.a1
- Initial spec file created

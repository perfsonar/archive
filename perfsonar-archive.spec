%define install_base        /usr/lib/perfsonar
%define archive_base        %{install_base}/archive
%define scripts_base        %{archive_base}/perfsonar-scripts
%define setup_base          %{archive_base}/pselastic_setup
%define config_base         /etc/perfsonar/archive

#Version variables set by automated scripts
%define perfsonar_auto_version 4.4.0
%define perfsonar_auto_relnum 0.0.a1

Name:			perfsonar-archive
Version:		%{perfsonar_auto_version}
Release:		%{perfsonar_auto_relnum}%{?dist}
Summary:		perfSONAR Measurement Archive
License:		ASL 2.0
Group:			Development/Libraries
URL:			http://www.perfsonar.net
Source0:		perfsonar-archive-%{version}.%{perfsonar_auto_relnum}.tar.gz
BuildRoot:		%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:		noarch
Requires:		opendistroforelasticsearch
Requires:       	java-11-openjdk
Requires:       	openssl
Requires:       	perfsonar-logstash

%description
A package that installs the perfSONAR Archive based on Logstash and Opendistro for Elasticsearch.

%pre
/usr/sbin/groupadd -r perfsonar 2> /dev/null || :
/usr/sbin/useradd -g perfsonar -r -s /sbin/nologin -c "perfSONAR User" -d /tmp perfsonar 2> /dev/null || :

%prep
%setup -q -n perfsonar-archive-%{version}.%{perfsonar_auto_relnum}

%build

%install
make ROOTPATH=%{buildroot}/%{archive_base} CONFIGPATH=%{buildroot}/%{config_base} install

%clean
rm -rf %{buildroot}

%post
#create config directory
mkdir -p %{config_base}

export JAVA_HOME=/usr/share/elasticsearch/jdk
%{scripts_base}/pselastic_secure.sh

#Restart/enable elasticsearch and logstash
%systemd_post elasticsearch.service
%systemd_post logstash.service
if [ "$1" = "1" ]; then
    #if new install, then enable
    systemctl enable elasticsearch.service
    systemctl start elasticsearch.service
    systemctl enable logstash.service
    systemctl start logstash.service
fi

%preun
%systemd_preun elasticsearch.service

%postun
%systemd_postun_with_restart elasticsearch.service

%files
%defattr(0644,perfsonar,perfsonar,0755)
%license LICENSE
%attr(0755, perfsonar, perfsonar) %{scripts_base}/*
%attr(0755, perfsonar, perfsonar) %{setup_base}/bin/*
%{setup_base}/conf.d/ilm/*
%{setup_base}/conf.d/roles/*
%{setup_base}/conf.d/users/*
%{setup_base}/pselastic/*

%changelog
* Sun Mar 21 2021 andy@es.net 4.4.0-0.0.a1
- Initial spec file created

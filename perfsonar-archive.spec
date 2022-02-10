%define install_base        /usr/lib/perfsonar
%define archive_base        %{install_base}/archive
%define scripts_base        %{archive_base}/perfsonar-scripts
%define setup_base          %{archive_base}/config
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
Requires:       java-11-openjdk
Requires:       openssl
Requires:       jq
Requires:       perfsonar-logstash
Requires:       perfsonar-elmond

%description
A package that installs the perfSONAR Archive based on Logstash and Opendistro for Elasticsearch.

%pre
/usr/sbin/groupadd -r perfsonar 2> /dev/null || :
/usr/sbin/useradd -g perfsonar -r -s /sbin/nologin -c "perfSONAR User" -d /tmp perfsonar 2> /dev/null || :

%prep
%setup -q -n perfsonar-archive-%{version}.%{perfsonar_auto_relnum}

%build

%install
make PERFSONAR-ROOTPATH=%{buildroot}/%{archive_base} PERFSONAR-CONFIGPATH=%{buildroot}/%{config_base} install
install -D -m 0644 config/pscheduler-default-archive.json %{buildroot}/etc/pscheduler/default-archives/http_logstash.json

%clean
rm -rf %{buildroot}

%post
#create config directory
mkdir -p %{config_base}

export JAVA_HOME=/usr/share/elasticsearch/jdk

#Restart/enable elasticsearch and logstash
%systemd_post elasticsearch.service
%systemd_post logstash.service
if [ "$1" = "1" ]; then
    #if new install, then enable
    systemctl daemon-reload
    systemctl enable elasticsearch.service
    systemctl enable logstash.service
    #fix directory permissions
    chmod g+ws /etc/elasticsearch/
    chown -R root:elasticsearch /etc/elasticsearch/
    #run elasticsearch pre startup script
    bash %{scripts_base}/pselastic_secure_pre.sh
    #start elasticsearch
    systemctl start elasticsearch.service
    #restart logstash
    systemctl restart logstash.service
    #restart the service to fix port conflict
    systemctl restart opendistro-performance-analyzer.service
    #run elasticsearch post startup script
    bash %{scripts_base}/pselastic_secure_pos.sh
    #run elmond configuration script
    bash %{scripts_base}/elmond_configuration.sh
    usermod -a -G elasticsearch perfsonar
    #restart elmond
    systemctl restart elmond.service
    #restart pscheduler-archiver to load new default-archive
    systemctl restart pscheduler-archiver
fi

%preun
%systemd_preun elasticsearch.service

%postun
%systemd_postun_with_restart elasticsearch.service

%files
%defattr(0644,perfsonar,perfsonar,0755)
%license LICENSE
%attr(0755, perfsonar, perfsonar) %{scripts_base}/*
%{setup_base}/ilm/*
%{setup_base}/roles/*
%{setup_base}/users/*
/etc/pscheduler/default-archives/http_logstash.json

%changelog
* Thu Sep 09 2021 daniel.neto@rnp.br 4.4.0-0.0.a1
- Adding script to configure elmond

* Sun Mar 21 2021 andy@es.net 4.4.0-0.0.a1
- Initial spec file created

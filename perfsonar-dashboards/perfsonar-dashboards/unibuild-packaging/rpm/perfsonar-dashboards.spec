%define install_base        /usr/lib/perfsonar
%define dashboards_base     %{install_base}/dashboards
%define scripts_base        %{dashboards_base}/dashboards-scripts
%define httpd_config_base   /etc/httpd/conf.d

#Version variables set by automated scripts
%define perfsonar_auto_version 5.1.0
%define perfsonar_auto_relnum 0.b1.5

Name:			perfsonar-dashboards
Version:		%{perfsonar_auto_version}
Release:		%{perfsonar_auto_relnum}%{?dist}
Summary:		Install and configure Opensearch Dashboards
License:		ASL 2.0
Group:			Development/Libraries
URL:			http://www.perfsonar.net
Source0:		perfsonar-dashboards-%{version}.tar.gz
BuildRoot:		%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:		noarch
Requires:       opensearch-dashboards >= 2.1.0
Requires:       httpd
Requires:       mod_ssl

%description
A package that installs and configure Opensearch Dashboards.

%pre
/usr/sbin/groupadd -r perfsonar 2> /dev/null || :
/usr/sbin/useradd -g perfsonar -r -s /sbin/nologin -c "perfSONAR User" -d /tmp perfsonar 2> /dev/null || :

%prep
%setup -q -n perfsonar-dashboards-%{version}

%build

%install
make DASHBOARDS-ROOTPATH=%{buildroot}/%{dashboards_base} HTTPD-CONFIGPATH=%{buildroot}/%{httpd_config_base} install

%clean
rm -rf %{buildroot}

%post
#Restart/enable opensearch-dashboards
%systemd_post opensearch-dashboards.service
if [ "$1" = "1" ]; then
    #if new install, then enable
    systemctl daemon-reload
    systemctl enable opensearch-dashboards.service
    #run opensearch dashboards pre startup script
    bash %{scripts_base}/dashboards_secure_pre.sh
    #start opensearch dashboards
    systemctl start opensearch-dashboards.service
    #run opensearch dashboards post startup script
    bash %{scripts_base}/dashboards_secure_pos.sh
    #Enable and restart apache for reverse proxy
    systemctl enable httpd
    systemctl restart httpd
elif [ $1 == 2 ];then
    #if rpm is getting upgraded, (re)start opensearch-dashboards
    systemctl restart opensearch-dashboards.service
fi

%preun
%systemd_preun opensearch-dashboards.service

%postun
%systemd_postun_with_restart opensearch-dashboards.service

%files
%defattr(0644,perfsonar,perfsonar,0755)
%license LICENSE
%attr(0755, perfsonar, perfsonar) %{scripts_base}/*
%attr(0644, perfsonar, perfsonar) %{httpd_config_base}/apache-opensearchdash.conf

%changelog
* Tue Feb 15 2022 luan.rios@rnp.br 5.0.0-0.0.a1
- Initial spec file created

%define install_base        /usr/lib/perfsonar
%define archive_base        %{install_base}/archive
%define scripts_base        %{archive_base}/perfsonar-scripts
%define setup_base          %{archive_base}/config
%define httpd_config_base   /etc/httpd/conf.d
%define systemd_config_base /etc/systemd/system

#Version variables set by automated scripts
%define perfsonar_auto_version 5.1.0
%define perfsonar_auto_relnum 0.a1.0

# defining macros needed by SELinux
# SELinux policy type - Targeted policy is the default SELinux policy used in Red Hat Enterprise Linux.
%global selinuxtype targeted
# default boolean value needs to be changed to enable http proxy for opensearch and logstash
%global selinuxbooleans httpd_can_network_connect=1

Name:			perfsonar-archive
Version:		%{perfsonar_auto_version}
Release:		%{perfsonar_auto_relnum}%{?dist}
Summary:		perfSONAR Measurement Archive
License:		ASL 2.0
Group:			Development/Libraries
URL:			http://www.perfsonar.net
Source0:		perfsonar-archive-%{version}.tar.gz
BuildRoot:		%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:		noarch
Requires:		opensearch >= 2.1.0
Requires:       openssl
Requires:       jq
Requires:       perfsonar-common
Requires:       perfsonar-logstash
Requires:       perfsonar-elmond
Requires:       httpd
Requires:       mod_ssl
Requires:       curl
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
BuildRequires:  selinux-policy-devel
BuildRequires:  git
%{?selinux_requires}

%description
A package that installs the perfSONAR Archive based on Logstash and Opensearch.

%prep
%setup -q -n perfsonar-archive-%{version}

%build

%install
make PERFSONAR-ROOTPATH=%{buildroot}/%{archive_base} HTTPD-CONFIGPATH=%{buildroot}/%{httpd_config_base} SYSTEMD-CONFIGPATH=%{buildroot}/%{systemd_config_base} install

%clean
rm -rf %{buildroot}

%post
export JAVA_HOME=/usr/share/opensearch/jdk

#Restart/enable opensearch and logstash
%systemd_post opensearch.service
%systemd_post logstash.service
if [ "$1" = "1" ]; then
    #####
    # 5.0 upgrade - clean out esmond. Don't obsolete so people can still get at data
    (systemctl stop --quiet cassandra &> /dev/null) || :
    (systemctl disable --quiet cassandra &> /dev/null) || :
    rm -f /etc/httpd/conf.d/apache-esmond.conf
    ######
    #if new install, then enable
    systemctl daemon-reload
    systemctl enable opensearch.service
    systemctl enable logstash.service
    #fix directory permissions
    chmod g+ws /etc/opensearch/
    chown -R root:opensearch /etc/opensearch/
    #run opensearch pre startup script
    bash %{scripts_base}/pselastic_secure_pre.sh
    #start opensearch
    systemctl start opensearch.service
    #restart logstash
    systemctl restart logstash.service
    #run elmond configuration script
    bash %{scripts_base}/elmond_configuration.sh
    usermod -a -G opensearch perfsonar
    #restart elmond
    systemctl restart elmond.service
    #Enable and restart apache for reverse proxy
    systemctl enable httpd
    systemctl restart httpd
    #set SELinux booleans to allow httpd proxy to work
    %selinux_set_booleans -s %{selinuxtype} %{selinuxbooleans}
else
    #reload daemons to make sure systemd override applies
    systemctl daemon-reload
fi
#run opensearch post startup script
bash %{scripts_base}/pselastic_secure_pos.sh

%preun
%systemd_preun opensearch.service

%postun
%systemd_postun_with_restart opensearch.service
if [ $1 -eq 0 ]; then
    %selinux_unset_booleans -s %{selinuxtype} %{selinuxbooleans}
fi

%files
%defattr(0644,perfsonar,perfsonar,0755)
%license LICENSE
%attr(0755, perfsonar, perfsonar) %{scripts_base}/*
%{setup_base}/ilm/*
%{setup_base}/roles/*
%{setup_base}/users/*
%{setup_base}/index_template-prometheus.json
%{setup_base}/index_template-pscheduler.json
%{setup_base}/index_template-auditlog.json
%{setup_base}/index_template-opendistro-ism.json
%attr(0644, perfsonar, perfsonar) %{httpd_config_base}/apache-opensearch.conf
#set to config so users can modify settings if they need to
%config(noreplace) %attr(0644, perfsonar, perfsonar) %{systemd_config_base}/opensearch.service.d/override.conf
%config(noreplace) %attr(0644, perfsonar, perfsonar) %{systemd_config_base}/logstash.service.d/override.conf
# Set to config so users can update auth settings
%config(noreplace) %attr(0644, perfsonar, perfsonar) %{httpd_config_base}/apache-logstash.conf

%changelog
* Tue Feb 15 2022 luan.rios@rnp.br 5.0.0-0.0.a1
- Update to use with opensearch

* Thu Sep 09 2021 daniel.neto@rnp.br 4.4.0-0.0.a1
- Adding script to configure elmond

* Sun Mar 21 2021 andy@es.net 4.4.0-0.0.a1
- Initial spec file created

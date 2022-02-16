FROM centos:7
ENV container docker

#cleanup to enable systemd
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == \
    systemd-tmpfiles-setup.service ] || rm -f $i; done); \
    rm -f /lib/systemd/system/multi-user.target.wants/*;\
    rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*;

#copy opendistroelastic yum repo
COPY ./docker/centos7/opendistro.repo /etc/yum.repos.d/opendistro.repo

#copy elastic yum repo
COPY ./docker/centos7/elastic.repo /etc/yum.repos.d/elastic.repo

##add perfSONAR nightly repo for perfsonar-logstash dependency
#RUN rpm -hUv http://software.internet2.edu/rpms/el7/x86_64/latest/packages/perfSONAR-repo-nightly-minor-0.10-1.noarch.rpm

#Install build environment dependencies
RUN yum update -y && \
    yum install -y epel-release make rpmbuild rpmdevtools git && \
    yum clean all && \
    mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} && \
    echo 'test' && \
    echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

# Copy code to /app
COPY . /app

#Build RPM
RUN cd /app && \
    make dist && \
    # elasticsearch and logstash
    mv perfsonar-archive-*.tar.gz ~/rpmbuild/SOURCES/ && \
    rpmbuild -bs perfsonar-archive.spec && \
    rpmbuild -ba perfsonar-archive.spec && \ 
    # dashboards
    mv perfsonar-dashboards-*.tar.gz ~/rpmbuild/SOURCES/ && \
    rpmbuild -bs perfsonar-dashboards.spec && \
    rpmbuild -ba perfsonar-dashboards.spec
    # install both
    #yum install -y ~/rpmbuild/RPMS/noarch/*.rpm

#This is elasticsearch docker specific stuff that is only needed here
#RUN mkdir -p /var/lib/perfsonar/archive/tmp && \
#    echo "" >> /etc/elasticsearch/jvm.options && \
#    echo "-Djava.io.tmpdir=/var/lib/perfsonar/archive/tmp" >> /etc/elasticsearch/jvm.options && \
#    chown -R elasticsearch:elasticsearch /var/lib/perfsonar/archive

#This is logstash docker specific stuff that is only needed here
#RUN mkdir -p /var/lib/perfsonar/logstash/tmp && \
#    echo "" >> /etc/logstash/jvm.options && \
#    echo "-Djava.io.tmpdir=/var/lib/perfsonar/logstash/tmp" >> /etc/logstash/jvm.options && \
#    chown -R logstash:logstash /var/lib/perfsonar/logstash

#shared volumes
VOLUME /sys/fs/cgroup

#Keep container running
#CMD tail -f /dev/null
CMD ["/usr/sbin/init"]

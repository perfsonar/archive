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

#Install build environment dependencies
RUN yum update -y && \
    yum install -y epel-release make rpmbuild rpmdevtools git && \
    yum clean all && \
    mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} && \
    echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

# Copy code to /app
COPY . /app

#Build RPM
RUN cd /app && \
    #make dist && \
    # opensearch and logstash
    mv perfsonar-archive-*.tar.gz ~/rpmbuild/SOURCES/ && \
    rpmbuild -bs perfsonar-archive.spec && \
    rpmbuild -ba perfsonar-archive.spec && \ 
    # dashboards
    mv perfsonar-dashboards-*.tar.gz ~/rpmbuild/SOURCES/ && \
    rpmbuild -bs perfsonar-dashboards.spec && \
    rpmbuild -ba perfsonar-dashboards.spec

#shared volumes
VOLUME /sys/fs/cgroup

#Keep container running
CMD ["/usr/sbin/init"]

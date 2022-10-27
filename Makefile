# Makefile for perfSONAR Archive
#
PERFSONAR-PACKAGE=perfsonar-archive
DASHBOARDS-PACKAGE=perfsonar-dashboards
PERFSONAR-ROOTPATH=/usr/lib/perfsonar/archive
DASHBOARDS-ROOTPATH=/usr/lib/perfsonar/dashboards
HTTPD-CONFIGPATH=/etc/httpd/conf.d
PERFSONAR_AUTO_VERSION=5.0.0
PERFSONAR_AUTO_RELNUM=0.b2.1
VERSION=${PERFSONAR_AUTO_VERSION}
RELEASE=${PERFSONAR_AUTO_RELNUM}
DC_CMD_BASE=docker-compose
DC_CMD=${DC_CMD_BASE} -p ${PERFSONAR-PACKAGE}

centos7:
	mkdir -p ./artifacts/centos7
	${DC_CMD} -f docker-compose.qa.yml up --build --no-start centos7
	docker cp ${PERFSONAR-PACKAGE}_centos7_1:/root/rpmbuild/SRPMS ./artifacts/centos7/srpms
	docker cp ${PERFSONAR-PACKAGE}_centos7_1:/root/rpmbuild/RPMS/noarch ./artifacts/centos7/rpms

dist:
	# opensearch and logstash
	git archive --format=tar --prefix=$(PERFSONAR-PACKAGE)-$(VERSION).$(RELEASE)/ HEAD | gzip >$(PERFSONAR-PACKAGE)-$(VERSION).$(RELEASE).tar.gz
	# dashboards
	git archive --format=tar --prefix=$(DASHBOARDS-PACKAGE)-$(VERSION).$(RELEASE)/ HEAD | gzip >$(DASHBOARDS-PACKAGE)-$(VERSION).$(RELEASE).tar.gz

install_arch:
	# opensearch and logstash
	mkdir -p ${PERFSONAR-ROOTPATH}/perfsonar-scripts
	mkdir -p ${PERFSONAR-ROOTPATH}/config
	mkdir -p ${HTTPD-CONFIGPATH}
	cp -r opensearch-scripts/* ${PERFSONAR-ROOTPATH}/perfsonar-scripts
	cp -r config/* ${PERFSONAR-ROOTPATH}/config
	mv ${PERFSONAR-ROOTPATH}/config/apache/archive/* ${HTTPD-CONFIGPATH}/
	rm -rf ${PERFSONAR-ROOTPATH}/config/apache

install_dash:
	# dashboards
	mkdir -p ${DASHBOARDS-ROOTPATH}/dashboards-scripts
	mkdir -p ${HTTPD-CONFIGPATH}
	cp -r dashboards-scripts/* ${DASHBOARDS-ROOTPATH}/dashboards-scripts/
	cp -r config/apache/dashboards/* ${HTTPD-CONFIGPATH}/

# Some of the jobs require the containers to be down. Detects if we have 
# already generated a docker-compose.yml and stops containers accordingly
# Uses ${DC_CMD} and ${DC_CMD_BASE} to cleanup both default and non-default images
dc_clean:
	${DC_CMD} -f docker-compose.qa.yml down -v
	${DC_CMD_BASE} -f docker-compose.qa.yml down -v

clean:
	rm -rf artifacts/

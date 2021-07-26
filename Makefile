# Makefile for perfSONAR Archive
#
PACKAGE=perfsonar-archive
ROOTPATH=/usr/lib/perfsonar/archive
CONFIGPATH=/etc/perfsonar/archive
PERFSONAR_AUTO_VERSION=4.4.0
PERFSONAR_AUTO_RELNUM=0.0.a1
VERSION=${PERFSONAR_AUTO_VERSION}
RELEASE=${PERFSONAR_AUTO_RELNUM}
DC_CMD_BASE=docker-compose
DC_CMD=${DC_CMD_BASE} -p ${PACKAGE}

centos7:
	mkdir -p ./artifacts/centos7
	${DC_CMD} -f docker-compose.qa.yml up --build --no-start centos7
	docker cp ${PACKAGE}_centos7_1:/root/rpmbuild/SRPMS ./artifacts/centos7/srpms
	docker cp ${PACKAGE}_centos7_1:/root/rpmbuild/RPMS/noarch ./artifacts/centos7/rpms

dist:
	git archive --format=tar --prefix=$(PACKAGE)-$(VERSION).$(RELEASE)/ HEAD | gzip >$(PACKAGE)-$(VERSION).$(RELEASE).tar.gz

install:
	mkdir -p ${ROOTPATH}/perfsonar-scripts
	mkdir -p ${ROOTPATH}/pselastic_setup
	mkdir -p ${CONFIGPATH}
	cp -r perfsonar-scripts/* ${ROOTPATH}/perfsonar-scripts/
	cp -r pselastic_setup/* ${ROOTPATH}/pselastic_setup

# Some of the jobs require the containers to be down. Detects if we have 
# already generated a docker-compose.yml and stops containers accordingly
# Uses ${DC_CMD} and ${DC_CMD_BASE} to cleanup both default and non-default images
dc_clean:
	${DC_CMD} -f docker-compose.yml -f docker-compose.qa.yml down -v
	${DC_CMD_BASE} -f docker-compose.yml -f docker-compose.qa.yml down -v

clean:
	rm -rf artifacts/

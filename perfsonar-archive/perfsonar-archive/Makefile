# Makefile for perfSONAR Archive
#
default:
	@true

install:
ifndef PERFSONAR-ROOTPATH
	@echo No PERFSONAR-ROOTPATH specified for installation
	@false
endif
ifndef HTTPD-CONFIGPATH
	@echo No HTTPD-CONFIGPATH specified for installation
	@false
endif
ifndef SYSTEMD-CONFIGPATH
	@echo No SYSTEMD-CONFIGPATH specified for installation
	@false
endif
	# opensearch and logstash
	mkdir -p ${PERFSONAR-ROOTPATH}/perfsonar-scripts
	mkdir -p ${PERFSONAR-ROOTPATH}/config
	mkdir -p ${HTTPD-CONFIGPATH}
	mkdir -p ${SYSTEMD-CONFIGPATH}
	cp -r opensearch-scripts/* ${PERFSONAR-ROOTPATH}/perfsonar-scripts
	cp -r config/systemd/* ${SYSTEMD-CONFIGPATH}/
	cp -r config/* ${PERFSONAR-ROOTPATH}/config
	rm -rf ${PERFSONAR-ROOTPATH}/config/systemd
	mv ${PERFSONAR-ROOTPATH}/config/apache/* ${HTTPD-CONFIGPATH}/
	rm -rf ${PERFSONAR-ROOTPATH}/config/apache

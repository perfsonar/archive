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
ifndef BINPATH
	@echo No BINPATH specified for installation
	@false
endif
ifndef LOGSTASH-ROOTPATH
	@echo No LOGSTASH-ROOTPATH specified for installation
	@false
endif
	# opensearch and logstash
	mkdir -p ${PERFSONAR-ROOTPATH}/perfsonar-scripts
	mkdir -p ${PERFSONAR-ROOTPATH}/bin/commands
	mkdir -p ${PERFSONAR-ROOTPATH}/config
	mkdir -p ${HTTPD-CONFIGPATH}
	mkdir -p ${LOGSTASH-ROOTPATH}/prometheus_pipeline/
	mkdir -p ${SYSTEMD-CONFIGPATH}
	mkdir -p ${BINPATH}
	install -m 0755 bin/psarchive ${PERFSONAR-ROOTPATH}/bin
	install -m 0755 bin/commands/* ${PERFSONAR-ROOTPATH}/bin/commands
	ln -fs  /usr/lib/perfsonar/archive/bin/psarchive ${BINPATH}/psarchive
	cp -r opensearch-scripts/* ${PERFSONAR-ROOTPATH}/perfsonar-scripts
	cp -r config/systemd/* ${SYSTEMD-CONFIGPATH}/
	cp -r config/* ${PERFSONAR-ROOTPATH}/config
	rm -rf ${PERFSONAR-ROOTPATH}/config/systemd
	mv ${PERFSONAR-ROOTPATH}/config/apache/* ${HTTPD-CONFIGPATH}/
	rm -rf ${PERFSONAR-ROOTPATH}/config/apache
	mv ${PERFSONAR-ROOTPATH}/config/01-input-local_prometheus.conf ${LOGSTASH-ROOTPATH}/prometheus_pipeline/
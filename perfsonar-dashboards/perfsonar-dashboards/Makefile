# Makefile for perfSONAR Dashboards
#

default:
	@true

install:
ifndef DASHBOARDS-ROOTPATH
	@echo No DASHBOARDS-ROOTPATH specified for installation
	@false
endif
ifndef HTTPD-CONFIGPATH
	@echo No HTTPD-CONFIGPATH specified for installation
	@false
endif
	# dashboards
	mkdir -p ${DASHBOARDS-ROOTPATH}/dashboards-scripts
	mkdir -p ${HTTPD-CONFIGPATH}
	cp -r dashboards-scripts/* ${DASHBOARDS-ROOTPATH}/dashboards-scripts/
	cp -r config/* ${HTTPD-CONFIGPATH}/

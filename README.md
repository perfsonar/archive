# archive

**UNDER CONSTRUCTION - DO NOT USE**

The perfSONAR Measurement Archive based on Elasticsearch

## RPMS for centos7
```
#Build rpm and test install in a container
make centos7

##verify RPM install
###enter into test container
docker-compose -f docker-compose.qa.yml up -d centos7
docker-compose -f docker-compose.qa.yml exec centos7 bash

###install RPM packages
yum install -y /root/rpmbuild/RPMS/noarch/perfsonar-archive*.rpm
yum install -y /root/rpmbuild/RPMS/noarch/kibana-archive*.rpm

###verify services
systemctl status kibana
systemctl status logstash
systemctl status elasticsearch

tail -f /var/log/elasticsearch/elasticsearch.log
tail -f /var/log/logstash/logstash-plain.log

##stop container
docker-compose -f docker-compose.qa.yml down -v 

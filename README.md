# archive

**UNDER CONSTRUCTION - DO NOT USE**

The perfSONAR Measurement Archive based on Elasticsearch
Proxy authentication credentials are stored in /etc/perfsonar/logstash/proxy_auth.json. To add them to perfsonar tasks, just append the line to the "_headers" json array in the archiver specification and set the destination to host/logstash.

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
systemctl status opensearch

tail -f /var/log/opensearch/opensearch.log
tail -f /var/log/logstash/logstash-plain.log

##stop container
docker-compose -f docker-compose.qa.yml down -v 



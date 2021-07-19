# archive

**UNDER CONSTRUCTION - DO NOT USE**

The perfSONAR Measurement Archive based on Elasticsearch

## RPMS for centos7
```
#Build rpm and test install in a container
make centos7

##verify RPM install
docker-compose -f docker-compose.qa.yml up -d centos7
docker-compose -f docker-compose.qa.yml exec centos7 bash

systemctl status kibana
systemctl status logstash
systemctl status elasticsearch

tail -f /var/log/elasticsearch/elasticsearch.log
tail -f /var/log/logstash/logstash-plain.log

##stop container
docker-compose -f docker-compose.qa.yml down -v 

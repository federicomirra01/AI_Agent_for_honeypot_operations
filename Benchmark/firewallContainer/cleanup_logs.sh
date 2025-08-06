#!/bin/bash
docker exec suricata /bin/bash -c "> /var/log/suricata/eve.json"
docker exec suricata /bin/bash -c "> /var/log/suricata/stats.log"
docker exec suricata /bin/bash -c "> /var/log/suricata/fast.log"
docker exec suricata /bin/bash -c "> /var/log/suricata/suricata.log"

docker exec firewall_router /bin/bash -c "> /suricata/logs/eve.json"
docker exec firewall_router /bin/bash -c "> /suricata/logs/fast.log"

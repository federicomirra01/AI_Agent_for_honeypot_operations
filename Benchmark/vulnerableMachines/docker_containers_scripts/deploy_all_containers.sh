#! /bin/bash
# cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableMachines/cves && docker compose up -d 
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableMachines/multi_step_machine/docker/unauthorized-rce/scripts &&  ./deploy_containers.sh
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableMachines/multi_step_machine/struts2/s2-057/scripts && ./deploy_containers.sh
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableMachines/single_step_machine/gitlab/CVE-2021-22205/scripts && ./deploy_containers.sh

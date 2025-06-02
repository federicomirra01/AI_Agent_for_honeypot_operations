#! /bin/bash
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableContainers/cves/cve-2018-12613 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableContainers/multi_step_machine/docker/unauthorized-rce && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableContainers/multi_step_machine/struts2/s2-057 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/vulnerableContainers/single_step_machine/gitlab/CVE-2021-22205 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/firewallContainer && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_honeypot_operations/Benchmark/attackerContainer && docker compose down -v

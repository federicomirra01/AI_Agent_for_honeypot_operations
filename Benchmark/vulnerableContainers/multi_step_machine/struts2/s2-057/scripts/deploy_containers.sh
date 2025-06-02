#! /bin/bash
docker compose up -d
# Insert second stage flag into container
docker exec -u 0 s2-057-struts2-1 sh -c 'echo "flag{second_stage_completed}" > /root/root.txt'

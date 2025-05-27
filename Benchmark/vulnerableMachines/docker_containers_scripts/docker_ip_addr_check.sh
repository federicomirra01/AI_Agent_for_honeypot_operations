#! /bin/bash
docker ps -q | xargs -n1 docker inspect --format='{{.Name}} - IP: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} - Ports: {{range $p, $conf := .NetworkSettings.Ports}}{{$p}}{{if $conf}} => {{range $conf}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}{{end}}'


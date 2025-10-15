#!/usr/bin/env bash
set -euo pipefail

# Desired mapping: IP -> target ifname (<=15 chars)
declare -A MAP=(
  ["172.20.0.254"]="eth0"    # thesis_net -> eth0  (your requirement)
  ["192.168.100.254"]="eth1" # attacker_net -> eth1
  ["192.168.200.2"]="eth2"   # agent_net -> eth2
)

find_tmp_if() {
  local i=0
  while ip link show "t${i}" >/dev/null 2>&1; do i=$((i+1)); done
  echo "t${i}"
}

rename_if() {
  local cur="$1" tgt="$2"
  [[ "$cur" == "$tgt" ]] && return 0
  if ip link show "$tgt" >/dev/null 2>&1; then
    local tmp; tmp=$(find_tmp_if)
    ip link set dev "$tgt" down || true
    ip link set dev "$tgt" name "$tmp"
  fi
  ip link set dev "$cur" down
  ip link set dev "$cur" name "$tgt"
  ip link set dev "$tgt" up
}

# Helper: find interface that owns a given bare IPv4 (no /mask)
iface_for_ip() {
  local needle="$1"
  ip -4 -o addr show \
  | awk -v ip="$needle" '$3=="inet"{ split($4,a,"/"); if(a[1]==ip){ print $2; exit 0 } }'
}

# Wait until at least one of the target IPs shows up
for _ in $(seq 1 30); do
  present=0
  for ipaddr in "${!MAP[@]}"; do
    if [[ -n "$(iface_for_ip "$ipaddr")" ]]; then present=$((present+1)); fi
  done
  (( present > 0 )) && break
  sleep 1
done

# Rename each interface to the desired name
for ipaddr in "${!MAP[@]}"; do
  desired="${MAP[$ipaddr]}"
  cur_if="$(iface_for_ip "$ipaddr" || true)"
  if [[ -z "$cur_if" ]]; then
    echo "IP $ipaddr not present yet; skipping"
    continue
  fi
  rename_if "$cur_if" "$desired"
done

echo "Interface map after renaming:"
ip -4 -o addr show

exec "$@"

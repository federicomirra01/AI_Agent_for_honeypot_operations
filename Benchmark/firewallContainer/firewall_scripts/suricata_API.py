import json
import threading
import time
from collections import deque, defaultdict
from flask import Flask, request, jsonify
from datetime import datetime
import os
import logging
from datetime import datetime, timedelta, timezone
import re

# Path to Suricata's eve.json
EVE_JSON_PATH = '/suricata/logs/eve.json'
FAST_LOG_PATH = '/suricata/logs/fast.log'

MAX_EVENTS = 10000  # in-memory buffer per event type

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/firewall/logs/suricata_API.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Separate buffers for different event types based on suricata.yaml config
event_buffers = {
    'alert': deque(maxlen=MAX_EVENTS)
}
buffer_lock = threading.Lock()

seen_alerts_ids = set()
def tail_eve_json():
    """Thread to tail eve.json and store events by type."""
    logger.info("Starting to tail Suricata's eve.json for all event types")
    with open(EVE_JSON_PATH, 'r') as f:
        # Seek to the end of the file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                data = json.loads(line)
                event_type = data.get('event_type')
                fid = data.get('flow_id')
                sigid=data.get('alert', {}).get('signature_id')
                key = (fid, sigid, data.get('timestamp'))

                with buffer_lock:
                    if key in seen_alerts_ids:
                        continue
                    seen_alerts_ids.add(key)
                    event_buffers[event_type].append(data)
                    if len(seen_alerts_ids) > MAX_EVENTS * 2:
                        seen_alerts_ids.clear()

            except json.JSONDecodeError:
                continue

def compress_alert(alert, max_payload_len=200):
    """Return trimmed alert object suitable for AI analysis."""
    alert_info = alert.get('alert', {})
    return {
        'timestamp': alert.get('timestamp'),
        'src_ip': alert.get('src_ip'),
        'src_port': alert.get('src_port'),
        'dest_ip': alert.get('dest_ip'),
        'dest_port': alert.get('dest_port'),
        'proto': alert.get('proto'),
        'signature': alert_info.get('signature'),
        'category': alert_info.get('category'),
        'severity': alert_info.get('severity'),
        'payload': alert.get('payload_printable', '')[:max_payload_len] if alert.get('payload_printable') else None,
        'flow_id': alert.get('flow_id'),
        #'community_id': alert.get('community_id'),
        #'metadata': alert.get('metadata')
    }


fast_log_line_re = re.compile(r'^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$')

def parse_fast_log_line(line):
    """Parse a line from fast.log and convert timestamp using system local time."""
    match = fast_log_line_re.match(line)
    if not match:
        return None

    timestamp_str, message = match.groups()

    try:
        # Parse the timestamp using the format in fast.log
        dt = datetime.strptime(timestamp_str, "%m/%d/%Y-%H:%M:%S.%f")

        # Localize to system time zone (e.g., Europe/Rome)
        local_tz = datetime.now().astimezone().tzinfo
        dt = dt.replace(tzinfo=local_tz)

        return {"timestamp": dt.isoformat(), "message": message}
    except Exception as e:
        logger.warning(f"Failed to parse fast.log timestamp: {e}")
        return None

def read_fast_log(time_window_minutes=10):
    """Read fast.log and return alerts within the time window."""
    results = []
    now = datetime.now().astimezone()
    time_threshold = now - timedelta(minutes=time_window_minutes)

    if not os.path.exists(FAST_LOG_PATH):
        logger.warning("fast.log not found at %s", FAST_LOG_PATH)
        return []

    try:
        with open(FAST_LOG_PATH, 'r') as f:
            for line in f:
                parsed = parse_fast_log_line(line.strip())
                if parsed:
                    try:
                        event_time = parse_timestamp(parsed['timestamp'])
                        if event_time >= time_threshold:
                            results.append(parsed)
                    except ValueError as ve:
                        logger.debug(f"Skipping line due to timestamp error: {ve}")
    except Exception as e:
        logger.error(f"Error reading fast.log: {e}")

    return results

logger = logging.getLogger(__name__)

def parse_timestamp(timestamp_str):
    # If ends with 'Z', treat as UTC
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1] + '+00:00'
    else:
        # Normalize +0000 or +0100 to +00:00 or +01:00
        match = re.match(r"(.*)([+-]\d{2})(\d{2})$", timestamp_str)
        if match:
            base, hour, minute = match.groups()
            timestamp_str = f"{base}{hour}:{minute}"
    dt = datetime.fromisoformat(timestamp_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def filter_events_by_time(events, time_window_minutes):
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=time_window_minutes)
    filtered = []
    for e in events:
        try:
            event_time = parse_timestamp(e['timestamp'])
            if event_time >= cutoff:
                filtered.append(e)
        except (ValueError, KeyError):
            continue
    return filtered


@app.route("/alerts", methods=["GET"])
def get_alerts():
    """Get recent alerts - useful for AI correlation analysis."""
    time_window = int(request.args.get("time_window", 10))  # minutes

    with buffer_lock:
        alerts = list(event_buffers.get('alert', []))
        if time_window > 0:
            alerts = filter_events_by_time(alerts, time_window)

        compressed_alerts = [compress_alert(alert, 500) for alert in alerts]
    return jsonify({
        "total_events": len(compressed_alerts),
        "time_window_minutes": time_window,
        "events_by_type": compressed_alerts,
        "timestamp": datetime.now().isoformat() + "Z"
    })

@app.route("/health", methods=["GET"])
def health_check():
    """Health check with buffer status for all event types."""
    buffer_status = {}
    total_events = 0

    with buffer_lock:
        for event_type, buffer in event_buffers.items():
            count = len(buffer)
            buffer_status[event_type] = count
            total_events += count

    return jsonify({
        "status": "ok",
        "total_events": total_events,
        "buffer_status": buffer_status,
        "timestamp": datetime.now().isoformat() + "Z"
    })

@app.route("/fastlog", methods=["GET"])
def get_fast_log():
    """Return parsed alerts from fast.log filtered by optional time_window."""
    time_window = int(request.args.get("time_window", 10))  # minutes
    entries = read_fast_log(time_window)
    return jsonify({
        "count": len(entries),
        "time_window_minutes": time_window,
        "alerts": entries,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get statistics about collected events - useful for AI monitoring."""
    time_window = int(request.args.get("time_window", 10))  # minutes

    stats = {}
    with buffer_lock:
        for event_type, buffer in event_buffers.items():
            events = list(buffer)
            if time_window > 0:
                events = filter_events_by_time(events, time_window)

            # Basic statistics
            stats[event_type] = {
                "total_count": len(events),
                "unique_src_ips": len(set(e.get('src_ip', '') for e in events if e.get('src_ip'))),
                "unique_dest_ips": len(set(e.get('dest_ip', '') for e in events if e.get('dest_ip'))),
                "protocols": list(set(e.get('proto', '') for e in events if e.get('proto')))
            }

            # Event-specific stats
            if event_type == 'alert':
                severities = [e.get('alert', {}).get('severity', 0) for e in events if e.get('alert')]
                stats[event_type]["avg_severity"] = sum(severities) / len(severities) if severities else 0
                stats[event_type]["max_severity"] = max(severities) if severities else 0

            elif event_type == 'http':
                methods = [e.get('http', {}).get('http_method', '') for e in events if e.get('http')]
                stats[event_type]["http_methods"] = list(set(methods))

    return jsonify({
        "time_window_minutes": time_window,
        "statistics": stats,
        "timestamp": datetime.now().isoformat() + "Z"
    })

if __name__ == "__main__":
    # Start the eve.json tailing thread
    threading.Thread(target=tail_eve_json, daemon=True).start()
    logger.info("Started Suricata EVE JSON parser for AI agent integration")
    app.run(host="0.0.0.0", port=7000, debug=False)

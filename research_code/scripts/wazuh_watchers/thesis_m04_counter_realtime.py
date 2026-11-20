#!/usr/bin/env python3

import json
import os
import ssl
import time
import base64
import urllib.request
from datetime import datetime, timezone

CONFIG_FILE = "/etc/thesis-m04/indexer.json"
STATE_FILE = "/var/lib/thesis-m04/realtime_state.json"
OUTPUT_FILE = "/var/ossec/logs/thesis_m04_detections.json"

THRESHOLD = 4
WINDOW_SECONDS = 300


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    temp = STATE_FILE + ".tmp"
    with open(temp, "w") as f:
        json.dump(state, f)
    os.replace(temp, STATE_FILE)


def query_indexer():
    config = load_json(CONFIG_FILE, {})
    now = int(time.time())

    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {
                        "agent.name": "LAB-SERVER"
                    }},
                    {"term": {
                        "data.win.system.eventID": "4663"
                    }},
                    {"term": {
                        "data.win.eventdata.accessMask": "0x10000"
                    }},
                    {"regexp": {
                        "data.win.eventdata.objectName": {
                            "value": r"C:.*UniversityData.*\\..+",
                            "case_insensitive": True
                        }
                    }},
                    {"range": {
                        "@timestamp": {
                            "gte": now - WINDOW_SECONDS,
                            "lt": now,
                            "format": "epoch_second"
                        }
                    }}
                ]
            }
        },
        "aggs": {
            "users": {
                "terms": {
                    "field": "data.win.eventdata.subjectUserName",
                    "size": 100
                },
                "aggs": {
                    "unique_files": {
                        "cardinality": {
                            "field": "data.win.eventdata.objectName",
                            "precision_threshold": 3000
                        }
                    }
                }
            }
        }
    }

    credentials = (
        config["username"] + ":" + config["password"]
    ).encode()

    token = base64.b64encode(credentials).decode()

    request = urllib.request.Request(
        config["url"] + "/wazuh-archives-*/_search",
        data=json.dumps(query).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + token
        },
        method="POST"
    )

    context = ssl.create_default_context(
        cafile=config["ca_cert"]
    )

    with urllib.request.urlopen(
        request, context=context, timeout=30
    ) as response:
        return json.load(response)


def main():
    result = query_indexer()
    now = int(time.time())

    # Users already above the threshold on the previous run
    state = load_json(STATE_FILE, {"active_users": []})
    previously_active = set(state.get("active_users", []))

    current_active = set()
    new_detections = 0

    for user in result["aggregations"]["users"]["buckets"]:
        username = str(user["key"]).strip().lower()
        count = int(user["unique_files"]["value"])

        if count <= THRESHOLD:
            continue

        current_active.add(username)

        # Avoid sending another alert while the user
        # remains above the threshold
        if username in previously_active:
            continue

        timestamp = datetime.fromtimestamp(
            now, timezone.utc
        ).isoformat()

        event = {
            "m04": {
                "scenario": "M04",
                "username": username,
                "unique_files": str(count),
                "window_minutes": "5",
                "window_start": datetime.fromtimestamp(
                    now - WINDOW_SECONDS, timezone.utc
                ).isoformat(),
                "detection_id": f"{username}|{now}",
                "detection_time": timestamp
            }
        }

        with open(OUTPUT_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")

        new_detections += 1

        print(
            f"M04 ALERT: {username}, "
            f"{count} distinct files, {timestamp}"
        )

    # Users automatically become eligible for a new alert
    # after their five-minute rolling count falls to 30 or less
    save_state({
        "active_users": sorted(current_active)
    })

    print(f"Completed. New M04 detections: {new_detections}")


if __name__ == "__main__":
    main()

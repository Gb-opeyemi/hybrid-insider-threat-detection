#!/usr/bin/env python3

import json
import os
import ssl
import time
import base64
import urllib.request
from datetime import datetime, timezone

CONFIG_FILE = "/etc/thesis-m04/indexer.json"
STATE_FILE = "/var/lib/thesis-m04/processed.json"
OUTPUT_FILE = "/var/ossec/logs/thesis_m04_detections.json"

THRESHOLD = 4
WINDOW_SECONDS = 300
INGESTION_DELAY = 120


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)


def save_state(state):
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
                            "value": "C:.*UniversityData.*\\..+",
                            "case_insensitive": True
                        }
                    }},
                    {"range": {
                        "@timestamp": {
                            "gte": now - 1800,
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
                    "windows": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "5m",
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "unique_files": {
                                "cardinality": {
                                    "field": "data.win.eventdata.objectName",
                                    "precision_threshold": 3000
                                }
                            },
                            "m03_detection": {
                                "bucket_selector": {
                                    "buckets_path": {
                                        "fileCount": "unique_files"
                                    },
                                    "script": "params.fileCount >= 5"
                                }
                            }
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
    state = load_json(STATE_FILE, {})
    processed = state.get("processed", {})

    now = int(time.time())
    alerts = 0

    users = result["aggregations"]["users"]["buckets"]

    for user in users:
        username = user["key"]

        for window in user["windows"]["buckets"]:
            start = window["key"] // 1000
            end = start + WINDOW_SECONDS

            # Only evaluate completed windows
            if now < end + INGESTION_DELAY:
                continue

            count = int(window["unique_files"]["value"])

            if count <= THRESHOLD:
                continue

            detection_id = f"{username}|{start}"

            if detection_id in processed:
                continue

            timestamp = datetime.fromtimestamp(
                start, timezone.utc
            ).isoformat()

            event = {
                "m04": {
                    "scenario": "M04",
                    "username": username,
                    "unique_files": str(count),
                    "window_minutes": "5",
                    "window_start": timestamp,
                    "detection_id": detection_id
                }
            }

            with open(OUTPUT_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")

            processed[detection_id] = now
            alerts += 1

            print(
                f"M04 ALERT: {username}, "
                f"{count} distinct files, {timestamp}"
            )

    # Retain deduplication state for 30 days
    cutoff = now - 30 * 86400

    processed = {
        k: v for k, v in processed.items()
        if v >= cutoff
    }

    save_state({"processed": processed})

    print(f"Completed. New M04 detections: {alerts}")


if __name__ == "__main__":
    main()

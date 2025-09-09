#!/usr/bin/env python3
#parses csv output from EvtxECmd and filters

import sys

def filter_events(input_file, output_file, event_ids):
    event_ids = set(event_ids)

    with open(input_file, "r", encoding="utf-8", errors="ignore") as infile, \
         open(output_file, "w", encoding="utf-8") as outfile:

        header = infile.readline()
        outfile.write(header)  # keep header row

        for line in infile:
            # Split only first 5 commas ? EventId is at index 3
            parts = line.split(",", 5)
            if len(parts) > 4:
                event_id = parts[3].strip()
                if event_id in event_ids:
                    outfile.write(line)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python filter_events.py <input.csv> <output.csv> <event_ids>")
        print("Example: python filter_events.py Security.csv filtered.csv 4688,4696,4826")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = sys.argv[2]
    event_ids = sys.argv[3].split(",")

    filter_events(input_csv, output_csv, event_ids)

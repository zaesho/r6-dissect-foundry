"""Diagnose movement data loss by examining raw position distribution."""
import json
import subprocess
import sys
import os

rec = "samplefiles/Match-2026-01-21_18-00-14-3788/Match-2026-01-21_18-00-14-3788-R01.rec"

# We need to look at raw positions before the continuity filter.
# Let's use the existing probeall tool to see raw packet counts per player ID.
print("Running probeall to check raw packet distribution by player ID...")
print()

result = subprocess.run(
    ["go", "run", "./tools/probeall", rec],
    capture_output=True, text=True, cwd=os.getcwd()
)

# Extract the relevant sections
lines = result.stdout.split('\n')
in_section = False
for line in lines:
    if 'Player ID Probe' in line or 'Players:' in line or 'ANALYSIS 1' in line:
        in_section = True
    if in_section:
        print(line)
    if in_section and line.strip() == '' and 'ANALYSIS' not in line:
        pass
    if 'ANALYSIS 2' in line:
        break

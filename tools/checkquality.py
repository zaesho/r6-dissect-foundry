import json
import sys

with open('samplefiles/R01_movement_export.json') as f:
    d = json.load(f)

moves = d.get('movements', [])
for m in moves:
    pos = m['positions']
    username = m['username']
    operator = m.get('operator', '?')
    team = m.get('team', '?')
    print(f"{username} - {operator} - {team}: {len(pos)} positions")

    total_jumps = 0
    big_jumps = 0
    for i in range(1, len(pos)):
        dx = pos[i]['x'] - pos[i-1]['x']
        dy = pos[i]['y'] - pos[i-1]['y']
        dist = (dx*dx + dy*dy)**0.5
        if dist > 3.0:
            total_jumps += 1
        if dist > 10.0:
            big_jumps += 1

    if len(pos) > 1:
        pct = 100 * total_jumps / (len(pos) - 1)
        print(f"  Jumps >3m: {total_jumps}/{len(pos)-1} ({pct:.1f}%)")
        print(f"  Jumps >10m: {big_jumps}/{len(pos)-1}")

    # Show first 20 positions with jump markers
    for i in range(min(20, len(pos))):
        p = pos[i]
        jump = ''
        if i > 0:
            dx = p['x'] - pos[i-1]['x']
            dy = p['y'] - pos[i-1]['y']
            dist = (dx*dx + dy*dy)**0.5
            if dist > 3:
                jump = f' *** JUMP {dist:.1f}m ***'
        t = p['timeInSeconds']
        x = p['x']
        y = p['y']
        z = p['z']
        print(f"    t={t:.1f}  ({x:.2f}, {y:.2f}, {z:.2f}){jump}")
    print()

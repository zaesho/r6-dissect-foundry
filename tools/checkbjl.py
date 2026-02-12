import json

with open('samplefiles/R01_movement_export.json') as f:
    d = json.load(f)

for m in d.get('movements', []):
    if m['username'] == 'BjL-':
        pos = m['positions']
        xs = set()
        ys = set()
        zs = set()
        for p in pos:
            xs.add(round(p['x'], 2))
            ys.add(round(p['y'], 2))
            zs.add(round(p['z'], 2))
        print("BjL-: %d positions" % len(pos))
        print("  Unique X values: %d (range: %.2f to %.2f)" % (len(xs), min(xs), max(xs)))
        print("  Unique Y values: %d (range: %.2f to %.2f)" % (len(ys), min(ys), max(ys)))
        print("  Unique Z values: %d (range: %.2f to %.2f)" % (len(zs), min(zs), max(zs)))
        print()
        print("First 50 positions:")
        for i, p in enumerate(pos[:50]):
            print("  t=%.1f  (%.2f, %.2f, %.2f)" % (p['timeInSeconds'], p['x'], p['y'], p['z']))
        print()
        print("Positions 500-520:")
        for p in pos[500:520]:
            print("  t=%.1f  (%.2f, %.2f, %.2f)" % (p['timeInSeconds'], p['x'], p['y'], p['z']))
        print()
        print("Last 30 positions:")
        for p in pos[-30:]:
            print("  t=%.1f  (%.2f, %.2f, %.2f)" % (p['timeInSeconds'], p['x'], p['y'], p['z']))

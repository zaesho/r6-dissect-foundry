"""Check death times vs track end times, with proper time conversion.
R6 deathTime is in COUNTDOWN seconds (higher = more time left = earlier in round).
Track times are in ELAPSED seconds from start of replay.
Conversion: death_elapsed ~= 45 (prep) + (180 - countdown)
"""
import json

for fname, label in [
    ('samplefiles/R01_movement_export.json', 'Chalet R01'),
    ('samplefiles/R03_match2_export.json', 'Nighthaven R03'),
]:
    d = json.load(open(fname))
    moves = {m['username']: m for m in d.get('movements', [])}
    feedback = d.get('matchFeedback', [])
    
    print("=== %s ===" % label)
    print()
    
    # Get kill/death events (countdown time)
    deaths_countdown = {}
    for ev in feedback:
        t = ev.get('type', {})
        name = t.get('name', '')
        if name == 'Kill':
            victim = ev.get('target', '')
            deaths_countdown[victim] = ev.get('timeInSeconds', 0)
        elif name == 'Death':
            victim = ev.get('username', '')
            deaths_countdown[victim] = ev.get('timeInSeconds', 0)
    
    for username, m in moves.items():
        pos = m['positions']
        if not pos:
            continue
        track_start = pos[0]['timeInSeconds']
        track_end = pos[-1]['timeInSeconds']
        
        if username in deaths_countdown:
            countdown = deaths_countdown[username]
            # Convert countdown to elapsed: ~45 prep + (180 - countdown)
            death_elapsed = 45.0 + (180.0 - countdown)
            diff = track_end - death_elapsed
            
            if abs(diff) <= 10:
                status = "GOOD (died at ~%.0fs elapsed, track ends at %.0fs, diff=%.0fs)" % (death_elapsed, track_end, diff)
            elif diff > 10:
                status = "BAD: track moves %.0fs AFTER death (died ~%.0fs, track ends %.0fs)" % (diff, death_elapsed, track_end)
            else:
                status = "OK: track ends %.0fs BEFORE death (died ~%.0fs, track ends %.0fs)" % (-diff, death_elapsed, track_end)
        else:
            status = "survived (track ends at %.0fs)" % track_end
        
        print("  %-20s %-8s %s" % (username, m.get('team', '?'), status))
    print()

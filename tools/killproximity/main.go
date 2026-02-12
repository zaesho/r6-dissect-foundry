package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: killproximity <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	r.EnableMovementTracking(1)

	if err := r.Read(); err != nil && err.Error() != "EOF" {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	rawPos := r.GetRawPositions()
	if len(rawPos) == 0 {
		fmt.Println("No raw positions!")
		return
	}

	// Find packet range
	minPkt, maxPkt := rawPos[0].PacketNum, rawPos[0].PacketNum
	for _, p := range rawPos {
		if p.PacketNum < minPkt {
			minPkt = p.PacketNum
		}
		if p.PacketNum > maxPkt {
			maxPkt = p.PacketNum
		}
	}
	pktRange := float64(maxPkt - minPkt)

	// Build tracks
	type posTrack struct {
		positions    []dissect.RawPosition
		lastX, lastY float32
	}
	tracks := make([]*posTrack, 0, 12)
	threshold := float32(1.5)

	for _, pos := range rawPos {
		bestTrack := -1
		bestDist := float32(math.MaxFloat32)
		for i, t := range tracks {
			dx := pos.X - t.lastX
			dy := pos.Y - t.lastY
			dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
			if dist < bestDist {
				bestDist = dist
				bestTrack = i
			}
		}
		if bestTrack >= 0 && bestDist <= threshold {
			tracks[bestTrack].positions = append(tracks[bestTrack].positions, pos)
			tracks[bestTrack].lastX = pos.X
			tracks[bestTrack].lastY = pos.Y
		} else {
			tracks = append(tracks, &posTrack{
				positions: []dissect.RawPosition{pos},
				lastX:     pos.X,
				lastY:     pos.Y,
			})
		}
	}

	// Sort by size, take top 10
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})
	if len(tracks) > 10 {
		tracks = tracks[:10]
	}

	// Function to find track position at a given packet number
	getTrackPosAtPkt := func(t *posTrack, targetPkt int) (float32, float32, float32, bool) {
		// Find closest position to target packet
		var bestPos dissect.RawPosition
		bestDiff := math.MaxInt32
		for _, pos := range t.positions {
			diff := abs(pos.PacketNum - targetPkt)
			if diff < bestDiff {
				bestDiff = diff
				bestPos = pos
			}
		}
		if bestDiff < 1000 { // Within reasonable range
			return bestPos.X, bestPos.Y, bestPos.Z, true
		}
		return 0, 0, 0, false
	}

	// Calculate prep phase movement for each track (first 25% of packets - should be prep)
	prepEndPkt := minPkt + int(pktRange*0.25)
	type trackInfo struct {
		idx       int
		prepMove  float32
		positions []dissect.RawPosition
	}
	var trackInfos []trackInfo

	for i, t := range tracks {
		if len(t.positions) < 50 {
			continue
		}
		var prepMove float32
		var lastX, lastY float32
		for j, pos := range t.positions {
			if pos.PacketNum <= prepEndPkt && j > 0 {
				dx := pos.X - lastX
				dy := pos.Y - lastY
				prepMove += float32(math.Sqrt(float64(dx*dx + dy*dy)))
			}
			lastX, lastY = pos.X, pos.Y
		}
		trackInfos = append(trackInfos, trackInfo{i, prepMove, t.positions})
	}

	// Sort by prep movement (high = defender)
	sort.Slice(trackInfos, func(i, j int) bool {
		return trackInfos[i].prepMove > trackInfos[j].prepMove
	})

	fmt.Println("=== TRACK PREP PHASE MOVEMENT ===")
	for i, ti := range trackInfos {
		team := "ATK"
		if i < 5 {
			team = "DEF"
		}
		fmt.Printf("Track %d: PrepMove=%.1f [%s]\n", ti.idx+1, ti.prepMove, team)
	}

	// For each kill event, check if killer and victim tracks are near each other
	fmt.Println("\n=== KILL PROXIMITY ANALYSIS ===")
	fmt.Println("For each kill, showing distance between ALL track pairs at kill time")
	fmt.Println("Killer and victim should be CLOSE (<5 units typically)")
	fmt.Println()

	for _, event := range r.MatchFeedback {
		if event.Type != dissect.Kill || event.Target == "" {
			continue
		}

		// Convert countdown to packet number (approximate)
		// Assuming prep=45s (first 25% of round) + action phase
		// countdown is in action phase, so higher countdown = earlier in action
		// Let's estimate: if countdown=84s remaining out of 180s action, 
		// that's (180-84)/180 = 53% through action phase
		// Action starts at 25% of packets, so kill is at 25% + 53%*75% = ~65% of packets
		actionProgress := (180.0 - event.TimeInSeconds) / 180.0
		killPktRatio := 0.25 + actionProgress*0.75
		killPkt := minPkt + int(pktRange*killPktRatio)

		fmt.Printf("KILL: %s -> %s at %.0fs remaining (pkt ~%d, %.1f%% through round)\n",
			event.Username, event.Target, event.TimeInSeconds, killPkt, killPktRatio*100)

		// Get position of each track at this time
		type trackPos struct {
			trackIdx int
			team     string
			x, y, z  float32
			valid    bool
		}
		var positions []trackPos

		for i, ti := range trackInfos {
			team := "ATK"
			if i < 5 {
				team = "DEF"
			}
			x, y, z, valid := getTrackPosAtPkt(tracks[ti.idx], killPkt)
			positions = append(positions, trackPos{ti.idx, team, x, y, z, valid})
		}

		// Find closest pairs (potential killer-victim pairs)
		fmt.Println("  Closest track pairs at this moment:")
		type pairDist struct {
			t1, t2   int
			team1, team2 string
			dist     float32
		}
		var pairs []pairDist

		for i := 0; i < len(positions); i++ {
			for j := i + 1; j < len(positions); j++ {
				if !positions[i].valid || !positions[j].valid {
					continue
				}
				// Only consider ATK-DEF pairs (kills are between teams)
				if positions[i].team == positions[j].team {
					continue
				}
				dx := positions[i].x - positions[j].x
				dy := positions[i].y - positions[j].y
				dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
				pairs = append(pairs, pairDist{
					positions[i].trackIdx, positions[j].trackIdx,
					positions[i].team, positions[j].team,
					dist,
				})
			}
		}

		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i].dist < pairs[j].dist
		})

		// Show top 5 closest pairs
		for k := 0; k < 5 && k < len(pairs); k++ {
			p := pairs[k]
			fmt.Printf("    Track%d[%s] <-> Track%d[%s]: %.1f units\n",
				p.t1+1, p.team1, p.t2+1, p.team2, p.dist)
		}
		fmt.Println()
	}

	// Show header players for reference
	fmt.Println("=== HEADER PLAYERS ===")
	for i, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			teamRole = string(r.Header.Teams[p.TeamIndex].Role)
		}
		fmt.Printf("  [%d] %s (%s) - %s\n", i, p.Username, teamRole, p.Operator.String())
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

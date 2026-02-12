package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: deathdiag <replay.rec>")
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

	fmt.Println("=== DEATH EVENTS (from matchFeedback) ===")
	// Find min countdown to estimate actual round duration
	var minCountdown float64 = 999
	for _, event := range r.MatchFeedback {
		if event.TimeInSeconds > 0 && event.TimeInSeconds < minCountdown {
			minCountdown = event.TimeInSeconds
		}
	}
	totalTime := 180.0
	if minCountdown < 180 {
		totalTime = 45.0 + (180.0 - minCountdown)
	}
	fmt.Printf("  (Estimated round duration: %.1fs, last event at %.0fs remaining)\n\n", totalTime, minCountdown)
	
	deathTimes := make(map[string]float64)
	for _, event := range r.MatchFeedback {
		if event.Type == dissect.Kill && event.Target != "" {
			elapsed := 45.0 + (180.0 - event.TimeInSeconds)
			deathTimes[event.Target] = elapsed
			fmt.Printf("  %s killed %s at %.1fs elapsed (%.0fs remaining)\n",
				event.Username, event.Target, elapsed, event.TimeInSeconds)
		} else if event.Type == dissect.Death && event.Username != "" {
			elapsed := 45.0 + (180.0 - event.TimeInSeconds)
			deathTimes[event.Username] = elapsed
			fmt.Printf("  %s died at %.1fs elapsed (%.0fs remaining)\n",
				event.Username, elapsed, event.TimeInSeconds)
		}
	}

	// Build tracks manually to analyze
	fmt.Println("\n=== TRACK ANALYSIS ===")
	rawPos := r.GetRawPositions()
	if len(rawPos) == 0 {
		fmt.Println("No raw positions!")
		return
	}

	// Find min/max packet for time normalization
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
	fmt.Printf("  Packet range: %d to %d (total: %.0f packets)\n", minPkt, maxPkt, pktRange)
	pktToTime := func(pkt int) float64 {
		return (float64(pkt-minPkt) / pktRange) * totalTime
	}

	// Build tracks using continuity
	type posTrack struct {
		positions []dissect.RawPosition
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

	// Sort by size
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})

	// Calculate prep phase end packet (first ~40 seconds)
	prepPhaseRatio := 40.0 / totalTime
	prepPhaseEndPkt := minPkt + int(float64(maxPkt-minPkt)*prepPhaseRatio)
	fmt.Printf("  Prep phase ends at packet: %d (%.1f%% of range)\n\n", prepPhaseEndPkt, prepPhaseRatio*100)

	// Analyze top 10 tracks
	fmt.Printf("Top 10 tracks (sorted by position count):\n")
	fmt.Printf("%-8s %-10s %-12s %-12s %-12s\n", "Track", "Positions", "PrepMove", "LastSigMove", "EndTime")
	fmt.Println("----------------------------------------------------------------")

	type trackData struct {
		idx         int
		positions   int
		prepMove    float32
		lastSigMove float64
		endTime     float64
	}
	var trackDatas []trackData

	for i := 0; i < 10 && i < len(tracks); i++ {
		t := tracks[i]
		if len(t.positions) < 50 {
			continue
		}

		endTime := pktToTime(t.positions[len(t.positions)-1].PacketNum)

		// Calculate prep phase movement and last significant move
		var prepMove float32
		var lastX, lastY float32
		var lastSigX, lastSigY, lastSigZ float32
		var lastSigMoveTime float64 = 0

		for j, pos := range t.positions {
			posTime := pktToTime(pos.PacketNum)
			
			// Prep phase movement
			if pos.PacketNum <= prepPhaseEndPkt && j > 0 {
				dx := pos.X - lastX
				dy := pos.Y - lastY
				prepMove += float32(math.Sqrt(float64(dx*dx + dy*dy)))
			}
			lastX, lastY = pos.X, pos.Y
			
			// Last significant movement
			if j == 0 {
				lastSigX, lastSigY, lastSigZ = pos.X, pos.Y, pos.Z
				lastSigMoveTime = posTime
			} else {
				dx := pos.X - lastSigX
				dy := pos.Y - lastSigY
				dz := pos.Z - lastSigZ
				dist := float32(math.Sqrt(float64(dx*dx + dy*dy + dz*dz)))
				if dist > 0.5 {
					lastSigX, lastSigY, lastSigZ = pos.X, pos.Y, pos.Z
					lastSigMoveTime = posTime
				}
			}
		}

		trackDatas = append(trackDatas, trackData{i + 1, len(t.positions), prepMove, lastSigMoveTime, endTime})
	}

	// Sort by prep phase movement (descending) to show team separation
	sort.Slice(trackDatas, func(i, j int) bool {
		return trackDatas[i].prepMove > trackDatas[j].prepMove
	})

	for i, td := range trackDatas {
		team := "ATK"
		if i < 5 {
			team = "DEF"
		}
		fmt.Printf("%-8d %-10d %-12.1f %-12.1f %-12.1f [%s]\n", 
			td.idx, td.positions, td.prepMove, td.lastSigMove, td.endTime, team)
	}

	// Print players from header
	fmt.Println("\n=== HEADER PLAYERS ===")
	for i, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			teamRole = string(r.Header.Teams[p.TeamIndex].Role)
		}
		deathStr := "survived"
		if dt, exists := deathTimes[p.Username]; exists {
			deathStr = fmt.Sprintf("died @ %.1fs", dt)
		}
		fmt.Printf("  [%d] %s (%s) - %s - %s\n", i, p.Username, teamRole, p.Operator.String(), deathStr)
	}
}

func readFloat32LE(b []byte) float32 {
	bits := binary.LittleEndian.Uint32(b)
	return math.Float32frombits(bits)
}

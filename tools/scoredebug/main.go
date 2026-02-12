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
		fmt.Println("Usage: scoredebug <replay.rec>")
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
		fmt.Println("No positions")
		return
	}

	// Build tracks
	threshold := float32(1.5)
	type posTrack struct {
		positions    []dissect.RawPosition
		lastX, lastY float32
	}
	tracks := make([]*posTrack, 0, 12)

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

	// Calculate time normalization
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

	var minCountdown float64 = 180
	for _, event := range r.MatchFeedback {
		if event.TimeInSeconds > 0 && event.TimeInSeconds < minCountdown {
			minCountdown = event.TimeInSeconds
		}
	}
	totalTime := 45.0 + (180.0 - minCountdown)

	pktToTime := func(pkt int) float64 {
		return (float64(pkt-minPkt) / pktRange) * totalTime
	}

	// Calculate prep phase movement
	prepPktFraction := 45.0 / totalTime
	prepPhaseEndPkt := minPkt + int(pktRange*prepPktFraction)

	// Track metadata
	type trackMeta struct {
		idx             int
		prepMove        float32
		lastSigMoveTime float64
		endTime         float64
	}
	var trackMetas []trackMeta

	for i, t := range tracks {
		if len(t.positions) < 50 {
			continue
		}

		var prepMove float32
		var lastX, lastY float32
		var lastSigX, lastSigY, lastSigZ float32
		var lastSigMoveTime float64 = 0

		for j, pos := range t.positions {
			posTime := pktToTime(pos.PacketNum)
			if pos.PacketNum <= prepPhaseEndPkt && j > 0 {
				dx := pos.X - lastX
				dy := pos.Y - lastY
				prepMove += float32(math.Sqrt(float64(dx*dx + dy*dy)))
			}
			lastX, lastY = pos.X, pos.Y

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

		endTime := pktToTime(t.positions[len(t.positions)-1].PacketNum)
		trackMetas = append(trackMetas, trackMeta{i, prepMove, lastSigMoveTime, endTime})
	}

	// Sort by prep movement
	sort.Slice(trackMetas, func(i, j int) bool {
		return trackMetas[i].prepMove > trackMetas[j].prepMove
	})

	fmt.Println("=== TRACKS (sorted by prep movement) ===")
	fmt.Printf("%-6s %-10s %-12s %-12s %-8s\n", "Track", "PrepMove", "LastSigMove", "EndTime", "Team")
	for i, tm := range trackMetas {
		team := "ATK"
		if i < 5 {
			team = "DEF"
		}
		fmt.Printf("%-6d %-10.1f %-12.1f %-12.1f %-8s\n", tm.idx+1, tm.prepMove, tm.lastSigMoveTime, tm.endTime, team)
	}

	// Death times
	fmt.Println("\n=== DEATH EVENTS ===")
	for _, event := range r.MatchFeedback {
		if event.Type == dissect.Kill && event.Target != "" {
			elapsed := 45.0 + (180.0 - event.TimeInSeconds)
			fmt.Printf("%s dies at %.0fs\n", event.Target, elapsed)
		}
	}

	// Header players
	fmt.Println("\n=== HEADER PLAYERS ===")
	for i, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "ATK"
			} else {
				teamRole = "DEF"
			}
		}
		fmt.Printf("[%d] %s (%s)\n", i, p.Username, teamRole)
	}
}

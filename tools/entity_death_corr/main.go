package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"

	"github.com/klauspost/compress/zstd"
	"github.com/redraskal/r6-dissect/dissect"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

type entityTrack struct {
	id            uint32
	positionCount int
	firstPktNum   int
	lastPktNum    int
	firstTime     float64 // Estimated time based on packet number
	lastTime      float64
	totalMove     float32 // Total distance traveled
	positions     []posData
}

type posData struct {
	pktNum int
	x, y, z float32
}

type deathEvent struct {
	killer string
	victim string
	time   float64 // Countdown timer value
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entity_death_corr <replay.rec>")
		os.Exit(1)
	}

	// Read with dissect
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	if err := r.Read(); err != nil && err.Error() != "EOF" {
	}
	f.Close()

	// Extract player info and death events
	fmt.Println("=== PLAYERS ===")
	playerTeams := make(map[string]string)
	for _, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				team = "ATK"
			} else {
				team = "DEF"
			}
		}
		playerTeams[p.Username] = team
		fmt.Printf("  %-15s (%s) %s\n", p.Username, team, p.Operator.String())
	}

	// Extract death events and convert to elapsed time
	var deaths []deathEvent
	fmt.Println("\n=== DEATH EVENTS (converted to elapsed time) ===")
	for _, event := range r.MatchFeedback {
		if event.Type == dissect.Kill && event.Target != "" {
			// TimeInSeconds is countdown (180 = start, 0 = end of action phase)
			// Prep phase is first 45 seconds
			// Elapsed = 45 + (180 - countdown)
			elapsed := 45.0 + (180.0 - event.TimeInSeconds)
			deaths = append(deaths, deathEvent{
				killer: event.Username,
				victim: event.Target,
				time:   elapsed,
			})
			fmt.Printf("  %.1fs: %s killed %s (countdown: %.0f)\n", 
				elapsed, event.Username, event.Target, event.TimeInSeconds)
		}
	}

	// Now analyze raw data
	f, err = os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		fmt.Println("Error decompressing:", err)
		os.Exit(1)
	}

	// Build entity tracks
	entities := make(map[uint32]*entityTrack)
	pktNum := 0
	maxPkt := 0

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if pos+14 > len(data) {
			continue
		}
		typeFirst := data[pos]
		typeSecond := data[pos+1]
		if typeSecond != 0x01 && typeSecond != 0x03 {
			continue
		}
		if typeFirst < 0xB0 {
			continue
		}

		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+6 : pos+10]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+10 : pos+14]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		pktNum++
		if pktNum > maxPkt {
			maxPkt = pktNum
		}

		if i < 4 {
			continue
		}
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		if entities[entityID] == nil {
			entities[entityID] = &entityTrack{
				id:          entityID,
				firstPktNum: pktNum,
			}
		}
		e := entities[entityID]
		e.positionCount++
		e.lastPktNum = pktNum
		
		// Track movement
		if len(e.positions) > 0 {
			last := e.positions[len(e.positions)-1]
			dx := x - last.x
			dy := y - last.y
			e.totalMove += float32(math.Sqrt(float64(dx*dx + dy*dy)))
		}
		e.positions = append(e.positions, posData{pktNum, x, y, z})
	}

	// Calculate estimated times
	// Estimate total round time from last death event
	var maxDeathTime float64 = 225 // Default to max
	if len(deaths) > 0 {
		for _, d := range deaths {
			if d.time > maxDeathTime-10 {
				maxDeathTime = d.time + 5
			}
		}
	}
	totalTime := maxDeathTime
	if totalTime <= 0 {
		totalTime = 225
	}

	// Convert packet numbers to times
	for _, e := range entities {
		e.firstTime = (float64(e.firstPktNum) / float64(maxPkt)) * totalTime
		e.lastTime = (float64(e.lastPktNum) / float64(maxPkt)) * totalTime
	}

	// Sort entities by position count
	var sorted []*entityTrack
	for _, e := range entities {
		sorted = append(sorted, e)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].positionCount > sorted[j].positionCount
	})

	// Take top 15 (likely 10 players + extras)
	topEntities := sorted
	if len(topEntities) > 15 {
		topEntities = topEntities[:15]
	}

	// Print entity summary with timing
	fmt.Println("\n=== TOP ENTITIES WITH TIMING ===")
	fmt.Printf("%-12s %6s %8s %8s %8s %8s\n", 
		"EntityID", "Pos", "FirstT", "LastT", "Duration", "Move")
	for _, e := range topEntities {
		duration := e.lastTime - e.firstTime
		fmt.Printf("0x%08x %6d %8.1f %8.1f %8.1f %8.0f\n",
			e.id, e.positionCount, e.firstTime, e.lastTime, duration, e.totalMove)
	}

	// Try to correlate entity "end times" with death events
	fmt.Println("\n=== ENTITY END TIME vs DEATH CORRELATION ===")
	
	// For each death event, find the entity that stopped moving closest to that time
	// AND was moving before that time
	for _, death := range deaths {
		fmt.Printf("\nDeath: %s at %.1fs\n", death.victim, death.time)
		
		// Find entities that stopped within 5 seconds of death
		type candidate struct {
			entity   *entityTrack
			timeDiff float64
		}
		var candidates []candidate
		
		for _, e := range topEntities {
			// Entity should have been active before death and stopped near death time
			if e.firstTime < death.time-5 && e.lastTime >= death.time-10 && e.lastTime <= death.time+5 {
				timeDiff := math.Abs(e.lastTime - death.time)
				candidates = append(candidates, candidate{e, timeDiff})
			}
		}
		
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].timeDiff < candidates[j].timeDiff
		})
		
		for i, c := range candidates {
			if i >= 3 {
				break
			}
			fmt.Printf("  Candidate: 0x%08x ended at %.1fs (diff: %.1fs), %d positions\n",
				c.entity.id, c.entity.lastTime, c.timeDiff, c.entity.positionCount)
		}
	}

	// Group entities by team using first position (prep phase position)
	fmt.Println("\n=== TEAM SEPARATION BY PREP PHASE MOVEMENT ===")
	
	// Calculate prep phase movement for each entity (first 45 seconds)
	type entityPrepMove struct {
		entity   *entityTrack
		prepMove float32
		firstPos posData
	}
	var prepMoves []entityPrepMove
	
	for _, e := range topEntities {
		var prepMove float32
		var lastX, lastY float32
		for _, p := range e.positions {
			posTime := (float64(p.pktNum) / float64(maxPkt)) * totalTime
			if posTime > 45 {
				break
			}
			if lastX != 0 || lastY != 0 {
				dx := p.x - lastX
				dy := p.y - lastY
				prepMove += float32(math.Sqrt(float64(dx*dx + dy*dy)))
			}
			lastX, lastY = p.x, p.y
		}
		if len(e.positions) > 0 {
			prepMoves = append(prepMoves, entityPrepMove{e, prepMove, e.positions[0]})
		}
	}
	
	sort.Slice(prepMoves, func(i, j int) bool {
		return prepMoves[i].prepMove > prepMoves[j].prepMove
	})
	
	fmt.Println("\nEntities by prep phase movement (defenders move more in prep):")
	fmt.Printf("%-12s %8s %25s %8s\n", "EntityID", "PrepMove", "FirstPos", "Positions")
	for _, pm := range prepMoves {
		firstPos := fmt.Sprintf("(%.1f, %.1f, %.1f)", pm.firstPos.x, pm.firstPos.y, pm.firstPos.z)
		fmt.Printf("0x%08x %8.1f %25s %8d\n", 
			pm.entity.id, pm.prepMove, firstPos, pm.entity.positionCount)
	}
	
	// Try to match deaths to entities more precisely
	fmt.Println("\n=== DEATH-TO-ENTITY MATCHING (using last known position near kill time) ===")
	
	for _, death := range deaths {
		fmt.Printf("\n%s (victim team: %s) killed at %.1fs:\n", 
			death.victim, playerTeams[death.victim], death.time)
		
		// For each top entity, find its position at the death time
		type entityAtDeath struct {
			entity *entityTrack
			pos    posData
			stillAlive bool
		}
		var atDeath []entityAtDeath
		
		for _, e := range topEntities {
			// Find position closest to death time
			var bestPos posData
			bestDiff := math.MaxFloat64
			for _, p := range e.positions {
				posTime := (float64(p.pktNum) / float64(maxPkt)) * totalTime
				diff := math.Abs(posTime - death.time)
				if diff < bestDiff {
					bestDiff = diff
					bestPos = p
				}
			}
			stillAlive := e.lastTime > death.time+5
			atDeath = append(atDeath, entityAtDeath{e, bestPos, stillAlive})
		}
		
		// Group by approximate position
		fmt.Println("  Entity positions at death time:")
		for _, ead := range atDeath {
			status := "ALIVE"
			if !ead.stillAlive {
				status = "STOPPED"
			}
			fmt.Printf("    0x%08x at (%.1f, %.1f) - %s (ends at %.1fs)\n",
				ead.entity.id, ead.pos.x, ead.pos.y, status, ead.entity.lastTime)
		}
	}
}

func decompressReplay(f *os.File) ([]byte, error) {
	br := bufio.NewReader(f)
	temp, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}

	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	isChunked := false
	for i := 0; i < len(temp)-4; i++ {
		if bytes.Equal(temp[i:i+4], zstdMagic) {
			for j := i + 100; j < len(temp)-4; j++ {
				if bytes.Equal(temp[j:j+4], zstdMagic) {
					isChunked = true
					break
				}
			}
			break
		}
	}

	if isChunked {
		zstdReader, _ := zstd.NewReader(nil)
		var result []byte
		offset := 0
		for {
			found := false
			for ; offset < len(temp)-4; offset++ {
				if bytes.Equal(temp[offset:offset+4], zstdMagic) {
					found = true
					break
				}
			}
			if !found {
				break
			}

			chunkReader := bytes.NewReader(temp[offset:])
			if err := zstdReader.Reset(chunkReader); err != nil {
				offset++
				continue
			}
			chunk, err := io.ReadAll(zstdReader)
			if err != nil && !errors.Is(err, zstd.ErrMagicMismatch) {
				if len(chunk) == 0 {
					offset++
					continue
				}
			}
			result = append(result, chunk...)
			offset += 4
		}
		return result, nil
	} else {
		f.Seek(0, 0)
		zstdReader, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(zstdReader)
	}
}

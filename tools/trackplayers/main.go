package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type position struct {
	x, y, z   float32
	time      float64 // packet sequence number
	assigned  bool
	trackID   int
}

var allPositions []position
var packetCounter int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating reader: %v\n", err)
		os.Exit(1)
	}

	// Capture all position-type packets (B0xx, B8xx, C0xx, E0xx with suffix 01 or 03)
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePosition)

	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
	}

	fmt.Printf("Captured %d positions\n\n", len(allPositions))

	// Sort by time
	sort.Slice(allPositions, func(i, j int) bool {
		return allPositions[i].time < allPositions[j].time
	})

	// Simple tracking: for each position, find the nearest unassigned position
	// within a reasonable time window and distance threshold
	
	// Initialize tracks
	type track struct {
		id        int
		positions []position
	}
	var tracks []track
	
	// Parameters
	maxDist := float32(3.0)      // Max distance to link positions (player can move ~3 units between frames)
	maxTimeGap := float64(100.0) // Max time gap between linked positions
	
	for i := range allPositions {
		if allPositions[i].assigned {
			continue
		}
		
		// Start a new track
		trackID := len(tracks)
		t := track{id: trackID}
		
		// Follow the track
		current := &allPositions[i]
		current.assigned = true
		current.trackID = trackID
		t.positions = append(t.positions, *current)
		
		for {
			// Find next position: nearest unassigned position within threshold
			var bestIdx int = -1
			var bestDist float32 = maxDist
			
			for j := i + 1; j < len(allPositions); j++ {
				if allPositions[j].assigned {
					continue
				}
				
				timeDiff := allPositions[j].time - current.time
				if timeDiff <= 0 {
					continue // Must be later
				}
				if timeDiff > maxTimeGap {
					break // Too far in time
				}
				
				dx := allPositions[j].x - current.x
				dy := allPositions[j].y - current.y
				dz := allPositions[j].z - current.z
				dist := float32(math.Sqrt(float64(dx*dx + dy*dy + dz*dz)))
				
				if dist < bestDist {
					bestDist = dist
					bestIdx = j
				}
			}
			
			if bestIdx < 0 {
				break // No more linked positions
			}
			
			// Add to track
			allPositions[bestIdx].assigned = true
			allPositions[bestIdx].trackID = trackID
			t.positions = append(t.positions, allPositions[bestIdx])
			current = &allPositions[bestIdx]
		}
		
		tracks = append(tracks, t)
	}
	
	fmt.Printf("Found %d tracks\n\n", len(tracks))
	
	// Sort tracks by length
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})
	
	// Show top tracks
	fmt.Printf("Top 15 tracks by position count:\n")
	for i := 0; i < 15 && i < len(tracks); i++ {
		t := tracks[i]
		if len(t.positions) < 10 {
			break
		}
		first := t.positions[0]
		last := t.positions[len(t.positions)-1]
		fmt.Printf("  Track %d: %d positions, time %.1f-%.1f, start(%.1f,%.1f,%.1f) end(%.1f,%.1f,%.1f)\n",
			t.id, len(t.positions), first.time, last.time,
			first.x, first.y, first.z, last.x, last.y, last.z)
	}
	
	// Count tracks with >100 positions (likely players)
	playerLikeTracks := 0
	for _, t := range tracks {
		if len(t.positions) >= 100 {
			playerLikeTracks++
		}
	}
	fmt.Printf("\nTracks with >=100 positions: %d (these are likely players)\n", playerLikeTracks)
}

func capturePosition(r *dissect.Reader) error {
	packetCounter++
	
	// Read type bytes
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	
	// Filter to position types
	if typeBytes[1] != 0x01 && typeBytes[1] != 0x03 {
		return nil
	}
	if typeBytes[0] < 0xB0 {
		return nil
	}
	
	// Read coords
	x, err := r.Float32()
	if err != nil {
		return nil
	}
	y, err := r.Float32()
	if err != nil {
		return nil
	}
	z, err := r.Float32()
	if err != nil {
		return nil
	}

	if !isValid(x) || !isValid(y) || z < -5 || z > 15 {
		return nil
	}
	if math.Abs(float64(x)) < 1 && math.Abs(float64(y)) < 1 {
		return nil
	}

	allPositions = append(allPositions, position{
		x:    x,
		y:    y,
		z:    z,
		time: float64(packetCounter),
	})

	return nil
}

func isValid(f float32) bool {
	return !math.IsNaN(float64(f)) && f >= -100 && f <= 100
}

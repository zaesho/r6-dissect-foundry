package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// Build tracks by following position continuity
// Ignore the "player ID" field - assign packets to tracks based on proximity

type posPacket struct {
	packetNum int
	x, y, z   float32
}

type track struct {
	positions []posPacket
	lastX, lastY float32
}

var packets []posPacket
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePos)
	r.Read()

	fmt.Printf("Total position packets: %d\n\n", len(packets))

	// Build tracks by assigning each packet to the nearest existing track
	// or creating a new track if no track is within threshold
	
	tracks := make([]*track, 0, 10)
	threshold := float32(8.0) // Max distance to consider same entity
	
	for _, p := range packets {
		// Find nearest track
		bestTrack := -1
		bestDist := float32(math.MaxFloat32)
		
		for i, t := range tracks {
			dx := p.x - t.lastX
			dy := p.y - t.lastY
			dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
			if dist < bestDist {
				bestDist = dist
				bestTrack = i
			}
		}
		
		if bestTrack >= 0 && bestDist <= threshold {
			// Assign to existing track
			tracks[bestTrack].positions = append(tracks[bestTrack].positions, p)
			tracks[bestTrack].lastX = p.x
			tracks[bestTrack].lastY = p.y
		} else {
			// Create new track
			newTrack := &track{
				positions: []posPacket{p},
				lastX:     p.x,
				lastY:     p.y,
			}
			tracks = append(tracks, newTrack)
		}
	}
	
	fmt.Printf("Total tracks created: %d\n\n", len(tracks))
	
	// Sort tracks by size
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})
	
	// Show top 20 tracks
	fmt.Printf("=== Top 20 tracks by packet count ===\n\n")
	totalInTop20 := 0
	for i := 0; i < 20 && i < len(tracks); i++ {
		t := tracks[i]
		totalInTop20 += len(t.positions)
		
		// Calculate path length
		pathLen := float64(0)
		for j := 1; j < len(t.positions); j++ {
			dx := t.positions[j].x - t.positions[j-1].x
			dy := t.positions[j].y - t.positions[j-1].y
			pathLen += math.Sqrt(float64(dx*dx + dy*dy))
		}
		
		fmt.Printf("Track %2d: %5d packets, path=%.0f units, start=(%.1f,%.1f) end=(%.1f,%.1f)\n",
			i+1, len(t.positions), pathLen,
			t.positions[0].x, t.positions[0].y,
			t.positions[len(t.positions)-1].x, t.positions[len(t.positions)-1].y)
	}
	
	fmt.Printf("\nTop 20 tracks contain %d/%d packets (%.1f%%)\n", 
		totalInTop20, len(packets), float64(totalInTop20)/float64(len(packets))*100)
	
	// Show how many tracks have significant size
	significant := 0
	for _, t := range tracks {
		if len(t.positions) >= 100 {
			significant++
		}
	}
	fmt.Printf("Tracks with 100+ packets: %d\n", significant)

	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}
}

func capturePos(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	if typeBytes[0] != 0xB8 || typeBytes[1] != 0x03 {
		return nil
	}

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

	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) {
		return nil
	}
	
	if x < -100 || x > 100 || y < -100 || y > 100 {
		return nil
	}

	packets = append(packets, posPacket{
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

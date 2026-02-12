package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// Final tracker: Use position continuity to identify players
// Output per-player movement tracks

type posPacket struct {
	packetNum int
	x, y, z   float32
}

type PlayerTrack struct {
	TrackID   int        `json:"track_id"`
	Positions []Position `json:"positions"`
}

type Position struct {
	Tick int     `json:"tick"`
	X    float32 `json:"x"`
	Y    float32 `json:"y"`
	Z    float32 `json:"z"`
}

type track struct {
	id           int
	positions    []posPacket
	lastX, lastY float32
}

var packets []posPacket
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec> [output.json]")
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

	fmt.Printf("Total position packets: %d\n", len(packets))

	// Build tracks using position continuity
	tracks := buildTracks(packets, 8.0)
	
	fmt.Printf("Tracks created: %d\n\n", len(tracks))

	// Sort by size
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})

	// Show stats for top 12 tracks
	fmt.Printf("=== Top 12 Tracks ===\n\n")
	for i := 0; i < 12 && i < len(tracks); i++ {
		t := tracks[i]
		if len(t.positions) < 50 {
			continue
		}
		
		pathLen := float64(0)
		for j := 1; j < len(t.positions); j++ {
			dx := t.positions[j].x - t.positions[j-1].x
			dy := t.positions[j].y - t.positions[j-1].y
			pathLen += math.Sqrt(float64(dx*dx + dy*dy))
		}
		
		fmt.Printf("Track %2d: %5d positions, %.0f units traveled\n", i+1, len(t.positions), pathLen)
		fmt.Printf("  Start: (%.1f, %.1f, %.1f) @ tick %d\n", 
			t.positions[0].x, t.positions[0].y, t.positions[0].z, t.positions[0].packetNum)
		fmt.Printf("  End:   (%.1f, %.1f, %.1f) @ tick %d\n", 
			t.positions[len(t.positions)-1].x, t.positions[len(t.positions)-1].y, 
			t.positions[len(t.positions)-1].z, t.positions[len(t.positions)-1].packetNum)
	}

	// Convert to export format
	var exports []PlayerTrack
	for i := 0; i < 12 && i < len(tracks); i++ {
		t := tracks[i]
		if len(t.positions) < 50 {
			continue
		}
		
		export := PlayerTrack{
			TrackID:   i + 1,
			Positions: make([]Position, 0, len(t.positions)),
		}
		
		// Deduplicate consecutive identical positions
		var lastX, lastY, lastZ float32
		for _, p := range t.positions {
			if p.x != lastX || p.y != lastY || p.z != lastZ {
				export.Positions = append(export.Positions, Position{
					Tick: p.packetNum,
					X:    p.x,
					Y:    p.y,
					Z:    p.z,
				})
				lastX, lastY, lastZ = p.x, p.y, p.z
			}
		}
		
		exports = append(exports, export)
	}

	// Output JSON if requested
	if len(os.Args) >= 3 {
		outFile, err := os.Create(os.Args[2])
		if err != nil {
			fmt.Printf("Error creating output: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
		
		encoder := json.NewEncoder(outFile)
		encoder.SetIndent("", "  ")
		encoder.Encode(exports)
		
		fmt.Printf("\nWrote %d tracks to %s\n", len(exports), os.Args[2])
	}

	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}
}

func buildTracks(packets []posPacket, threshold float32) []*track {
	tracks := make([]*track, 0, 12)
	
	for _, p := range packets {
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
			tracks[bestTrack].positions = append(tracks[bestTrack].positions, p)
			tracks[bestTrack].lastX = p.x
			tracks[bestTrack].lastY = p.y
		} else {
			newTrack := &track{
				id:        len(tracks),
				positions: []posPacket{p},
				lastX:     p.x,
				lastY:     p.y,
			}
			tracks = append(tracks, newTrack)
		}
	}
	
	return tracks
}

func capturePos(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	// Accept both B801 and B803 packets
	if typeBytes[0] < 0xB0 || (typeBytes[1] != 0x01 && typeBytes[1] != 0x03) {
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

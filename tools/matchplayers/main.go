package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// Now we know position continuity gives ~10 tracks
// Let's try to match tracks to players based on starting positions
// and track the full movement for each player

type posPacket struct {
	packetNum int
	rawID     int // The raw "ID" field from the packet (for comparison)
	x, y, z   float32
}

type track struct {
	id        int
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, func(rd *dissect.Reader) error {
		return capturePos(rd)
	})
	r.Read()

	fmt.Printf("Total position packets: %d\n\n", len(packets))

	// Build tracks
	tracks := make([]*track, 0, 12)
	threshold := float32(8.0)
	
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
	
	// Sort tracks by size
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})
	
	fmt.Printf("=== Track analysis ===\n\n")
	
	for i := 0; i < 12 && i < len(tracks); i++ {
		t := tracks[i]
		if len(t.positions) < 100 {
			continue
		}
		
		// Count rawID distribution within this track
		rawIDCounts := make(map[int]int)
		for _, p := range t.positions {
			rawIDCounts[p.rawID]++
		}
		
		// Find most common rawID
		mostCommonID := 0
		mostCommonCount := 0
		for id, count := range rawIDCounts {
			if count > mostCommonCount {
				mostCommonID = id
				mostCommonCount = count
			}
		}
		
		pct := float64(mostCommonCount) / float64(len(t.positions)) * 100
		
		fmt.Printf("Track %2d (%5d packets):\n", i+1, len(t.positions))
		fmt.Printf("  Start: (%.1f, %.1f)  End: (%.1f, %.1f)\n",
			t.positions[0].x, t.positions[0].y,
			t.positions[len(t.positions)-1].x, t.positions[len(t.positions)-1].y)
		fmt.Printf("  Most common rawID: %d (%.1f%% of packets)\n", mostCommonID, pct)
		fmt.Printf("  All rawIDs: ")
		for id, count := range rawIDCounts {
			fmt.Printf("%d:%d ", id, count)
		}
		fmt.Println()
		fmt.Println()
	}

	fmt.Printf("=== Header Players ===\n")
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

	// Read the "rawID" field at the offset we thought was player ID
	postBytes, err := r.Bytes(36)
	if err != nil {
		return nil
	}
	
	rawID := int(postBytes[20]) | int(postBytes[21])<<8 | int(postBytes[22])<<16 | int(postBytes[23])<<24

	packets = append(packets, posPacket{
		packetNum: packetNum,
		rawID:     rawID,
		x:         x,
		y:         y,
		z:         z,
	})
	
	return nil
}

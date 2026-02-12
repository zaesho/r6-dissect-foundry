package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type posRecord struct {
	typeCode  uint16
	playerID  int
	packetNum int
	x, y, z   float32
}

var positions []posRecord
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

	// Capture ALL position packets (both 01 and 03 types)
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureAll)
	r.Read()

	fmt.Printf("Total captured: %d positions\n\n", len(positions))

	// Separate by type suffix (01 vs 03)
	var type01, type03 []posRecord
	for _, p := range positions {
		if p.typeCode&0xFF == 0x01 {
			type01 = append(type01, p)
		} else if p.typeCode&0xFF == 0x03 {
			type03 = append(type03, p)
		}
	}

	fmt.Printf("01-type packets: %d\n", len(type01))
	fmt.Printf("03-type packets: %d\n", len(type03))

	// For 01-type: count by player ID
	fmt.Printf("\n=== 01-type by player ID ===\n")
	playerCounts01 := make(map[int]int)
	for _, p := range type01 {
		playerCounts01[p.playerID]++
	}
	
	var ids []int
	for id := range playerCounts01 {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	
	for _, id := range ids {
		if id >= 1 && id <= 20 {
			fmt.Printf("  Player %2d: %d positions\n", id, playerCounts01[id])
		}
	}

	// For 03-type: we don't have player IDs, but let's see if we can match them
	// by looking at which positions correlate with 01-type positions
	fmt.Printf("\n=== Matching 03-type to 01-type ===\n")
	
	// Sort both by packet number
	sort.Slice(type01, func(i, j int) bool {
		return type01[i].packetNum < type01[j].packetNum
	})
	sort.Slice(type03, func(i, j int) bool {
		return type03[i].packetNum < type03[j].packetNum
	})

	// For each 03-type, find the closest 01-type with matching position
	matched := 0
	matchedByPlayer := make(map[int]int)
	
	for _, p03 := range type03 {
		// Binary search for nearby 01-type
		for _, p01 := range type01 {
			pktDiff := p01.packetNum - p03.packetNum
			if pktDiff < -20 {
				continue
			}
			if pktDiff > 20 {
				break
			}
			
			// Check if position matches (within 0.5 units)
			dx := p01.x - p03.x
			dy := p01.y - p03.y
			if dx*dx+dy*dy < 0.25 {
				matched++
				matchedByPlayer[p01.playerID]++
				break
			}
		}
	}

	fmt.Printf("03-type packets matched to 01-type: %d/%d (%.1f%%)\n", 
		matched, len(type03), float64(matched)/float64(len(type03))*100)
	
	fmt.Printf("\n03-type matched by inferred player ID:\n")
	for _, id := range ids {
		if id >= 1 && id <= 20 && matchedByPlayer[id] > 0 {
			fmt.Printf("  Player %2d: %d matched 03-type positions\n", id, matchedByPlayer[id])
		}
	}

	// Combined totals
	fmt.Printf("\n=== Combined totals (01 + matched 03) ===\n")
	for _, id := range ids {
		if id >= 1 && id <= 20 {
			total := playerCounts01[id] + matchedByPlayer[id]
			rate := float64(total) / 85.0 // Assuming 85 second round
			fmt.Printf("  Player %2d: %4d positions (%.1f/sec)\n", id, total, rate)
		}
	}

	// Now let's check the 03-type packets more carefully
	// Maybe there IS a player ID hidden somewhere
	fmt.Printf("\n=== Analyzing 03-type packet bytes ===\n")
	
	// Group 03-type by their post-byte patterns
	post4Counts := make(map[uint32]int)
	for _, p := range type03 {
		// p.playerID is actually the post4 bytes for 03-type
		post4Counts[uint32(p.playerID)]++
	}
	
	fmt.Printf("03-type post-byte patterns (bytes 4-7):\n")
	type kv struct {
		k uint32
		v int
	}
	var sorted []kv
	for k, v := range post4Counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})
	for i := 0; i < 10 && i < len(sorted); i++ {
		fmt.Printf("  0x%08X: %d\n", sorted[i].k, sorted[i].v)
	}
}

func captureAll(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	// Accept both 01 and 03 suffix
	if typeBytes[1] != 0x01 && typeBytes[1] != 0x03 {
		return nil
	}
	if typeBytes[0] < 0xB0 {
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

	if x < -100 || x > 100 || y < -100 || y > 100 || z < -5 || z > 15 {
		return nil
	}

	postBytes, err := r.Bytes(8)
	if err != nil {
		return nil
	}

	// For 01-type: player ID at bytes 4-7
	// For 03-type: store the raw value for analysis
	playerID := int(binary.LittleEndian.Uint32(postBytes[4:8]))

	positions = append(positions, posRecord{
		typeCode:  typeCode,
		playerID:  playerID,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

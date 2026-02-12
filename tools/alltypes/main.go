package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	typeCode  uint16
	packetNum int
	playerID  int // extracted where possible
	x, y, z   float32
}

var packets []packet
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

	// Capture ALL packets after the 60 73 85 fe marker - no filtering
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureAll)
	r.Read()

	fmt.Printf("Captured %d total packets after 60 73 85 fe marker\n\n", len(packets))

	// Count by type code (full 2-byte type)
	typeCounts := make(map[uint16]int)
	for _, p := range packets {
		typeCounts[p.typeCode]++
	}

	// Sort by count descending
	type kv struct {
		k uint16
		v int
	}
	var sorted []kv
	for k, v := range typeCounts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})

	fmt.Printf("=== All type codes (sorted by count) ===\n")
	for _, kv := range sorted {
		suffix := kv.k & 0xFF
		prefix := (kv.k >> 8) & 0xFF
		fmt.Printf("  0x%04X (prefix=0x%02X, suffix=0x%02X): %6d packets\n", kv.k, prefix, suffix, kv.v)
	}

	// Group by suffix (last byte)
	fmt.Printf("\n=== Grouped by suffix (second byte) ===\n")
	suffixCounts := make(map[uint8]int)
	for _, p := range packets {
		suffix := uint8(p.typeCode & 0xFF)
		suffixCounts[suffix]++
	}
	
	var suffixes []uint8
	for s := range suffixCounts {
		suffixes = append(suffixes, s)
	}
	sort.Slice(suffixes, func(i, j int) bool {
		return suffixCounts[suffixes[i]] > suffixCounts[suffixes[j]]
	})
	
	for _, s := range suffixes {
		fmt.Printf("  Suffix 0x%02X: %6d packets\n", s, suffixCounts[s])
	}

	// Now analyze player distribution for EACH suffix type
	fmt.Printf("\n=== Player distribution by suffix type ===\n")
	for _, s := range suffixes {
		playerCounts := make(map[int]int)
		validPackets := 0
		
		for _, p := range packets {
			if uint8(p.typeCode&0xFF) == s && p.playerID >= 5 && p.playerID <= 14 {
				playerCounts[p.playerID]++
				validPackets++
			}
		}
		
		if validPackets > 0 {
			fmt.Printf("\nSuffix 0x%02X (%d packets with valid player IDs 5-14):\n", s, validPackets)
			for id := 5; id <= 14; id++ {
				if playerCounts[id] > 0 {
					fmt.Printf("  Player %2d: %5d\n", id, playerCounts[id])
				}
			}
		}
	}

	// Header info
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d) -> Expected Player ID %d\n", i, p.Username, p.TeamIndex, i+5)
	}
}

func captureAll(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	// Try to read coordinates for position-like packets
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

	// Read extended post bytes to try to find player ID
	postBytes, err := r.Bytes(24)
	if err != nil {
		postBytes = make([]byte, 24)
	}

	// Try to extract player ID based on known patterns
	var playerID int
	suffix := typeBytes[1]
	
	if suffix == 0x01 {
		// 01-type: player ID at bytes 4-7
		playerID = int(binary.LittleEndian.Uint32(postBytes[4:8]))
	} else if suffix == 0x03 {
		// 03-type: player ID at bytes 20-23
		playerID = int(binary.LittleEndian.Uint32(postBytes[20:24]))
	} else {
		// Try both locations for other suffixes
		id1 := int(binary.LittleEndian.Uint32(postBytes[4:8]))
		id2 := int(binary.LittleEndian.Uint32(postBytes[20:24]))
		
		if id1 >= 5 && id1 <= 14 {
			playerID = id1
		} else if id2 >= 5 && id2 <= 14 {
			playerID = id2
		}
	}

	packets = append(packets, packet{
		typeCode:  typeCode,
		packetNum: packetNum,
		playerID:  playerID,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

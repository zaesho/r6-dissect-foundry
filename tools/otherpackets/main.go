package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

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

	// Try a different approach - look for patterns that might be player entity IDs
	// in ALL packets, not just B0xx
	
	foundCoords := make(map[uint16]int)      // type -> count of packets with valid-looking coords
	foundPlayerIDs := make(map[uint16]map[int]int) // type -> playerID -> count
	
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, func(r *dissect.Reader) error {
		packetNum++
		
		typeBytes, err := r.Bytes(2)
		if err != nil {
			return nil
		}
		typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])
		
		// Read lots of data to search through
		data, err := r.Bytes(60)
		if err != nil {
			return nil
		}
		
		// Try to find coordinates at various offsets
		for offset := 0; offset+12 <= len(data); offset += 4 {
			x := math.Float32frombits(binary.LittleEndian.Uint32(data[offset:offset+4]))
			y := math.Float32frombits(binary.LittleEndian.Uint32(data[offset+4:offset+8]))
			z := math.Float32frombits(binary.LittleEndian.Uint32(data[offset+8:offset+12]))
			
			// Check if these look like map coordinates
			if isMapCoord(x) && isMapCoord(y) && z >= -5 && z <= 15 {
				// Found coordinates!
				foundCoords[typeCode]++
				
				// Now try to find player ID nearby
				for idOffset := 0; idOffset+4 <= len(data); idOffset += 4 {
					id := int(binary.LittleEndian.Uint32(data[idOffset:idOffset+4]))
					if id >= 5 && id <= 14 {
						if foundPlayerIDs[typeCode] == nil {
							foundPlayerIDs[typeCode] = make(map[int]int)
						}
						foundPlayerIDs[typeCode][id]++
					}
				}
				break // Only count once per packet
			}
		}
		
		return nil
	})
	
	r.Read()
	
	fmt.Printf("=== Packets with map-like coordinates by type ===\n")
	for typeCode, count := range foundCoords {
		if count > 100 { // Only show significant types
			fmt.Printf("Type 0x%04X: %d packets with coords\n", typeCode, count)
			
			if players, ok := foundPlayerIDs[typeCode]; ok {
				fmt.Printf("  Player ID distribution:\n")
				for id := 5; id <= 14; id++ {
					if players[id] > 0 {
						fmt.Printf("    Player %d: %d\n", id, players[id])
					}
				}
			}
		}
	}
}

func isMapCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	// Most R6 maps have coordinates roughly in -50 to 50 range
	return f >= -100 && f <= 100 && (f < -1 || f > 1) // Must have some magnitude
}

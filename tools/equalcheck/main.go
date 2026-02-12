package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type rawPacket struct {
	typeCode  uint16
	packetNum int
	allBytes  []byte
}

var packets []rawPacket
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureRaw)
	r.Read()

	fmt.Printf("Total packets: %d\n\n", len(packets))

	// Group by type code
	typeGroups := make(map[uint16][]rawPacket)
	for _, p := range packets {
		typeGroups[p.typeCode] = append(typeGroups[p.typeCode], p)
	}

	// For each type, check player distribution at various offsets
	fmt.Printf("=== Checking which packet types have EQUAL player distribution ===\n\n")

	var typeCodes []uint16
	for tc := range typeGroups {
		typeCodes = append(typeCodes, tc)
	}
	sort.Slice(typeCodes, func(i, j int) bool {
		return len(typeGroups[typeCodes[i]]) > len(typeGroups[typeCodes[j]])
	})

	for _, tc := range typeCodes {
		group := typeGroups[tc]
		if len(group) < 100 {
			continue // Skip small groups
		}

		// Try to find player IDs at various offsets
		bestOffset := -1
		bestVariance := math.MaxFloat64
		bestDist := make(map[int]int)

		for offset := 0; offset < 50; offset++ {
			dist := make(map[int]int)
			for _, p := range group {
				if offset+4 <= len(p.allBytes) {
					id := int(binary.LittleEndian.Uint32(p.allBytes[offset : offset+4]))
					if id >= 5 && id <= 14 {
						dist[id]++
					}
				}
			}

			// Check if we got all 10 players
			if len(dist) >= 8 {
				// Calculate variance
				total := 0
				for _, c := range dist {
					total += c
				}
				if total > len(group)/2 { // At least half the packets have valid IDs
					mean := float64(total) / 10.0
					variance := 0.0
					for id := 5; id <= 14; id++ {
						diff := float64(dist[id]) - mean
						variance += diff * diff
					}
					variance /= 10.0

					if variance < bestVariance {
						bestVariance = variance
						bestOffset = offset
						bestDist = dist
					}
				}
			}
		}

		if bestOffset >= 0 {
			total := 0
			for _, c := range bestDist {
				total += c
			}
			stdDev := math.Sqrt(bestVariance)
			mean := float64(total) / 10.0
			cv := stdDev / mean * 100 // Coefficient of variation

			// Only show if CV is low (more equal distribution)
			if cv < 100 {
				fmt.Printf("Type 0x%04X (%d packets): Player ID at offset %d\n", tc, len(group), bestOffset)
				fmt.Printf("  CV=%.1f%% (lower = more equal)\n", cv)
				for id := 5; id <= 14; id++ {
					pct := float64(bestDist[id]) / float64(total) * 100
					fmt.Printf("    Player %2d: %5d (%.1f%%)\n", id, bestDist[id], pct)
				}
				fmt.Println()
			}
		}
	}

	// Also look for completely different patterns - maybe rotation/state packets
	// that cycle through all players equally
	fmt.Printf("\n=== Looking for cycling patterns (10 distinct values in sequence) ===\n")
	
	// Check B802 type - we filtered these out before, maybe they're important
	if group, ok := typeGroups[0xB802]; ok && len(group) > 100 {
		fmt.Printf("\n0xB802 packets (%d):\n", len(group))
		// Show first 20 raw
		for i := 0; i < 20 && i < len(group); i++ {
			p := group[i]
			fmt.Printf("[%d] %02X\n", i, p.allBytes[:32])
		}
	}

	// Check the 30xx packets
	if group, ok := typeGroups[0x3006]; ok && len(group) > 100 {
		fmt.Printf("\n0x3006 packets (%d):\n", len(group))
		for i := 0; i < 10 && i < len(group); i++ {
			p := group[i]
			fmt.Printf("[%d] %02X\n", i, p.allBytes[:32])
		}
	}
}

func captureRaw(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	allBytes, err := r.Bytes(60)
	if err != nil {
		return nil
	}

	packets = append(packets, rawPacket{
		typeCode:  typeCode,
		packetNum: packetNum,
		allBytes:  allBytes,
	})

	return nil
}

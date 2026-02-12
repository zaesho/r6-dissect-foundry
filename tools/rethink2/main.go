package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

// Rethink: What if the "player ID" field doesn't mean what I think?
// Let's look at ALL small integer values at ALL offsets and see which
// offset gives us 10 values with EQUAL distribution

type rawPacket struct {
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

	// Filter to B803 only (the most common position packet)
	var b803 []rawPacket
	for _, p := range packets {
		if len(p.allBytes) >= 2 && p.allBytes[0] == 0xB8 && p.allBytes[1] == 0x03 {
			b803 = append(b803, p)
		}
	}

	fmt.Printf("Total B803 packets: %d\n\n", len(b803))

	// For EVERY single-byte offset, check how many distinct values and their distribution
	fmt.Printf("=== Single byte offsets with 8-12 distinct values ===\n\n")
	
	for offset := 0; offset < 60; offset++ {
		dist := make(map[byte]int)
		for _, p := range b803 {
			if offset < len(p.allBytes) {
				dist[p.allBytes[offset]]++
			}
		}
		
		if len(dist) >= 8 && len(dist) <= 15 {
			// Calculate coefficient of variation
			total := 0
			for _, c := range dist {
				total += c
			}
			mean := float64(total) / float64(len(dist))
			
			variance := 0.0
			for _, c := range dist {
				diff := float64(c) - mean
				variance += diff * diff
			}
			stdDev := math.Sqrt(variance / float64(len(dist)))
			cv := stdDev / mean * 100
			
			fmt.Printf("Offset %2d: %2d distinct values, CV=%.1f%%\n", offset, len(dist), cv)
			
			// Show distribution if CV is low (more equal)
			if cv < 50 {
				fmt.Printf("  Distribution:\n")
				for val, count := range dist {
					pct := float64(count) / float64(total) * 100
					fmt.Printf("    0x%02X (%3d): %5d (%.1f%%)\n", val, val, count, pct)
				}
			}
		}
	}

	// Also check 2-byte and 4-byte values
	fmt.Printf("\n=== 4-byte offsets (uint32) with 8-12 distinct values in 0-100 range ===\n\n")
	
	for offset := 0; offset < 56; offset++ {
		dist := make(map[uint32]int)
		for _, p := range b803 {
			if offset+4 <= len(p.allBytes) {
				val := binary.LittleEndian.Uint32(p.allBytes[offset : offset+4])
				if val > 0 && val <= 100 {
					dist[val]++
				}
			}
		}
		
		if len(dist) >= 8 && len(dist) <= 15 {
			total := 0
			for _, c := range dist {
				total += c
			}
			
			// Only consider if most packets have valid IDs
			if total < len(b803)/2 {
				continue
			}
			
			mean := float64(total) / float64(len(dist))
			variance := 0.0
			for _, c := range dist {
				diff := float64(c) - mean
				variance += diff * diff
			}
			stdDev := math.Sqrt(variance / float64(len(dist)))
			cv := stdDev / mean * 100
			
			fmt.Printf("Offset %2d: %2d distinct values, CV=%.1f%%, coverage=%d/%d\n", 
				offset, len(dist), cv, total, len(b803))
			
			if cv < 100 {
				fmt.Printf("  Distribution:\n")
				for val, count := range dist {
					pct := float64(count) / float64(total) * 100
					fmt.Printf("    %2d: %5d (%.1f%%)\n", val, count, pct)
				}
			}
		}
	}

	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}
}

func captureRaw(r *dissect.Reader) error {
	packetNum++

	allBytes, err := r.Bytes(80)
	if err != nil {
		return nil
	}

	packets = append(packets, rawPacket{
		packetNum: packetNum,
		allBytes:  allBytes,
	})

	return nil
}

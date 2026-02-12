package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
)

func main() {
	data, err := os.ReadFile("samplefiles/R01_dump.bin") // Chalet
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Deep Analysis of Movement Packets ===\n")

	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}

	type packet struct {
		offset    int
		seq       uint32
		entityID  byte
		x, y, z   float32
		before32  []byte
		after32   []byte
	}

	var packets []packet

	for i := 32; i <= len(data)-64; i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}

		// Read sequence (offset +8)
		seq := binary.LittleEndian.Uint32(data[i+8:])
		
		// Read entity byte (offset +12)
		entityID := data[i+12]
		
		// Read coords (offset +20)
		floatOff := i + 20
		x := readFloat(data[floatOff:])
		y := readFloat(data[floatOff+4:])
		z := readFloat(data[floatOff+8:])

		before := make([]byte, 32)
		copy(before, data[i-32:i])
		
		after := make([]byte, 32)
		copy(after, data[i+32:i+64])

		packets = append(packets, packet{i, seq, entityID, x, y, z, before, after})
	}

	fmt.Printf("Total packets found: %d\n\n", len(packets))

	// Group by entity
	byEntity := make(map[byte][]packet)
	for _, p := range packets {
		byEntity[p.entityID] = append(byEntity[p.entityID], p)
	}

	// Sort entities by count
	type entityInfo struct {
		id     byte
		pkts   []packet
	}
	var entities []entityInfo
	for id, pkts := range byEntity {
		entities = append(entities, entityInfo{id, pkts})
	}
	sort.Slice(entities, func(i, j int) bool {
		return len(entities[i].pkts) > len(entities[j].pkts)
	})

	fmt.Println("=== Packets by Entity ===")
	for _, e := range entities {
		fmt.Printf("\nEntity 0x%02X: %d packets\n", e.id, len(e.pkts))
		
		// Show first few packets with context
		for i := 0; i < min(3, len(e.pkts)); i++ {
			p := e.pkts[i]
			fmt.Printf("  #%d @ 0x%06X seq=0x%08X coords=(%.2f, %.2f, %.2f)\n", 
				i+1, p.offset, p.seq, p.x, p.y, p.z)
			fmt.Printf("    Before: ...%s\n", hex.EncodeToString(p.before32[16:]))
			fmt.Printf("    After:  %s...\n", hex.EncodeToString(p.after32[:16]))
		}
		
		// Analyze sequence gaps for this entity
		if len(e.pkts) > 1 {
			sort.Slice(e.pkts, func(i, j int) bool {
				return e.pkts[i].seq < e.pkts[j].seq
			})
			
			// Check for massive sequence gaps
			var gaps []uint32
			for i := 1; i < len(e.pkts); i++ {
				gap := e.pkts[i].seq - e.pkts[i-1].seq
				gaps = append(gaps, gap)
			}
			
			// Find min/max/average gap
			minGap, maxGap := gaps[0], gaps[0]
			var totalGap uint64
			for _, g := range gaps {
				if g < minGap { minGap = g }
				if g > maxGap { maxGap = g }
				totalGap += uint64(g)
			}
			avgGap := float64(totalGap) / float64(len(gaps))
			
			fmt.Printf("  Sequence gaps: min=%d max=%d avg=%.1f\n", minGap, maxGap, avgGap)
			
			// If max gap >> avg gap, there are discontinuities
			if float64(maxGap) > avgGap*100 {
				fmt.Printf("  WARNING: Large sequence gaps detected - data may be non-continuous\n")
			}
		}
	}

	// Now look for OTHER potential position patterns
	fmt.Println("\n\n=== Searching for other position-like patterns ===")
	
	// Look for sequences of 3 consecutive floats that look like world coords
	// without requiring the specific marker
	
	type floatTriple struct {
		offset int
		x, y, z float32
		context []byte
	}
	
	var candidatePositions []floatTriple
	
	for i := 0; i <= len(data)-12; i += 4 {
		x := readFloat(data[i:])
		y := readFloat(data[i+4:])
		z := readFloat(data[i+8:])
		
		// Check if these look like world coordinates
		if isWorldCoord(x, -100, 100) && isWorldCoord(y, -50, 50) && isWorldCoord(z, -5, 15) {
			// Additional check: not all zero or near-zero
			if abs(x) > 1 || abs(y) > 1 || abs(z) > 0.5 {
				ctx := make([]byte, 16)
				if i >= 16 {
					copy(ctx, data[i-16:i])
				}
				candidatePositions = append(candidatePositions, floatTriple{i, x, y, z, ctx})
			}
		}
	}
	
	fmt.Printf("Found %d candidate position triples (X: -100..100, Y: -50..50, Z: -5..15)\n", len(candidatePositions))
	
	// Group by the 8 bytes before the coords (potential packet type)
	prefixGroups := make(map[string][]floatTriple)
	for _, fp := range candidatePositions {
		prefix := hex.EncodeToString(fp.context[8:16])
		prefixGroups[prefix] = append(prefixGroups[prefix], fp)
	}
	
	// Sort by count
	type prefixInfo struct {
		prefix string
		triples []floatTriple
	}
	var prefixes []prefixInfo
	for p, t := range prefixGroups {
		if len(t) >= 50 { // Only show groups with at least 50 instances
			prefixes = append(prefixes, prefixInfo{p, t})
		}
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i].triples) > len(prefixes[j].triples)
	})
	
	fmt.Println("\nTop prefixes with 50+ occurrences:")
	for i := 0; i < min(15, len(prefixes)); i++ {
		p := prefixes[i]
		fmt.Printf("\n  Prefix %s: %d instances\n", p.prefix, len(p.triples))
		
		// Show first 3
		for j := 0; j < min(3, len(p.triples)); j++ {
			t := p.triples[j]
			fmt.Printf("    @ 0x%06X: (%.2f, %.2f, %.2f)\n", t.offset, t.x, t.y, t.z)
		}
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isWorldCoord(f float32, minV, maxV float32) bool {
	if f != f { return false } // NaN
	if math.IsInf(float64(f), 0) { return false }
	return f >= minV && f <= maxV
}

func abs(f float32) float32 {
	if f < 0 { return -f }
	return f
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

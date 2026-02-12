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

	fmt.Println("=== Analyzing sequence numbers and looking for player IDs ===\n")

	// Pattern: 83 00 00 00 62 73 85 fe [4 bytes seq] 5e 00 00 00 00 00 00 00 [12 bytes xyz]
	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}
	suffix := []byte{0x5e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	type position struct {
		offset     int
		seq        uint32
		x, y, z    float32
		before16   []byte // 16 bytes before the marker
		after12    []byte // 12 bytes after XYZ
	}

	var positions []position

	for i := 16; i <= len(data)-44; i++ {
		// Check for marker
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

		// Check for suffix at offset +12 (marker=8, seq=4, suffix=8)
		suffixOff := i + 8 + 4
		for j, b := range suffix {
			if data[suffixOff+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}

		// Read sequence number
		seq := binary.LittleEndian.Uint32(data[i+8:])

		// Read position floats (at offset +20 from start)
		floatOff := i + 20
		x := readFloat(data[floatOff:])
		y := readFloat(data[floatOff+4:])
		z := readFloat(data[floatOff+8:])

		// Get context bytes
		before := make([]byte, 16)
		copy(before, data[i-16:i])
		
		after := make([]byte, 12)
		if floatOff+12+12 <= len(data) {
			copy(after, data[floatOff+12:floatOff+24])
		}

		if isValidCoord(x) && isValidCoord(y) && isValidCoord(z) {
			positions = append(positions, position{i, seq, x, y, z, before, after})
		}
	}

	fmt.Printf("Found %d position packets\n\n", len(positions))

	// Sort by sequence number
	sort.Slice(positions, func(i, j int) bool {
		return positions[i].seq < positions[j].seq
	})

	// Analyze sequence numbers
	if len(positions) > 0 {
		minSeq := positions[0].seq
		maxSeq := positions[len(positions)-1].seq
		seqRange := maxSeq - minSeq

		fmt.Printf("Sequence number range: 0x%08X to 0x%08X (range: %d)\n", minSeq, maxSeq, seqRange)
		fmt.Printf("If round is ~180 seconds, tick rate ≈ %.1f ticks/sec\n", float64(seqRange)/180.0)
		fmt.Printf("If 60 ticks/sec, round duration ≈ %.1f seconds\n\n", float64(seqRange)/60.0)
	}

	// Analyze the 16 bytes BEFORE marker for potential player IDs
	fmt.Println("=== Analyzing bytes BEFORE marker for player IDs ===")
	
	// Group by the bytes at specific offsets before marker
	// Looking for a field that varies (player ID) while others stay constant
	
	// Check bytes at offset -4 to -1 (4 bytes before marker)
	idCounts := make(map[string][]position)
	for _, p := range positions {
		// Try different potential ID locations
		// -4 to -1: 4 bytes immediately before marker
		id4 := hex.EncodeToString(p.before16[12:16])
		idCounts[id4] = append(idCounts[id4], p)
	}

	fmt.Printf("\nUnique 4-byte values at offset -4 (just before marker): %d\n", len(idCounts))
	
	// Show top IDs by count
	type idInfo struct {
		id    string
		count int
		positions []position
	}
	var sortedIDs []idInfo
	for id, posns := range idCounts {
		sortedIDs = append(sortedIDs, idInfo{id, len(posns), posns})
	}
	sort.Slice(sortedIDs, func(i, j int) bool {
		return sortedIDs[i].count > sortedIDs[j].count
	})

	fmt.Println("\nTop 15 IDs (4 bytes before marker):")
	for i := 0; i < min(15, len(sortedIDs)); i++ {
		info := sortedIDs[i]
		fmt.Printf("  ID %s: %d positions\n", info.id, info.count)
		
		// Show coordinate spread for this ID
		if len(info.positions) > 0 {
			var xs, ys, zs []float32
			for _, p := range info.positions {
				xs = append(xs, p.x)
				ys = append(ys, p.y)
				zs = append(zs, p.z)
			}
			fmt.Printf("    X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
				minFloat(xs), maxFloat(xs), minFloat(ys), maxFloat(ys), minFloat(zs), maxFloat(zs))
		}
	}

	// Also try 8 bytes before
	fmt.Println("\n=== Trying 8 bytes before marker ===")
	id8Counts := make(map[string]int)
	for _, p := range positions {
		id8 := hex.EncodeToString(p.before16[8:16])
		id8Counts[id8]++
	}
	fmt.Printf("Unique 8-byte values: %d\n", len(id8Counts))

	// Show first 10 positions with full context
	fmt.Println("\n=== First 10 positions with context ===")
	for i := 0; i < min(10, len(positions)); i++ {
		p := positions[i]
		fmt.Printf("\n#%d Seq=0x%08X @ offset 0x%06X\n", i+1, p.seq, p.offset)
		fmt.Printf("  Before: %s\n", hex.EncodeToString(p.before16))
		fmt.Printf("  Coords: (%.2f, %.2f, %.2f)\n", p.x, p.y, p.z)
		fmt.Printf("  After:  %s\n", hex.EncodeToString(p.after12))
	}

	// Check if positions at similar seq numbers have different "IDs"
	fmt.Println("\n=== Checking if multiple players at same time ===")
	seqGroups := make(map[uint32][]position)
	for _, p := range positions {
		// Group by sequence number (same tick = same time)
		seqGroups[p.seq] = append(seqGroups[p.seq], p)
	}
	
	multiPlayerTicks := 0
	for seq, posns := range seqGroups {
		if len(posns) > 1 {
			multiPlayerTicks++
			if multiPlayerTicks <= 5 {
				fmt.Printf("\nSeq 0x%08X has %d positions:\n", seq, len(posns))
				for _, p := range posns {
					id4 := hex.EncodeToString(p.before16[12:16])
					fmt.Printf("  ID=%s: (%.2f, %.2f, %.2f)\n", id4, p.x, p.y, p.z)
				}
			}
		}
	}
	fmt.Printf("\nTotal ticks with multiple positions: %d (out of %d unique ticks)\n", multiPlayerTicks, len(seqGroups))
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isValidCoord(f float32) bool {
	if f != f {
		return false
	}
	if math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -200 && f <= 200
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(fs []float32) float32 {
	m := fs[0]
	for _, f := range fs {
		if f < m {
			m = f
		}
	}
	return m
}

func maxFloat(fs []float32) float32 {
	m := fs[0]
	for _, f := range fs {
		if f > m {
			m = f
		}
	}
	return m
}

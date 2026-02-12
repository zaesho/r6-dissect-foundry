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
	data, err := os.ReadFile("samplefiles/R01_dump.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Extracting player positions from 607385fe packets ===\n")

	// Full pattern: 00 00 60 73 85 fe [type 2 bytes]
	// Then coords follow
	
	baseMarker := []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	
	type packet struct {
		offset    int
		typeBytes []byte
		x, y, z   float32
	}
	
	var packets []packet
	
	for i := 0; i <= len(data)-24; i++ {
		match := true
		for j, b := range baseMarker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		typeB := make([]byte, 2)
		copy(typeB, data[i+6:i+8])
		
		// Find coords - they should be at a fixed offset after the type
		// Try +8 from marker start (= +2 from type bytes)
		for off := 8; off <= 20; off += 4 {
			if i+off+12 > len(data) {
				continue
			}
			
			x := readFloat(data[i+off:])
			y := readFloat(data[i+off+4:])
			z := readFloat(data[i+off+8:])
			
			// World coord check - broader range for Chalet
			if isWorldCoord(x) && isWorldCoord(y) && isWorldCoord(z) {
				// At least one significant value
				if abs(x) > 2 || abs(y) > 2 || abs(z) > 0.5 {
					packets = append(packets, packet{i, typeB, x, y, z})
					break
				}
			}
		}
	}
	
	fmt.Printf("Found %d packets with 0000607385fe + coords\n\n", len(packets))

	// Group by type
	byType := make(map[string][]packet)
	for _, p := range packets {
		key := hex.EncodeToString(p.typeBytes)
		byType[key] = append(byType[key], p)
	}
	
	// Sort by count
	type typeInfo struct {
		typeHex string
		pkts    []packet
	}
	var types []typeInfo
	for t, pkts := range byType {
		types = append(types, typeInfo{t, pkts})
	}
	sort.Slice(types, func(i, j int) bool {
		return len(types[i].pkts) > len(types[j].pkts)
	})
	
	fmt.Printf("Found %d unique packet types\n\n", len(types))
	
	// Show types with enough packets to be player data
	fmt.Println("Packet types (candidates for player movement):")
	
	playerIdx := 0
	for _, t := range types {
		if len(t.pkts) < 100 {
			continue // Skip low-count types
		}
		
		var xs, ys, zs []float32
		for _, p := range t.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		xRange := maxF(xs) - minF(xs)
		yRange := maxF(ys) - minF(ys)
		zRange := maxF(zs) - minF(zs)
		
		fmt.Printf("\n[Player %d?] Type '%s': %d positions\n", playerIdx, t.typeHex, len(t.pkts))
		fmt.Printf("  X: %.1f to %.1f (range: %.1f)\n", minF(xs), maxF(xs), xRange)
		fmt.Printf("  Y: %.1f to %.1f (range: %.1f)\n", minF(ys), maxF(ys), yRange)
		fmt.Printf("  Z: %.1f to %.1f (range: %.1f)\n", minF(zs), maxF(zs), zRange)
		
		// Show first 5 positions
		fmt.Println("  First 5 positions:")
		for j := 0; j < min(5, len(t.pkts)); j++ {
			p := t.pkts[j]
			fmt.Printf("    @ 0x%06X: (%.2f, %.2f, %.2f)\n", p.offset, p.x, p.y, p.z)
		}
		
		playerIdx++
	}

	// Total player-like types
	playerCount := 0
	totalPositions := 0
	for _, t := range types {
		if len(t.pkts) >= 100 {
			playerCount++
			totalPositions += len(t.pkts)
		}
	}
	
	fmt.Printf("\n\n=== Summary ===\n")
	fmt.Printf("Player-like packet types (100+ positions): %d\n", playerCount)
	fmt.Printf("Total positions in player types: %d\n", totalPositions)
	fmt.Printf("Average positions per player: %d\n", totalPositions/max(playerCount, 1))

	// Now let's output in a format suitable for parsing
	fmt.Println("\n=== Machine-readable type mapping ===")
	for idx, t := range types {
		if len(t.pkts) >= 100 {
			fmt.Printf("PLAYER_%d=0x%s # %d positions\n", idx, t.typeHex, len(t.pkts))
		}
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isWorldCoord(f float32) bool {
	if f != f { return false }
	if math.IsInf(float64(f), 0) { return false }
	return f >= -100 && f <= 100
}

func abs(f float32) float32 {
	if f < 0 { return -f }
	return f
}

func minF(fs []float32) float32 {
	if len(fs) == 0 { return 0 }
	m := fs[0]
	for _, f := range fs { if f < m { m = f } }
	return m
}

func maxF(fs []float32) float32 {
	if len(fs) == 0 { return 0 }
	m := fs[0]
	for _, f := range fs { if f > m { m = f } }
	return m
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

func max(a, b int) int {
	if a > b { return a }
	return b
}

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func main() {
	data, err := os.ReadFile("samplefiles/R01_dump.bin")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Analyzing 143-byte packet structure ===\n")

	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}

	var packets [][]byte
	
	for i := 0; i <= len(data)-143; i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			pkt := make([]byte, 143)
			copy(pkt, data[i:i+143])
			packets = append(packets, pkt)
		}
	}

	fmt.Printf("Found %d packets\n\n", len(packets))

	// Analyze structure by finding which bytes vary vs stay constant
	fmt.Println("=== Byte variability analysis ===")
	
	varCount := make([]int, 143)
	for i := 0; i < 143; i++ {
		seen := make(map[byte]bool)
		for _, pkt := range packets {
			seen[pkt[i]] = true
		}
		varCount[i] = len(seen)
	}
	
	// Print variability map
	fmt.Println("Variability (unique values per offset):")
	for row := 0; row < 9; row++ {
		start := row * 16
		end := min(start+16, 143)
		fmt.Printf("%03d: ", start)
		for i := start; i < end; i++ {
			if varCount[i] == 1 {
				fmt.Print("=  ") // Constant
			} else if varCount[i] < 10 {
				fmt.Printf("%d  ", varCount[i])
			} else if varCount[i] < 100 {
				fmt.Printf("%d ", varCount[i])
			} else {
				fmt.Print("*  ") // Highly variable
			}
		}
		fmt.Println()
	}

	// Now look for float values at various offsets
	fmt.Println("\n=== Looking for float coordinates at different offsets ===")
	
	// Known: coords at offset 20 (after marker+seq+suffix)
	// But let's check all offsets for float patterns
	
	type floatStats struct {
		offset    int
		minVal    float32
		maxVal    float32
		hasNormal bool // looks like -1 to 1 range
		hasWorld  bool // looks like world coords
	}
	
	var stats []floatStats
	
	for off := 0; off <= 139; off += 4 {
		var minV, maxV float32 = math.MaxFloat32, -math.MaxFloat32
		validCount := 0
		normalCount := 0
		worldCount := 0
		
		for _, pkt := range packets {
			f := readFloat(pkt[off:])
			if f == f && !math.IsInf(float64(f), 0) && abs(f) < 10000 {
				validCount++
				if f < minV { minV = f }
				if f > maxV { maxV = f }
				if f >= -1.1 && f <= 1.1 { normalCount++ }
				if abs(f) > 5 && abs(f) < 200 { worldCount++ }
			}
		}
		
		if validCount > len(packets)/2 { // At least half are valid floats
			stats = append(stats, floatStats{
				off, minV, maxV,
				float64(normalCount)/float64(validCount) > 0.9,
				float64(worldCount)/float64(validCount) > 0.5,
			})
		}
	}
	
	fmt.Println("\nFloat offsets with world-like coordinates:")
	for _, s := range stats {
		if s.hasWorld {
			fmt.Printf("  Offset %3d: %.2f to %.2f\n", s.offset, s.minVal, s.maxVal)
		}
	}
	
	fmt.Println("\nFloat offsets with normalized values (-1 to 1):")
	for _, s := range stats {
		if s.hasNormal {
			fmt.Printf("  Offset %3d: %.2f to %.2f\n", s.offset, s.minVal, s.maxVal)
		}
	}

	// Look at the first few complete packets
	fmt.Println("\n\n=== First 5 packet dumps ===")
	
	for i := 0; i < min(5, len(packets)); i++ {
		pkt := packets[i]
		
		fmt.Printf("\n--- Packet %d ---\n", i+1)
		
		// Dump in rows of 16 bytes
		for row := 0; row < 9; row++ {
			start := row * 16
			end := min(start+16, 143)
			fmt.Printf("%03d: %s\n", start, hex.EncodeToString(pkt[start:end]))
		}
		
		// Parse known fields
		seq := binary.LittleEndian.Uint32(pkt[8:12])
		entityID := pkt[12]
		x := readFloat(pkt[20:24])
		y := readFloat(pkt[24:28])
		z := readFloat(pkt[28:32])
		
		fmt.Printf("\nParsed: seq=0x%08X entity=0x%02X pos=(%.2f, %.2f, %.2f)\n", seq, entityID, x, y, z)
		
		// Check for additional float triplets
		fmt.Println("Other potential position triplets:")
		for off := 32; off <= 131; off += 12 {
			fx := readFloat(pkt[off:])
			fy := readFloat(pkt[off+4:])
			fz := readFloat(pkt[off+8:])
			
			// Check if looks like coords
			if isValidFloat(fx) && isValidFloat(fy) && isValidFloat(fz) {
				if (abs(fx) > 1 || abs(fy) > 1) && abs(fx) < 200 && abs(fy) < 200 && abs(fz) < 50 {
					fmt.Printf("  Offset %3d: (%.2f, %.2f, %.2f)\n", off, fx, fy, fz)
				}
			}
		}
	}
	
	// Check if there's a pattern of coordinates at specific offset appearing to be OTHER players
	fmt.Println("\n\n=== Checking offset 32-44 for second position ===")
	
	type positionPair struct {
		pos1 [3]float32
		pos2 [3]float32
	}
	
	var pairs []positionPair
	for _, pkt := range packets {
		x1 := readFloat(pkt[20:24])
		y1 := readFloat(pkt[24:28])
		z1 := readFloat(pkt[28:32])
		
		x2 := readFloat(pkt[32:36])
		y2 := readFloat(pkt[36:40])
		z2 := readFloat(pkt[40:44])
		
		if isWorldCoord(x1, y1, z1) && isValidFloat(x2) && isValidFloat(y2) && isValidFloat(z2) {
			pairs = append(pairs, positionPair{
				[3]float32{x1, y1, z1},
				[3]float32{x2, y2, z2},
			})
		}
	}
	
	fmt.Printf("Valid pairs: %d\n", len(pairs))
	
	if len(pairs) > 0 {
		// Check if pos2 looks like world coords or something else
		worldLike := 0
		normalized := 0
		for _, p := range pairs {
			if isWorldCoord(p.pos2[0], p.pos2[1], p.pos2[2]) {
				worldLike++
			}
			if abs(p.pos2[0]) <= 1 && abs(p.pos2[1]) <= 1 && abs(p.pos2[2]) <= 1 {
				normalized++
			}
		}
		fmt.Printf("  Pos2 world-like: %d (%.1f%%)\n", worldLike, float64(worldLike)/float64(len(pairs))*100)
		fmt.Printf("  Pos2 normalized: %d (%.1f%%)\n", normalized, float64(normalized)/float64(len(pairs))*100)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isValidFloat(f float32) bool {
	return f == f && !math.IsInf(float64(f), 0) && abs(f) < 10000
}

func isWorldCoord(x, y, z float32) bool {
	return abs(x) < 200 && abs(y) < 200 && abs(z) < 50 && (abs(x) > 1 || abs(y) > 1)
}

func abs(f float32) float32 {
	if f < 0 { return -f }
	return f
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

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

	fmt.Println("=== Analyzing 607385fe player position packets ===\n")

	// Pattern: 60 73 85 fe [2-byte type] ... [positions]
	// Type might indicate player ID
	
	marker := []byte{0x60, 0x73, 0x85, 0xfe}
	
	type packet struct {
		offset    int
		typeBytes []byte // 2 bytes after marker
		x, y, z   float32
		allBytes  []byte
	}
	
	var packets []packet
	
	for i := 0; i <= len(data)-40; i++ {
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
		
		typeB := make([]byte, 2)
		copy(typeB, data[i+4:i+6])
		
		all := make([]byte, 36)
		copy(all, data[i:min(i+36, len(data))])
		
		// Try to find coords at offset +8, +12, +16, +20
		for off := 8; off <= 24; off += 4 {
			if i+off+12 > len(data) {
				continue
			}
			
			x := readFloat(data[i+off:])
			y := readFloat(data[i+off+4:])
			z := readFloat(data[i+off+8:])
			
			// Check for Chalet world coords with significant values
			if x > -100 && x < 50 && y > -40 && y < 30 && z > -5 && z < 10 {
				sigCount := 0
				if abs(x) > 2 { sigCount++ }
				if abs(y) > 2 { sigCount++ }
				if abs(z) > 0.5 { sigCount++ }
				
				if sigCount >= 2 {
					packets = append(packets, packet{i, typeB, x, y, z, all})
					break
				}
			}
		}
	}
	
	fmt.Printf("Found %d packets with 607385fe + valid world coords\n\n", len(packets))

	// Group by type bytes
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
	
	fmt.Printf("Found %d unique type bytes\n\n", len(types))
	fmt.Println("Types with most packets:")
	
	for i := 0; i < min(20, len(types)); i++ {
		t := types[i]
		
		var xs, ys, zs []float32
		for _, p := range t.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		fmt.Printf("\nType '%s': %d packets\n", t.typeHex, len(t.pkts))
		fmt.Printf("  X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
			minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
		
		// Check if this looks like one player (limited spatial range on Z)
		zRange := maxF(zs) - minF(zs)
		if zRange < 5 {
			fmt.Printf("  [Possible single player - Z range only %.1f]\n", zRange)
		}
		
		// Show first 3 examples
		for j := 0; j < min(3, len(t.pkts)); j++ {
			p := t.pkts[j]
			fmt.Printf("  @ 0x%06X: (%.2f, %.2f, %.2f)\n", p.offset, p.x, p.y, p.z)
		}
	}

	// Now let's look at the second byte specifically - might be player index
	fmt.Println("\n\n=== Grouping by second byte of type (potential player ID) ===")
	
	bySecondByte := make(map[byte][]packet)
	for _, p := range packets {
		if len(p.typeBytes) >= 2 {
			key := p.typeBytes[1]
			bySecondByte[key] = append(bySecondByte[key], p)
		}
	}
	
	var secondBytes []struct {
		val  byte
		pkts []packet
	}
	for val, pkts := range bySecondByte {
		secondBytes = append(secondBytes, struct {
			val  byte
			pkts []packet
		}{val, pkts})
	}
	sort.Slice(secondBytes, func(i, j int) bool {
		return len(secondBytes[i].pkts) > len(secondBytes[j].pkts)
	})
	
	for _, sb := range secondBytes {
		if len(sb.pkts) < 50 {
			continue
		}
		
		var xs, ys, zs []float32
		for _, p := range sb.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		fmt.Printf("\nSecond byte 0x%02X: %d packets\n", sb.val, len(sb.pkts))
		fmt.Printf("  X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
			minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
	}

	// Let's try the FIRST byte - might be more interesting
	fmt.Println("\n\n=== Grouping by first byte of type ===")
	
	byFirstByte := make(map[byte][]packet)
	for _, p := range packets {
		if len(p.typeBytes) >= 1 {
			key := p.typeBytes[0]
			byFirstByte[key] = append(byFirstByte[key], p)
		}
	}
	
	var firstBytes []struct {
		val  byte
		pkts []packet
	}
	for val, pkts := range byFirstByte {
		firstBytes = append(firstBytes, struct {
			val  byte
			pkts []packet
		}{val, pkts})
	}
	sort.Slice(firstBytes, func(i, j int) bool {
		return len(firstBytes[i].pkts) > len(firstBytes[j].pkts)
	})
	
	for _, fb := range firstBytes {
		if len(fb.pkts) < 50 {
			continue
		}
		
		var xs, ys, zs []float32
		for _, p := range fb.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		fmt.Printf("\nFirst byte 0x%02X: %d packets\n", fb.val, len(fb.pkts))
		fmt.Printf("  X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
			minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
		
		zRange := maxF(zs) - minF(zs)
		if zRange < 6 && len(fb.pkts) > 200 {
			fmt.Printf("  ** LIKELY SINGLE PLAYER (Z range %.1f, %d positions) **\n", zRange, len(fb.pkts))
		}
	}

	// Summary table
	fmt.Println("\n\n=== Summary: Potential Player Movement Data ===")
	fmt.Println("First byte | Count | X range | Y range | Z range")
	fmt.Println("-----------|-------|---------|---------|--------")
	
	for _, fb := range firstBytes {
		if len(fb.pkts) < 100 {
			continue
		}
		
		var xs, ys, zs []float32
		for _, p := range fb.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		xRange := maxF(xs) - minF(xs)
		yRange := maxF(ys) - minF(ys)
		zRange := maxF(zs) - minF(zs)
		
		player := ""
		if zRange < 6 {
			player = " <-- PLAYER?"
		}
		
		fmt.Printf("    0x%02X   | %5d | %6.1f  | %6.1f  | %5.1f%s\n", 
			fb.val, len(fb.pkts), xRange, yRange, zRange, player)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
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

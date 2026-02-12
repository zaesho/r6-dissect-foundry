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

	fmt.Println("=== Analyzing '60 73 85 fe' packets for player positions ===\n")

	pattern := []byte{0x60, 0x73, 0x85, 0xfe}
	
	type packet struct {
		offset   int
		after4   []byte  // 4 bytes after pattern (potential player ID?)
		after8   []byte  // 8 bytes after pattern
		allBytes []byte  // Full packet context
		x, y, z  float32
		coordOff int     // Offset where coords were found
	}
	
	var packets []packet
	
	for i := 0; i <= len(data)-50; i++ {
		match := true
		for j, b := range pattern {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		// Read context bytes
		after4 := make([]byte, 4)
		copy(after4, data[i+4:i+8])
		
		after8 := make([]byte, 8)
		copy(after8, data[i+4:i+12])
		
		allBytes := make([]byte, 40)
		copy(allBytes, data[i:min(i+40, len(data))])
		
		// Find coords - try different offsets
		for off := 8; off <= 24; off += 4 {
			if i+off+12 > len(data) {
				continue
			}
			
			x := readFloat(data[i+off:])
			y := readFloat(data[i+off+4:])
			z := readFloat(data[i+off+8:])
			
			if isWorldCoord(x, -100, 100) && isWorldCoord(y, -50, 50) && isWorldCoord(z, -10, 20) {
				if abs(x) > 2 || abs(y) > 2 {
					packets = append(packets, packet{i, after4, after8, allBytes, x, y, z, off})
					break
				}
			}
		}
	}
	
	fmt.Printf("Found %d packets with '60 73 85 fe' + valid coords\n\n", len(packets))

	// Group by the 4 bytes after pattern (potential player identifier)
	byAfter4 := make(map[string][]packet)
	for _, p := range packets {
		key := hex.EncodeToString(p.after4)
		byAfter4[key] = append(byAfter4[key], p)
	}
	
	fmt.Printf("Unique 4-byte identifiers after pattern: %d\n\n", len(byAfter4))
	
	// Sort by count
	type idInfo struct {
		id   string
		pkts []packet
	}
	var ids []idInfo
	for id, pkts := range byAfter4 {
		ids = append(ids, idInfo{id, pkts})
	}
	sort.Slice(ids, func(i, j int) bool {
		return len(ids[i].pkts) > len(ids[j].pkts)
	})
	
	// Show top groups
	fmt.Println("Top identifier groups:")
	for i := 0; i < min(15, len(ids)); i++ {
		info := ids[i]
		
		// Get coordinate range
		var xs, ys, zs []float32
		for _, p := range info.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		fmt.Printf("\n  ID '%s': %d packets\n", info.id, len(info.pkts))
		fmt.Printf("    X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
			minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
		
		// Show first 3 examples
		for j := 0; j < min(3, len(info.pkts)); j++ {
			p := info.pkts[j]
			fmt.Printf("    @ 0x%06X: (%.2f, %.2f, %.2f) coordOff=%d\n", p.offset, p.x, p.y, p.z, p.coordOff)
		}
	}

	// Now let's try grouping by 2 bytes after pattern (smaller ID)
	fmt.Println("\n\n=== Grouping by 2 bytes after pattern ===")
	
	byAfter2 := make(map[string][]packet)
	for _, p := range packets {
		key := hex.EncodeToString(p.after4[:2])
		byAfter2[key] = append(byAfter2[key], p)
	}
	
	fmt.Printf("Unique 2-byte identifiers: %d\n\n", len(byAfter2))
	
	var ids2 []idInfo
	for id, pkts := range byAfter2 {
		ids2 = append(ids2, idInfo{id, pkts})
	}
	sort.Slice(ids2, func(i, j int) bool {
		return len(ids2[i].pkts) > len(ids2[j].pkts)
	})
	
	fmt.Println("Top 2-byte identifier groups:")
	for i := 0; i < min(15, len(ids2)); i++ {
		info := ids2[i]
		var xs, ys, zs []float32
		for _, p := range info.pkts {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		fmt.Printf("\n  ID '%s': %d packets\n", info.id, len(info.pkts))
		fmt.Printf("    X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
			minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
	}

	// Check the byte at offset +5 (after 60 73 85 fe XX) - might be player index
	fmt.Println("\n\n=== Checking byte at offset +5 (potential player index) ===")
	
	byByte5 := make(map[byte][]packet)
	for _, p := range packets {
		if len(p.after8) >= 2 {
			key := p.after8[1] // Second byte of after8 = offset +5
			byByte5[key] = append(byByte5[key], p)
		}
	}
	
	fmt.Printf("Unique values at offset +5: %d\n", len(byByte5))
	
	type byteInfo struct {
		val  byte
		pkts []packet
	}
	var bytes5 []byteInfo
	for val, pkts := range byByte5 {
		bytes5 = append(bytes5, byteInfo{val, pkts})
	}
	sort.Slice(bytes5, func(i, j int) bool {
		return len(bytes5[i].pkts) > len(bytes5[j].pkts)
	})
	
	for i := 0; i < min(15, len(bytes5)); i++ {
		info := bytes5[i]
		fmt.Printf("  Byte 0x%02X (%d): %d packets\n", info.val, info.val, len(info.pkts))
	}

	// Let's look at the structure more carefully
	fmt.Println("\n\n=== Detailed structure analysis ===")
	fmt.Println("Looking at first 20 packets:")
	
	for i := 0; i < min(20, len(packets)); i++ {
		p := packets[i]
		fmt.Printf("\n  @ 0x%06X:\n", p.offset)
		fmt.Printf("    Full: %s\n", hex.EncodeToString(p.allBytes))
		fmt.Printf("    Coords: (%.2f, %.2f, %.2f) at offset +%d\n", p.x, p.y, p.z, p.coordOff)
		
		// Parse some fields
		byte4 := p.allBytes[4]  // First byte after pattern
		byte5 := p.allBytes[5]  // Second byte after pattern
		fmt.Printf("    Bytes after pattern: %02X %02X\n", byte4, byte5)
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isWorldCoord(f, minV, maxV float32) bool {
	if f != f { return false }
	if math.IsInf(float64(f), 0) { return false }
	return f >= minV && f <= maxV
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

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

	fmt.Println("=== Analyzing '85fe' patterns for per-player positions ===\n")

	// We found that 607385fe appears in position clusters
	// And headers like 85feb001, 85fec001, 85feb801 have many positions
	// The 85fe seems to be a key marker
	
	// Let's find all instances of "XX 73 85 fe" where XX varies
	// This might be a per-player variant
	
	type packet struct {
		offset   int
		prefix   byte // byte before 73 85 fe
		suffix   []byte
		coords   [3]float32
	}
	
	var packets []packet
	
	for i := 1; i <= len(data)-30; i++ {
		// Check for 73 85 fe
		if data[i] != 0x73 || data[i+1] != 0x85 || data[i+2] != 0xfe {
			continue
		}
		
		prefix := data[i-1]
		
		// Read bytes after the marker
		suffix := make([]byte, 20)
		copy(suffix, data[i+3:i+23])
		
		// Try to find coordinates at various offsets
		for off := 5; off <= 17; off++ {
			if i+3+off+12 > len(data) {
				continue
			}
			
			x := readFloat(data[i+3+off:])
			y := readFloat(data[i+3+off+4:])
			z := readFloat(data[i+3+off+8:])
			
			if isWorldCoord(x, -100, 100) && isWorldCoord(y, -50, 50) && isWorldCoord(z, -10, 20) {
				if abs(x) > 3 || abs(y) > 3 {
					packets = append(packets, packet{i, prefix, suffix, [3]float32{x, y, z}})
					break
				}
			}
		}
	}
	
	fmt.Printf("Found %d packets with '?? 73 85 fe' + valid coords\n\n", len(packets))
	
	// Group by prefix byte
	byPrefix := make(map[byte][]packet)
	for _, p := range packets {
		byPrefix[p.prefix] = append(byPrefix[p.prefix], p)
	}
	
	// Sort by count
	type prefixInfo struct {
		prefix byte
		pkts   []packet
	}
	var prefixes []prefixInfo
	for prefix, pkts := range byPrefix {
		prefixes = append(prefixes, prefixInfo{prefix, pkts})
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i].pkts) > len(prefixes[j].pkts)
	})
	
	fmt.Println("Packets grouped by prefix byte:")
	for _, p := range prefixes {
		fmt.Printf("\n  Prefix 0x%02X: %d packets\n", p.prefix, len(p.pkts))
		
		// Show coordinate spread
		var xs, ys, zs []float32
		for _, pkt := range p.pkts {
			xs = append(xs, pkt.coords[0])
			ys = append(ys, pkt.coords[1])
			zs = append(zs, pkt.coords[2])
		}
		fmt.Printf("    X: %.1f to %.1f\n", minF(xs), maxF(xs))
		fmt.Printf("    Y: %.1f to %.1f\n", minF(ys), maxF(ys))
		fmt.Printf("    Z: %.1f to %.1f\n", minF(zs), maxF(zs))
		
		// Show first 3 examples
		for i := 0; i < min(3, len(p.pkts)); i++ {
			pkt := p.pkts[i]
			fmt.Printf("    @ 0x%06X: (%.2f, %.2f, %.2f)\n", pkt.offset, pkt.coords[0], pkt.coords[1], pkt.coords[2])
			fmt.Printf("      suffix: %s\n", hex.EncodeToString(pkt.suffix[:12]))
		}
	}

	// Now let's look at the specific pattern from the clusters
	// Pattern seen: 607385fe followed by more structure
	fmt.Println("\n\n=== Analyzing '60 73 85 fe' pattern specifically ===")
	
	pattern60 := []byte{0x60, 0x73, 0x85, 0xfe}
	
	type packet60 struct {
		offset   int
		context  []byte // 32 bytes starting from pattern
		coords   [][3]float32
	}
	
	var packets60 []packet60
	
	for i := 0; i <= len(data)-50; i++ {
		match := true
		for j, b := range pattern60 {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		ctx := make([]byte, 48)
		copy(ctx, data[i:min(i+48, len(data))])
		
		// Find all valid coordinate triplets in this region
		var coords [][3]float32
		for off := 4; off <= 36; off += 4 {
			if i+off+12 > len(data) {
				break
			}
			x := readFloat(data[i+off:])
			y := readFloat(data[i+off+4:])
			z := readFloat(data[i+off+8:])
			
			if isWorldCoord(x, -100, 100) && isWorldCoord(y, -50, 50) && isWorldCoord(z, -10, 20) {
				if abs(x) > 3 || abs(y) > 3 {
					coords = append(coords, [3]float32{x, y, z})
				}
			}
		}
		
		if len(coords) > 0 {
			packets60 = append(packets60, packet60{i, ctx, coords})
		}
	}
	
	fmt.Printf("Found %d instances of '60 73 85 fe' with valid coords\n\n", len(packets60))
	
	// Show some examples
	fmt.Println("First 10 examples:")
	for i := 0; i < min(10, len(packets60)); i++ {
		p := packets60[i]
		fmt.Printf("\n  @ 0x%06X:\n", p.offset)
		fmt.Printf("    Hex: %s\n", hex.EncodeToString(p.context[:32]))
		fmt.Printf("    Coords found: %d\n", len(p.coords))
		for j, c := range p.coords {
			fmt.Printf("      %d: (%.2f, %.2f, %.2f)\n", j, c[0], c[1], c[2])
		}
	}

	// Let's also check if there are MULTIPLE 607385fe in sequence (one per player)
	fmt.Println("\n\n=== Looking for sequential '60 73 85 fe' patterns ===")
	
	var offsets60 []int
	for i := 0; i <= len(data)-4; i++ {
		if data[i] == 0x60 && data[i+1] == 0x73 && data[i+2] == 0x85 && data[i+3] == 0xfe {
			offsets60 = append(offsets60, i)
		}
	}
	
	fmt.Printf("Total '60 73 85 fe' occurrences: %d\n", len(offsets60))
	
	// Check distances between consecutive occurrences
	if len(offsets60) > 1 {
		distCounts := make(map[int]int)
		for i := 1; i < len(offsets60); i++ {
			dist := offsets60[i] - offsets60[i-1]
			if dist <= 200 { // Only small distances (same packet block)
				distCounts[dist]++
			}
		}
		
		fmt.Println("\nDistances between consecutive patterns (<=200 bytes):")
		type distInfo struct {
			dist, count int
		}
		var dists []distInfo
		for d, c := range distCounts {
			if c >= 10 {
				dists = append(dists, distInfo{d, c})
			}
		}
		sort.Slice(dists, func(i, j int) bool {
			return dists[i].count > dists[j].count
		})
		
		for i := 0; i < min(15, len(dists)); i++ {
			fmt.Printf("  %d bytes apart: %d times\n", dists[i].dist, dists[i].count)
		}
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

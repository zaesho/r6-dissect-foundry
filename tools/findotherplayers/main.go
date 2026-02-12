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

	fmt.Println("=== Looking for player position packet patterns ===\n")

	// We know 83 00 00 00 62 73 85 fe works for the POV player
	// Let's look for similar patterns that might be used for other players
	
	// First, find all instances of "62 73 85 fe" (the unique part of our marker)
	// and see what comes before it
	
	subMarker := []byte{0x62, 0x73, 0x85, 0xfe}
	
	type markerInstance struct {
		offset    int
		prefix4   []byte
		followsBy []byte
	}
	
	var instances []markerInstance
	
	for i := 4; i <= len(data)-len(subMarker)-40; i++ {
		match := true
		for j, b := range subMarker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		prefix := make([]byte, 4)
		copy(prefix, data[i-4:i])
		
		follows := make([]byte, 20)
		copy(follows, data[i+4:i+24])
		
		instances = append(instances, markerInstance{i, prefix, follows})
	}
	
	fmt.Printf("Found %d instances of '62 73 85 fe'\n\n", len(instances))
	
	// Group by prefix (the 4 bytes before)
	prefixCounts := make(map[string]int)
	for _, inst := range instances {
		key := hex.EncodeToString(inst.prefix4)
		prefixCounts[key]++
	}
	
	fmt.Println("Prefixes before '62 73 85 fe':")
	type prefixInfo struct {
		prefix string
		count  int
	}
	var prefixes []prefixInfo
	for p, c := range prefixCounts {
		prefixes = append(prefixes, prefixInfo{p, c})
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].count > prefixes[j].count
	})
	for _, p := range prefixes {
		fmt.Printf("  %s: %d\n", p.prefix, p.count)
	}

	// Now let's look for patterns that have MULTIPLE players' positions in sequence
	// If there are packets for 10 players, they might be grouped together
	
	fmt.Println("\n\n=== Looking for grouped player position patterns ===")
	
	// Search for sequences where we see the marker repeated with small offsets
	// suggesting multiple players in one packet group
	
	mainMarker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}
	
	var markerOffsets []int
	for i := 0; i <= len(data)-len(mainMarker); i++ {
		match := true
		for j, b := range mainMarker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			markerOffsets = append(markerOffsets, i)
		}
	}
	
	fmt.Printf("\nFound %d total marker instances\n", len(markerOffsets))
	
	// Check distances between consecutive markers
	if len(markerOffsets) > 1 {
		distCounts := make(map[int]int)
		for i := 1; i < len(markerOffsets); i++ {
			dist := markerOffsets[i] - markerOffsets[i-1]
			distCounts[dist]++
		}
		
		fmt.Println("\nDistances between consecutive markers:")
		type distInfo struct {
			dist  int
			count int
		}
		var dists []distInfo
		for d, c := range distCounts {
			if c >= 5 { // Only show common distances
				dists = append(dists, distInfo{d, c})
			}
		}
		sort.Slice(dists, func(i, j int) bool {
			return dists[i].count > dists[j].count
		})
		for i := 0; i < min(20, len(dists)); i++ {
			fmt.Printf("  %d bytes: %d times\n", dists[i].dist, dists[i].count)
		}
	}

	// Now let's look for a completely different packet type
	// Search for patterns: [small int 0-9] followed by coordinates
	
	fmt.Println("\n\n=== Looking for player index + coordinates patterns ===")
	
	// The player index in R6 is usually 0-9 for 10 players
	// Look for: [byte 0-9] [padding?] [float] [float] [float]
	
	type indexedPosition struct {
		offset    int
		playerIdx byte
		x, y, z   float32
		context   []byte
	}
	
	var indexedPositions []indexedPosition
	
	for i := 16; i <= len(data)-20; i++ {
		// Check if byte could be player index
		idx := data[i]
		if idx > 9 {
			continue
		}
		
		// Try different offsets for the coordinates
		for coordOff := 4; coordOff <= 12; coordOff += 4 {
			if i+coordOff+12 > len(data) {
				continue
			}
			
			x := readFloat(data[i+coordOff:])
			y := readFloat(data[i+coordOff+4:])
			z := readFloat(data[i+coordOff+8:])
			
			// Check if Chalet-like coordinates
			if x >= -100 && x <= 50 && y >= -50 && y <= 30 && z >= -5 && z <= 15 {
				// Additional sanity check - not all near zero
				if abs(x) > 5 || abs(y) > 5 {
					ctx := make([]byte, 16)
					copy(ctx, data[i:i+16])
					indexedPositions = append(indexedPositions, indexedPosition{
						i, idx, x, y, z, ctx,
					})
				}
			}
		}
	}
	
	fmt.Printf("Found %d potential indexed positions\n", len(indexedPositions))
	
	// Group by player index
	byIdx := make(map[byte]int)
	for _, ip := range indexedPositions {
		byIdx[ip.playerIdx]++
	}
	
	fmt.Println("By player index:")
	for idx := byte(0); idx <= 9; idx++ {
		if count, ok := byIdx[idx]; ok {
			fmt.Printf("  Player %d: %d positions\n", idx, count)
		}
	}
	
	// Group by first 4 bytes (to find common packet type markers)
	packetTypes := make(map[string][]indexedPosition)
	for _, ip := range indexedPositions {
		key := hex.EncodeToString(ip.context[:4])
		packetTypes[key] = append(packetTypes[key], ip)
	}
	
	fmt.Println("\nPacket types with indexed positions (50+ occurrences):")
	type ptInfo struct {
		packetType string
		positions  []indexedPosition
	}
	var pts []ptInfo
	for pt, pos := range packetTypes {
		if len(pos) >= 50 {
			pts = append(pts, ptInfo{pt, pos})
		}
	}
	sort.Slice(pts, func(i, j int) bool {
		return len(pts[i].positions) > len(pts[j].positions)
	})
	
	for i := 0; i < min(10, len(pts)); i++ {
		pt := pts[i]
		fmt.Printf("\n  Type %s: %d positions\n", pt.packetType, len(pt.positions))
		
		// Count by player index for this type
		idxCounts := make(map[byte]int)
		for _, p := range pt.positions {
			idxCounts[p.playerIdx]++
		}
		fmt.Printf("    By index: ")
		for idx := byte(0); idx <= 9; idx++ {
			if c, ok := idxCounts[idx]; ok {
				fmt.Printf("%d:%d ", idx, c)
			}
		}
		fmt.Println()
		
		// Show first example
		if len(pt.positions) > 0 {
			p := pt.positions[0]
			fmt.Printf("    Example @ 0x%06X: idx=%d (%.2f, %.2f, %.2f)\n", 
				p.offset, p.playerIdx, p.x, p.y, p.z)
			fmt.Printf("    Context: %s\n", hex.EncodeToString(p.context))
		}
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func abs(f float32) float32 {
	if f < 0 { return -f }
	return f
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

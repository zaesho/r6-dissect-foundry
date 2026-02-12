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

	fmt.Println("=== Searching for ALL player position packets (Spectator Mode) ===\n")
	fmt.Println("The 1700+ positions are likely the spectator CAMERA.")
	fmt.Println("Player positions should be in a DIFFERENT packet format.\n")

	// Strategy: Look for repeated patterns that contain multiple float triplets
	// Spectator replays should have position updates for all visible players
	
	// First, let's look for patterns containing player indices 0-9
	// R6 uses small indices for players
	
	fmt.Println("=== Looking for packets with small indices (0-9) followed by floats ===")
	
	type playerPosCandidate struct {
		offset    int
		playerIdx byte
		x, y, z   float32
		context   []byte
	}
	
	var candidates []playerPosCandidate
	
	// Look for: [index 0-9] [possible padding] [X float] [Y float] [Z float]
	// Try various padding sizes
	
	for i := 0; i <= len(data)-20; i++ {
		idx := data[i]
		if idx > 9 {
			continue
		}
		
		// Try offset +1, +2, +4, +8 for coordinates
		for padding := 1; padding <= 12; padding++ {
			coordStart := i + padding
			if coordStart+12 > len(data) {
				continue
			}
			
			x := readFloat(data[coordStart:])
			y := readFloat(data[coordStart+4:])
			z := readFloat(data[coordStart+8:])
			
			// Check for Chalet-like world coordinates
			if isWorldCoord(x, -100, 50) && isWorldCoord(y, -30, 30) && isWorldCoord(z, -5, 10) {
				if abs(x) > 3 || abs(y) > 3 { // Significant position
					ctx := make([]byte, 20)
					if i >= 4 {
						copy(ctx, data[i-4:i+16])
					}
					candidates = append(candidates, playerPosCandidate{i, idx, x, y, z, ctx})
				}
			}
		}
	}
	
	fmt.Printf("Found %d candidates with player index 0-9 + world coords\n\n", len(candidates))
	
	// Group by player index
	byPlayer := make(map[byte][]playerPosCandidate)
	for _, c := range candidates {
		byPlayer[c.playerIdx] = append(byPlayer[c.playerIdx], c)
	}
	
	fmt.Println("Candidates by player index:")
	for idx := byte(0); idx <= 9; idx++ {
		if cands, ok := byPlayer[idx]; ok {
			fmt.Printf("  Player %d: %d candidates\n", idx, len(cands))
		}
	}

	// Now let's look for a DIFFERENT approach:
	// Find patterns that appear 10x per "tick" (one for each player)
	
	fmt.Println("\n\n=== Looking for repeated packet patterns (10 players) ===")
	
	// Find all unique 4-byte sequences and count them
	fourBytePatterns := make(map[string]int)
	for i := 0; i <= len(data)-4; i++ {
		key := hex.EncodeToString(data[i : i+4])
		fourBytePatterns[key]++
	}
	
	// Look for patterns that appear many times (could be per-player packet headers)
	type patternInfo struct {
		pattern string
		count   int
	}
	var patterns []patternInfo
	for p, c := range fourBytePatterns {
		if c >= 1000 && c <= 50000 { // Reasonable range for per-player updates
			patterns = append(patterns, patternInfo{p, c})
		}
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].count > patterns[j].count
	})
	
	fmt.Println("High-frequency 4-byte patterns (1000-50000 occurrences):")
	for i := 0; i < min(20, len(patterns)); i++ {
		p := patterns[i]
		fmt.Printf("  %s: %d times\n", p.pattern, p.count)
	}

	// Let's look specifically for position-like data NEAR player count patterns
	fmt.Println("\n\n=== Analyzing packets near '0a000000' (10 players marker) ===")
	
	tenMarker := []byte{0x0a, 0x00, 0x00, 0x00}
	
	var nearTenMarker []int
	for i := 0; i <= len(data)-len(tenMarker); i++ {
		match := true
		for j, b := range tenMarker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			nearTenMarker = append(nearTenMarker, i)
		}
	}
	
	fmt.Printf("Found %d instances of '0a000000'\n", len(nearTenMarker))
	
	// Check context around first few
	for i := 0; i < min(5, len(nearTenMarker)); i++ {
		off := nearTenMarker[i]
		fmt.Printf("\n  @ 0x%06X:\n", off)
		
		// Look for floats nearby
		for delta := 4; delta <= 100; delta += 4 {
			if off+delta+12 > len(data) {
				break
			}
			x := readFloat(data[off+delta:])
			y := readFloat(data[off+delta+4:])
			z := readFloat(data[off+delta+8:])
			
			if isWorldCoord(x, -100, 50) && isWorldCoord(y, -30, 30) && isWorldCoord(z, -5, 10) {
				if abs(x) > 3 || abs(y) > 3 {
					fmt.Printf("    +%d: (%.2f, %.2f, %.2f)\n", delta, x, y, z)
				}
			}
		}
	}

	// Let's look for a completely different pattern:
	// Search for blocks that contain MULTIPLE position triplets close together
	fmt.Println("\n\n=== Looking for position CLUSTERS (multiple players in one packet) ===")
	
	type posCluster struct {
		offset    int
		positions [][3]float32
	}
	
	var clusters []posCluster
	
	// Scan for regions with multiple valid position triplets
	for i := 0; i <= len(data)-120; i += 4 {
		var positionsInWindow [][3]float32
		
		for j := 0; j < 120; j += 12 {
			if i+j+12 > len(data) {
				break
			}
			x := readFloat(data[i+j:])
			y := readFloat(data[i+j+4:])
			z := readFloat(data[i+j+8:])
			
			if isWorldCoord(x, -100, 50) && isWorldCoord(y, -30, 30) && isWorldCoord(z, -5, 10) {
				if abs(x) > 3 || abs(y) > 3 {
					positionsInWindow = append(positionsInWindow, [3]float32{x, y, z})
				}
			}
		}
		
		// If we found 5+ positions in a 120-byte window, this might be a player position block
		if len(positionsInWindow) >= 5 {
			clusters = append(clusters, posCluster{i, positionsInWindow})
			i += 120 // Skip ahead to avoid overlap
		}
	}
	
	fmt.Printf("Found %d position clusters (5+ positions in 120 bytes)\n", len(clusters))
	
	if len(clusters) > 0 {
		fmt.Println("\nFirst 5 clusters:")
		for i := 0; i < min(5, len(clusters)); i++ {
			c := clusters[i]
			fmt.Printf("\n  Cluster @ 0x%06X with %d positions:\n", c.offset, len(c.positions))
			for j, pos := range c.positions {
				fmt.Printf("    %d: (%.2f, %.2f, %.2f)\n", j, pos[0], pos[1], pos[2])
			}
			// Show hex dump
			end := min(c.offset+120, len(data))
			fmt.Printf("    Hex: %s\n", hex.EncodeToString(data[c.offset:end]))
		}
	}

	// Look for DissectID patterns - these are unique player identifiers
	fmt.Println("\n\n=== Looking for DissectID-based position packets ===")
	
	// DissectIDs are typically 4-byte values in the format we've seen in headers
	// Let's search for patterns where a 4-byte ID is followed by position data
	
	// First find potential DissectIDs by looking for 4-byte values that repeat
	// exactly 10 times per "update" (once per player)
	
	fmt.Println("Searching for position data with identifiable structure...")
	
	// Try to find position update blocks by looking for sequences where
	// the same "header" bytes appear with different coordinate values
	
	// Look for the pattern: [constant bytes] [varying floats]
	type blockPattern struct {
		header string
		count  int
		coords []struct {
			offset int
			x, y, z float32
		}
	}
	
	headerToCoords := make(map[string]*blockPattern)
	
	for i := 8; i <= len(data)-20; i++ {
		// Try 4-byte header before potential coordinates
		header := hex.EncodeToString(data[i-4 : i])
		
		x := readFloat(data[i:])
		y := readFloat(data[i+4:])
		z := readFloat(data[i+8:])
		
		if isWorldCoord(x, -100, 50) && isWorldCoord(y, -30, 30) && isWorldCoord(z, -5, 10) {
			if abs(x) > 3 || abs(y) > 3 {
				if _, exists := headerToCoords[header]; !exists {
					headerToCoords[header] = &blockPattern{header: header}
				}
				bp := headerToCoords[header]
				bp.count++
				if len(bp.coords) < 5 {
					bp.coords = append(bp.coords, struct {
						offset int
						x, y, z float32
					}{i, x, y, z})
				}
			}
		}
	}
	
	// Find headers that appear many times (consistent packet type)
	var goodHeaders []blockPattern
	for _, bp := range headerToCoords {
		if bp.count >= 100 && bp.count <= 5000 {
			goodHeaders = append(goodHeaders, *bp)
		}
	}
	sort.Slice(goodHeaders, func(i, j int) bool {
		return goodHeaders[i].count > goodHeaders[j].count
	})
	
	fmt.Printf("\nFound %d header patterns with 100-5000 position instances:\n", len(goodHeaders))
	for i := 0; i < min(10, len(goodHeaders)); i++ {
		h := goodHeaders[i]
		fmt.Printf("\n  Header '%s': %d positions\n", h.header, h.count)
		for _, c := range h.coords {
			fmt.Printf("    @ 0x%06X: (%.2f, %.2f, %.2f)\n", c.offset, c.x, c.y, c.z)
		}
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isWorldCoord(f, minV, maxV float32) bool {
	if f != f {
		return false
	}
	if math.IsInf(float64(f), 0) {
		return false
	}
	return f >= minV && f <= maxV
}

func abs(f float32) float32 {
	if f < 0 {
		return -f
	}
	return f
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

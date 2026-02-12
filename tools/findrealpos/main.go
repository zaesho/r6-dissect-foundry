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

	fmt.Println("=== Finding REAL player positions (all 3 coords non-trivial) ===\n")

	// Look for float triplets where ALL THREE values are significant
	// (not just one axis)
	
	type position struct {
		offset  int
		x, y, z float32
		context []byte
	}
	
	var positions []position
	
	for i := 16; i <= len(data)-12; i += 4 {
		x := readFloat(data[i:])
		y := readFloat(data[i+4:])
		z := readFloat(data[i+8:])
		
		// All three must be valid and significant
		if !isValid(x) || !isValid(y) || !isValid(z) {
			continue
		}
		
		// Chalet-like bounds
		if x < -100 || x > 50 || y < -40 || y > 30 || z < -5 || z > 10 {
			continue
		}
		
		// At least TWO coords must be > 2 (real movement, not just up/down)
		significant := 0
		if abs(x) > 2 { significant++ }
		if abs(y) > 2 { significant++ }
		if abs(z) > 0.5 { significant++ }
		
		if significant < 2 {
			continue
		}
		
		ctx := make([]byte, 16)
		copy(ctx, data[i-16:i])
		
		positions = append(positions, position{i, x, y, z, ctx})
	}
	
	fmt.Printf("Found %d positions with significant X, Y, and Z\n\n", len(positions))

	// Group by 8 bytes before coords (packet header)
	byHeader := make(map[string][]position)
	for _, p := range positions {
		key := hex.EncodeToString(p.context[8:16])
		byHeader[key] = append(byHeader[key], p)
	}
	
	fmt.Printf("Unique 8-byte headers: %d\n\n", len(byHeader))
	
	// Sort by count
	type headerInfo struct {
		header string
		pos    []position
	}
	var headers []headerInfo
	for h, p := range byHeader {
		if len(p) >= 50 { // Need at least 50 instances
			headers = append(headers, headerInfo{h, p})
		}
	}
	sort.Slice(headers, func(i, j int) bool {
		return len(headers[i].pos) > len(headers[j].pos)
	})
	
	fmt.Printf("Headers with 50+ positions: %d\n\n", len(headers))
	
	for i := 0; i < min(15, len(headers)); i++ {
		h := headers[i]
		
		var xs, ys, zs []float32
		for _, p := range h.pos {
			xs = append(xs, p.x)
			ys = append(ys, p.y)
			zs = append(zs, p.z)
		}
		
		fmt.Printf("\nHeader '%s': %d positions\n", h.header, len(h.pos))
		fmt.Printf("  X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
			minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
		
		// Show first 5 examples
		for j := 0; j < min(5, len(h.pos)); j++ {
			p := h.pos[j]
			fmt.Printf("  @ 0x%06X: (%.2f, %.2f, %.2f)\n", p.offset, p.x, p.y, p.z)
		}
	}

	// Now let's specifically look at positions near our known marker 627385fe
	// These are the spectator camera positions - what's the full structure?
	fmt.Println("\n\n=== Looking at 627385fe (spectator camera) structure ===")
	
	marker62 := []byte{0x62, 0x73, 0x85, 0xfe}
	
	type pkt62 struct {
		offset  int
		after40 []byte
		x, y, z float32
	}
	
	var packets62 []pkt62
	
	for i := 0; i <= len(data)-50; i++ {
		match := true
		for j, b := range marker62 {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		
		after := make([]byte, 40)
		copy(after, data[i+4:min(i+44, len(data))])
		
		// Coords at offset +16 (4+12 = marker + seq + suffix)
		x := readFloat(data[i+16:])
		y := readFloat(data[i+20:])
		z := readFloat(data[i+24:])
		
		if isValid(x) && isValid(y) && isValid(z) {
			if x > -100 && x < 50 && y > -40 && y < 30 && z > -5 && z < 10 {
				packets62 = append(packets62, pkt62{i, after, x, y, z})
			}
		}
	}
	
	fmt.Printf("Found %d valid 627385fe packets\n", len(packets62))
	
	// Show a few examples
	for i := 0; i < min(5, len(packets62)); i++ {
		p := packets62[i]
		fmt.Printf("\n@ 0x%06X: (%.2f, %.2f, %.2f)\n", p.offset, p.x, p.y, p.z)
		fmt.Printf("  After marker: %s\n", hex.EncodeToString(p.after40[:24]))
	}

	// Check if there are multiple position blocks (10 players) near each other
	fmt.Println("\n\n=== Looking for 10-player position blocks ===")
	
	// Find all positions with significant coords
	type sigPos struct {
		offset  int
		x, y, z float32
	}
	
	var sigPositions []sigPos
	for _, p := range positions {
		sigPositions = append(sigPositions, sigPos{p.offset, p.x, p.y, p.z})
	}
	
	// Sort by offset
	sort.Slice(sigPositions, func(i, j int) bool {
		return sigPositions[i].offset < sigPositions[j].offset
	})
	
	// Look for clusters of 10 positions close together
	for i := 0; i < len(sigPositions)-10; i++ {
		// Check if next 9 positions are within 200 bytes
		clusterEnd := sigPositions[i+9].offset
		clusterStart := sigPositions[i].offset
		
		if clusterEnd-clusterStart < 300 {
			// Found a cluster!
			fmt.Printf("\nCluster at 0x%06X (span: %d bytes):\n", clusterStart, clusterEnd-clusterStart)
			for j := 0; j < 10; j++ {
				p := sigPositions[i+j]
				fmt.Printf("  %d: @ 0x%06X (%.2f, %.2f, %.2f)\n", j, p.offset, p.x, p.y, p.z)
			}
			
			// Show hex context
			if clusterEnd+20 <= len(data) {
				fmt.Printf("  Hex: %s\n", hex.EncodeToString(data[clusterStart:min(clusterEnd+20, len(data))]))
			}
			
			i += 9 // Skip this cluster
			
			if i > 50 { // Just show first few clusters
				break
			}
		}
	}
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isValid(f float32) bool {
	return f == f && !math.IsInf(float64(f), 0) && abs(f) < 10000
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

package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// Ignore the "player ID" field entirely
// Look at positions and try to cluster them to find 10 players
// If there are 10 players moving around, we should see ~10 distinct
// position sequences in small time windows

type posPacket struct {
	packetNum int
	x, y, z   float32
}

var packets []posPacket
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePos)
	r.Read()

	fmt.Printf("Total position packets: %d\n\n", len(packets))

	// Take time windows and count distinct positions
	// If all 10 players have roughly equal updates, each window should have
	// position updates for ~10 different locations
	
	windowSize := 100
	fmt.Printf("=== Distinct positions per %d-packet window ===\n\n", windowSize)
	
	for windowStart := 0; windowStart+windowSize <= len(packets) && windowStart < 2000; windowStart += windowSize {
		// Count distinct positions (rounded to 1 decimal)
		posSet := make(map[string]int)
		
		for i := windowStart; i < windowStart+windowSize; i++ {
			p := packets[i]
			key := fmt.Sprintf("%.1f,%.1f", p.x, p.y)
			posSet[key]++
		}
		
		fmt.Printf("Window %4d-%4d: %2d distinct XY positions\n", windowStart, windowStart+windowSize, len(posSet))
	}

	// Now let's look at the FULL replay and cluster all positions
	// to see how many distinct "tracks" exist
	fmt.Printf("\n=== Position clustering analysis ===\n\n")
	
	// Grid-based approach: divide the map into cells and count unique cells visited
	cellSize := float32(2.0) // 2 unit cells
	cellCounts := make(map[string]int)
	
	for _, p := range packets {
		cellX := int(p.x / cellSize)
		cellY := int(p.y / cellSize)
		key := fmt.Sprintf("%d,%d", cellX, cellY)
		cellCounts[key]++
	}
	
	fmt.Printf("Total unique cells visited: %d\n", len(cellCounts))
	
	// Show most visited cells
	type cellCount struct {
		cell  string
		count int
	}
	var cells []cellCount
	for c, n := range cellCounts {
		cells = append(cells, cellCount{c, n})
	}
	sort.Slice(cells, func(i, j int) bool {
		return cells[i].count > cells[j].count
	})
	
	fmt.Printf("\nTop 20 most visited cells:\n")
	for i := 0; i < 20 && i < len(cells); i++ {
		fmt.Printf("  %s: %d packets\n", cells[i].cell, cells[i].count)
	}

	// Look at position sequences - track "movement vectors"
	fmt.Printf("\n=== Movement vector analysis ===\n\n")
	
	// For consecutive packets, calculate movement direction
	// If multiple players are being tracked, we should see movements
	// that don't make sense as a single entity (teleporting)
	
	teleports := 0
	smallMoves := 0
	totalMoves := len(packets) - 1
	
	for i := 1; i < len(packets); i++ {
		dx := packets[i].x - packets[i-1].x
		dy := packets[i].y - packets[i-1].y
		dist := math.Sqrt(float64(dx*dx + dy*dy))
		
		if dist > 5.0 {
			teleports++
		} else if dist > 0.01 {
			smallMoves++
		}
	}
	
	fmt.Printf("Total position transitions: %d\n", totalMoves)
	fmt.Printf("Teleports (>5 units): %d (%.1f%%)\n", teleports, float64(teleports)/float64(totalMoves)*100)
	fmt.Printf("Small moves (0.01-5 units): %d (%.1f%%)\n", smallMoves, float64(smallMoves)/float64(totalMoves)*100)
	fmt.Printf("Static (<=0.01 units): %d (%.1f%%)\n", totalMoves-teleports-smallMoves, float64(totalMoves-teleports-smallMoves)/float64(totalMoves)*100)
	
	// The teleport percentage tells us roughly how interleaved the updates are
	// If 10 players are updating in round-robin, we'd expect ~90% teleports
	// If 1 player updates many times before another, we'd expect fewer teleports
}

func capturePos(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	// Only B803 (most common position packet)
	if typeBytes[0] != 0xB8 || typeBytes[1] != 0x03 {
		return nil
	}

	x, err := r.Float32()
	if err != nil {
		return nil
	}
	y, err := r.Float32()
	if err != nil {
		return nil
	}
	z, err := r.Float32()
	if err != nil {
		return nil
	}

	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) {
		return nil
	}
	
	// Basic bounds check
	if x < -100 || x > 100 || y < -100 || y > 100 {
		return nil
	}

	packets = append(packets, posPacket{
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

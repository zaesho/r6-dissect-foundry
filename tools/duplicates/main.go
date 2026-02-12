package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type positionRecord struct {
	typeCode  uint16
	packetNum int
	x, y, z   float32
}

var positions []positionRecord
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePosition)
	r.Read()

	fmt.Printf("Captured %d positions\n\n", len(positions))

	// Group by type
	byType := make(map[uint16][]positionRecord)
	for _, p := range positions {
		byType[p.typeCode] = append(byType[p.typeCode], p)
	}

	// For each type, analyze sequential duplicates
	fmt.Printf("=== Duplicate analysis per type ===\n")
	for tc, ps := range byType {
		// Sort by packet number
		sort.Slice(ps, func(i, j int) bool {
			return ps[i].packetNum < ps[j].packetNum
		})

		// Count exact duplicates (same position) and near-duplicates
		exactDups := 0
		nearDups := 0
		uniquePositions := make(map[string]bool)
		
		for i := 1; i < len(ps); i++ {
			// Check if exact same position as previous
			if ps[i].x == ps[i-1].x && ps[i].y == ps[i-1].y && ps[i].z == ps[i-1].z {
				exactDups++
			}
			
			// Check if very close to previous
			dx := ps[i].x - ps[i-1].x
			dy := ps[i].y - ps[i-1].y
			if math.Sqrt(float64(dx*dx+dy*dy)) < 0.1 {
				nearDups++
			}
			
			// Track unique positions (rounded to 0.1)
			key := fmt.Sprintf("%.1f,%.1f,%.1f", ps[i].x, ps[i].y, ps[i].z)
			uniquePositions[key] = true
		}

		fmt.Printf("Type 0x%04X: %d total, %d exact dups, %d near dups, %d unique positions\n",
			tc, len(ps), exactDups, nearDups, len(uniquePositions))
	}

	// Analyze B803 specifically - look at position clustering
	fmt.Printf("\n=== B803 position clustering ===\n")
	b803 := byType[0xB803]
	if len(b803) == 0 {
		return
	}

	// Sort by time
	sort.Slice(b803, func(i, j int) bool {
		return b803[i].packetNum < b803[j].packetNum
	})

	// Look at a small time window and count distinct positions
	windowStart := b803[0].packetNum
	windowSize := 50 // packets
	
	fmt.Printf("\nPositions in first few time windows (window=%d packets):\n", windowSize)
	for w := 0; w < 10; w++ {
		start := windowStart + w*windowSize
		end := start + windowSize
		
		var windowPositions []positionRecord
		for _, p := range b803 {
			if p.packetNum >= start && p.packetNum < end {
				windowPositions = append(windowPositions, p)
			}
		}
		
		// Count distinct XY positions (rounded)
		uniqueXY := make(map[string]bool)
		for _, p := range windowPositions {
			key := fmt.Sprintf("%.0f,%.0f", p.x, p.y)
			uniqueXY[key] = true
		}
		
		fmt.Printf("  Window %d (pkt %d-%d): %d positions, %d distinct XY\n",
			w, start, end, len(windowPositions), len(uniqueXY))
		
		if w == 0 && len(windowPositions) > 0 {
			fmt.Printf("    First 10 positions:\n")
			for i := 0; i < 10 && i < len(windowPositions); i++ {
				p := windowPositions[i]
				fmt.Printf("      pkt=%d (%.2f, %.2f, %.2f)\n", p.packetNum, p.x, p.y, p.z)
			}
		}
	}

	// Check packet number gaps within B803
	fmt.Printf("\n=== B803 packet number gaps ===\n")
	gaps := make(map[int]int)
	for i := 1; i < len(b803); i++ {
		gap := b803[i].packetNum - b803[i-1].packetNum
		gaps[gap]++
	}
	
	fmt.Printf("Gap distribution (consecutive packet number differences):\n")
	type kv struct {
		gap   int
		count int
	}
	var sortedGaps []kv
	for g, c := range gaps {
		sortedGaps = append(sortedGaps, kv{g, c})
	}
	sort.Slice(sortedGaps, func(i, j int) bool {
		return sortedGaps[i].count > sortedGaps[j].count
	})
	for i := 0; i < 10 && i < len(sortedGaps); i++ {
		fmt.Printf("  Gap %d: %d occurrences\n", sortedGaps[i].gap, sortedGaps[i].count)
	}
}

func capturePosition(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	if typeBytes[1] != 0x01 && typeBytes[1] != 0x03 {
		return nil
	}
	if typeBytes[0] < 0xB0 {
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

	if x < -100 || x > 100 || y < -100 || y > 100 || z < -5 || z > 15 {
		return nil
	}

	positions = append(positions, positionRecord{
		typeCode:  typeCode,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

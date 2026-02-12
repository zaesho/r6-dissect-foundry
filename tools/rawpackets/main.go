package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type packetCapture struct {
	hasFlag  bool // 0x80000000 flag
	x, y, z  float32
	packetNum int
}

var capturedPackets []packetCapture
var packetCounter int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating reader: %v\n", err)
		os.Exit(1)
	}

	// Add custom listener for B803 packets
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xB8, 0x03}, captureB803)

	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
	}

	fmt.Printf("Captured %d B803 packets\n", len(capturedPackets))

	// Separate by flag
	var withFlag, withoutFlag []packetCapture
	for _, p := range capturedPackets {
		if p.hasFlag {
			withFlag = append(withFlag, p)
		} else {
			withoutFlag = append(withoutFlag, p)
		}
	}

	fmt.Printf("  With 0x80 flag: %d packets\n", len(withFlag))
	fmt.Printf("  Without flag: %d packets\n\n", len(withoutFlag))

	// Analyze Z distribution for each group
	fmt.Printf("Z-level distribution (WITH flag):\n")
	printZDistribution(withFlag)

	fmt.Printf("\nZ-level distribution (WITHOUT flag):\n")
	printZDistribution(withoutFlag)

	// Try to cluster positions spatially for the NO-flag group
	// This is the larger group (9193 packets)
	fmt.Printf("\nSpatial clustering for NO-flag packets:\n")
	clusterByLocation(withoutFlag)
}

func printZDistribution(packets []packetCapture) {
	byZ := make(map[int]int)
	for _, p := range packets {
		zKey := int(p.z * 10)
		byZ[zKey]++
	}
	
	type kv struct {
		k int
		v int
	}
	var sorted []kv
	for k, v := range byZ {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})
	
	for i := 0; i < 5 && i < len(sorted); i++ {
		fmt.Printf("  Z=%.1f: %d packets\n", float32(sorted[i].k)/10, sorted[i].v)
	}
}

func clusterByLocation(packets []packetCapture) {
	// Use simple grid-based clustering
	// Divide map into 5x5 unit cells
	type cell struct {
		x, y int
	}
	byCells := make(map[cell]int)
	
	for _, p := range packets {
		c := cell{int(p.x / 5), int(p.y / 5)}
		byCells[c]++
	}

	fmt.Printf("  Grid cells with >50 packets:\n")
	type kv struct {
		c cell
		v int
	}
	var sorted []kv
	for c, v := range byCells {
		if v > 50 {
			sorted = append(sorted, kv{c, v})
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})
	
	for i := 0; i < 15 && i < len(sorted); i++ {
		c := sorted[i].c
		fmt.Printf("    Cell (%d,%d) [x:%d-%d, y:%d-%d]: %d packets\n", 
			c.x, c.y, c.x*5, (c.x+1)*5, c.y*5, (c.y+1)*5, sorted[i].v)
	}
	
	// How many distinct cells?
	fmt.Printf("  Total distinct cells: %d\n", len(byCells))
	
	// The idea: if positions are from multiple players, consecutive
	// packets should jump around significantly in location
	fmt.Printf("\nAnalyzing consecutive packet jumps:\n")
	jumpDist := make([]float32, 0)
	for i := 1; i < len(packets) && i < 1000; i++ {
		dx := packets[i].x - packets[i-1].x
		dy := packets[i].y - packets[i-1].y
		dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
		jumpDist = append(jumpDist, dist)
	}
	
	// Count jumps by size
	smallJumps := 0  // < 1 unit
	mediumJumps := 0 // 1-5 units
	largeJumps := 0  // > 5 units
	
	for _, d := range jumpDist {
		if d < 1 {
			smallJumps++
		} else if d < 5 {
			mediumJumps++
		} else {
			largeJumps++
		}
	}
	
	fmt.Printf("  Small jumps (<1 unit): %d (%.1f%%)\n", smallJumps, float64(smallJumps)/float64(len(jumpDist))*100)
	fmt.Printf("  Medium jumps (1-5 units): %d (%.1f%%)\n", mediumJumps, float64(mediumJumps)/float64(len(jumpDist))*100)
	fmt.Printf("  Large jumps (>5 units): %d (%.1f%%)\n", largeJumps, float64(largeJumps)/float64(len(jumpDist))*100)
	
	// If most jumps are large, it's because we're cycling through multiple players
	// If most jumps are small, positions are sequential for the same player
}

func captureB803(r *dissect.Reader) error {
	packetCounter++
	
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

	if !isValid(x) || !isValid(y) || z < -5 || z > 15 {
		return nil
	}

	// Read next 8 bytes
	after, err := r.Bytes(8)
	if err != nil {
		return nil
	}

	after8 := binary.LittleEndian.Uint32(after[4:8])
	hasFlag := after8 == 0x80000000

	capturedPackets = append(capturedPackets, packetCapture{
		hasFlag:   hasFlag,
		x:         x,
		y:         y,
		z:         z,
		packetNum: packetCounter,
	})

	return nil
}

func isValid(f float32) bool {
	return !math.IsNaN(float64(f)) && f >= -100 && f <= 100
}

package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

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

	r.EnableMovementTracking(1)

	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
		os.Exit(1)
	}

	// Get B803 positions
	const B803 = 47107 // 0xB803
	pm, exists := r.PlayerMovements[B803]
	if !exists {
		fmt.Println("B803 not found!")
		return
	}

	fmt.Printf("B803 has %d positions\n\n", len(pm.Positions))

	// Simple clustering: group positions that are close together spatially
	// Use DBSCAN-like approach: positions within 2 units are same player
	type cluster struct {
		positions []dissect.PlayerPosition
		centroidX float32
		centroidY float32
	}

	// Take a time slice (first 5 seconds worth of positions)
	// At ~131 positions/sec, that's ~655 positions
	sampleSize := 1000
	if sampleSize > len(pm.Positions) {
		sampleSize = len(pm.Positions)
	}

	// For each position, find nearby positions at the same time
	// Group by Z coordinate first (floor level)
	byZ := make(map[int][]dissect.PlayerPosition)
	for i := 0; i < sampleSize; i++ {
		pos := pm.Positions[i]
		zKey := int(pos.Z * 10) // Round to 0.1 precision
		byZ[zKey] = append(byZ[zKey], pos)
	}

	fmt.Printf("Z-level distribution (first %d positions):\n", sampleSize)
	type zCount struct {
		z     int
		count int
	}
	var zCounts []zCount
	for z, positions := range byZ {
		zCounts = append(zCounts, zCount{z, len(positions)})
	}
	sort.Slice(zCounts, func(i, j int) bool {
		return zCounts[i].count > zCounts[j].count
	})
	for i := 0; i < 10 && i < len(zCounts); i++ {
		fmt.Printf("  Z=%.1f: %d positions\n", float32(zCounts[i].z)/10, zCounts[i].count)
	}

	// Now try to cluster by position at same-ish time
	// Sort positions by time
	sortedPos := make([]dissect.PlayerPosition, len(pm.Positions))
	copy(sortedPos, pm.Positions)
	sort.Slice(sortedPos, func(i, j int) bool {
		return sortedPos[i].TimeInSeconds < sortedPos[j].TimeInSeconds
	})

	// Look at positions at similar times (within 0.1 seconds)
	fmt.Printf("\nPosition clusters at same timestamps:\n")
	
	// Group by rounded time
	byTime := make(map[int][]dissect.PlayerPosition)
	for _, pos := range sortedPos[:sampleSize] {
		timeKey := int(pos.TimeInSeconds * 10) // 0.1 sec precision
		byTime[timeKey] = append(byTime[timeKey], pos)
	}

	// Show time buckets with multiple positions
	multiPosCount := 0
	maxPositionsAtSameTime := 0
	for _, positions := range byTime {
		if len(positions) > 1 {
			multiPosCount++
			if len(positions) > maxPositionsAtSameTime {
				maxPositionsAtSameTime = len(positions)
			}
		}
	}
	fmt.Printf("  Time buckets with multiple positions: %d\n", multiPosCount)
	fmt.Printf("  Max positions at same time: %d\n", maxPositionsAtSameTime)

	// Show some examples of multiple positions at same time
	fmt.Printf("\nExamples of positions at same timestamp:\n")
	count := 0
	for timeKey, positions := range byTime {
		if len(positions) >= 3 && count < 5 {
			fmt.Printf("  Time %.1f: %d positions\n", float64(timeKey)/10, len(positions))
			for j, pos := range positions {
				if j < 5 {
					fmt.Printf("    (%.2f, %.2f, %.2f)\n", pos.X, pos.Y, pos.Z)
				}
			}
			if len(positions) > 5 {
				fmt.Printf("    ... and %d more\n", len(positions)-5)
			}
			count++
		}
	}

	// Try to identify distinct location clusters
	fmt.Printf("\nAttempting to identify distinct players by location clustering...\n")
	
	// Simple K-means like approach: find positions that consistently appear far apart
	// Look at position variance
	var sumX, sumY, sumZ float64
	for _, pos := range sortedPos[:sampleSize] {
		sumX += float64(pos.X)
		sumY += float64(pos.Y)
		sumZ += float64(pos.Z)
	}
	avgX := sumX / float64(sampleSize)
	avgY := sumY / float64(sampleSize)
	avgZ := sumZ / float64(sampleSize)
	
	var varX, varY float64
	for _, pos := range sortedPos[:sampleSize] {
		varX += math.Pow(float64(pos.X)-avgX, 2)
		varY += math.Pow(float64(pos.Y)-avgY, 2)
	}
	varX /= float64(sampleSize)
	varY /= float64(sampleSize)
	
	fmt.Printf("  Average position: (%.2f, %.2f, %.2f)\n", avgX, avgY, avgZ)
	fmt.Printf("  Variance X: %.2f, Y: %.2f\n", varX, varY)
	fmt.Printf("  Std Dev X: %.2f, Y: %.2f\n", math.Sqrt(varX), math.Sqrt(varY))
}

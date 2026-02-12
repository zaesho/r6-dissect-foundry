package main

import (
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type posRecord struct {
	typeCode  uint16
	packetNum int
	x, y, z   float32
}

var positions []posRecord
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

	// Capture only B803 (most common 03-type)
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xB8, 0x03}, captureB803)
	r.Read()

	fmt.Printf("Captured %d B803 positions\n\n", len(positions))

	// Deduplicate consecutive identical positions
	var deduped []posRecord
	for i, p := range positions {
		if i == 0 || p.x != positions[i-1].x || p.y != positions[i-1].y {
			deduped = append(deduped, p)
		}
	}
	fmt.Printf("After dedup: %d positions\n\n", len(deduped))

	// Sort by packet number
	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].packetNum < deduped[j].packetNum
	})

	// Check if positions cycle through N distinct locations
	// If there are 10 players, every ~10 consecutive positions should hit ~10 different locations
	fmt.Printf("=== Checking for round-robin pattern ===\n")
	
	windowSizes := []int{5, 10, 15, 20}
	
	for _, ws := range windowSizes {
		totalDistinct := 0
		windows := 0
		
		for i := 0; i+ws <= len(deduped); i += ws {
			uniqueXY := make(map[string]bool)
			for j := i; j < i+ws; j++ {
				key := fmt.Sprintf("%.0f,%.0f", deduped[j].x, deduped[j].y)
				uniqueXY[key] = true
			}
			totalDistinct += len(uniqueXY)
			windows++
		}
		
		avgDistinct := float64(totalDistinct) / float64(windows)
		fmt.Printf("  Window size %d: avg %.1f distinct positions per window\n", ws, avgDistinct)
	}

	// Analyze the cycle pattern more directly
	// Look at how positions repeat over time
	fmt.Printf("\n=== Position repetition analysis ===\n")
	
	// For each distinct XY, count how often it appears and what the spacing is
	type xyInfo struct {
		x, y        float32
		occurrences []int // packet numbers where this XY appears
	}
	
	xyMap := make(map[string]*xyInfo)
	for _, p := range deduped {
		key := fmt.Sprintf("%.1f,%.1f", p.x, p.y)
		if xyMap[key] == nil {
			xyMap[key] = &xyInfo{x: p.x, y: p.y}
		}
		xyMap[key].occurrences = append(xyMap[key].occurrences, p.packetNum)
	}

	// Find positions that appear many times
	type kv struct {
		key  string
		info *xyInfo
	}
	var sorted []kv
	for k, v := range xyMap {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].info.occurrences) > len(sorted[j].info.occurrences)
	})

	fmt.Printf("Top 10 most common positions:\n")
	for i := 0; i < 10 && i < len(sorted); i++ {
		info := sorted[i].info
		fmt.Printf("  (%.1f, %.1f): %d times\n", info.x, info.y, len(info.occurrences))
		
		// Calculate average spacing
		if len(info.occurrences) > 1 {
			var totalSpacing int
			for j := 1; j < len(info.occurrences); j++ {
				totalSpacing += info.occurrences[j] - info.occurrences[j-1]
			}
			avgSpacing := float64(totalSpacing) / float64(len(info.occurrences)-1)
			fmt.Printf("    Avg spacing: %.1f packets\n", avgSpacing)
		}
	}

	// Now let's try to identify players by tracking position continuity
	fmt.Printf("\n=== Tracking distinct entities ===\n")
	
	// At each moment, group positions that are close together spatially
	// across consecutive packet windows
	
	// Take first 1000 positions and try to identify distinct movement tracks
	sample := deduped
	if len(sample) > 2000 {
		sample = sample[:2000]
	}

	// Simple K-means style clustering: assume 10 players
	// Initialize with first 10 distinct positions
	numClusters := 10
	type cluster struct {
		centerX, centerY float32
		positions        []posRecord
	}
	clusters := make([]cluster, numClusters)

	// Find first 10 distinct positions as seeds
	seeds := make(map[string]bool)
	seedIdx := 0
	for _, p := range sample {
		key := fmt.Sprintf("%.0f,%.0f", p.x, p.y)
		if !seeds[key] && seedIdx < numClusters {
			clusters[seedIdx].centerX = p.x
			clusters[seedIdx].centerY = p.y
			seeds[key] = true
			seedIdx++
		}
	}

	// Assign each position to nearest cluster and update center
	for iter := 0; iter < 10; iter++ {
		// Clear assignments
		for i := range clusters {
			clusters[i].positions = nil
		}
		
		// Assign each position to nearest cluster
		for _, p := range sample {
			bestCluster := 0
			bestDist := float32(math.MaxFloat32)
			
			for c := range clusters {
				dx := p.x - clusters[c].centerX
				dy := p.y - clusters[c].centerY
				dist := dx*dx + dy*dy
				if dist < bestDist {
					bestDist = dist
					bestCluster = c
				}
			}
			
			clusters[bestCluster].positions = append(clusters[bestCluster].positions, p)
		}
		
		// Update centers
		for c := range clusters {
			if len(clusters[c].positions) > 0 {
				var sumX, sumY float32
				for _, p := range clusters[c].positions {
					sumX += p.x
					sumY += p.y
				}
				clusters[c].centerX = sumX / float32(len(clusters[c].positions))
				clusters[c].centerY = sumY / float32(len(clusters[c].positions))
			}
		}
	}

	// Show cluster results
	fmt.Printf("\nClustering results (K-means with 10 clusters):\n")
	totalAssigned := 0
	for i, c := range clusters {
		fmt.Printf("  Cluster %d: %d positions, center (%.1f, %.1f)\n", 
			i+1, len(c.positions), c.centerX, c.centerY)
		totalAssigned += len(c.positions)
	}
	fmt.Printf("Total assigned: %d\n", totalAssigned)
}

func captureB803(r *dissect.Reader) error {
	packetNum++

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

	positions = append(positions, posRecord{
		typeCode:  0xB803,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

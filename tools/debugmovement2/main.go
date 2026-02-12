package main

import (
	"fmt"
	"os"

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

	// Enable movement tracking with no sampling
	r.EnableMovementTracking(1)

	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
		os.Exit(1)
	}

	// Print raw stats
	fmt.Printf("\n=== Movement Tracking Debug ===\n")
	fmt.Printf("TrackMovement: %v\n", r.TrackMovement)
	fmt.Printf("MovementSampleRate: %d\n", r.MovementSampleRate)
	fmt.Printf("Total entities in map: %d\n", len(r.PlayerMovements))
	fmt.Printf("Min seq: %d, Max seq: %d\n", r.GetMovementMinSeq(), r.GetMovementMaxSeq())

	// Print each entity
	for id, pm := range r.PlayerMovements {
		fmt.Printf("\nEntity ID: %d (%s)\n", id, pm.Username)
		fmt.Printf("  Position count: %d\n", len(pm.Positions))
		if len(pm.Positions) > 0 {
			// Show first and last 3 positions
			fmt.Printf("  First 3 positions:\n")
			for i := 0; i < 3 && i < len(pm.Positions); i++ {
				p := pm.Positions[i]
				fmt.Printf("    [%d] time=%.2f x=%.2f y=%.2f z=%.2f\n", i, p.TimeInSeconds, p.X, p.Y, p.Z)
			}
			if len(pm.Positions) > 6 {
				fmt.Printf("  ...\n")
				fmt.Printf("  Last 3 positions:\n")
				for i := len(pm.Positions) - 3; i < len(pm.Positions); i++ {
					p := pm.Positions[i]
					fmt.Printf("    [%d] time=%.2f x=%.2f y=%.2f z=%.2f\n", i, p.TimeInSeconds, p.X, p.Y, p.Z)
				}
			}
		}
	}

	// Print header player count
	fmt.Printf("\n=== Header Players ===\n")
	fmt.Printf("Player count: %d\n", len(r.Header.Players))
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (ID: %d, Team: %d)\n", i, p.Username, p.ID, p.TeamIndex)
	}
}

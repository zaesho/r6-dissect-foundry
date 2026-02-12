package main

import (
	"fmt"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: checkmarker <replay.rec>")
		os.Exit(1)
	}

	// Use the dissect library to read the replay
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

	// Enable movement tracking to see if any movement packets are found
	r.EnableMovementTracking(1)

	// Read the replay
	if err := r.Read(); err != nil {
		fmt.Printf("Error reading replay: %v\n", err)
		os.Exit(1)
	}

	// Check movement data
	movements := r.GetMovementData()
	if movements == nil || len(movements) == 0 {
		fmt.Println("No movement data found")
	} else {
		for _, m := range movements {
			fmt.Printf("Player: %s, Positions: %d\n", m.Username, len(m.Positions))
			if len(m.Positions) > 0 {
				// Show first 5 and last 5 positions
				fmt.Println("  First 5 positions:")
				for i := 0; i < min(5, len(m.Positions)); i++ {
					p := m.Positions[i]
					fmt.Printf("    %.2fs: (%.2f, %.2f, %.2f)\n", p.TimeInSeconds, p.X, p.Y, p.Z)
				}
				if len(m.Positions) > 10 {
					fmt.Println("  ...")
					fmt.Println("  Last 5 positions:")
					for i := len(m.Positions) - 5; i < len(m.Positions); i++ {
						p := m.Positions[i]
						fmt.Printf("    %.2fs: (%.2f, %.2f, %.2f)\n", p.TimeInSeconds, p.X, p.Y, p.Z)
					}
				}
			}
		}
	}

	// Print match info
	fmt.Printf("\nMap: %s\n", r.Header.Map.String())
	fmt.Printf("Site: %s\n", r.Header.Site)
	fmt.Printf("Players: %d\n", len(r.Header.Players))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

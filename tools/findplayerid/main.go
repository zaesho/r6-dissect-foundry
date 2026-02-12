package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

// Custom reader to access raw data
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

	// We need to intercept the raw data during parsing
	// Let's use a modified approach: track positions AND analyze surrounding bytes
	
	// For now, let's look at actual player count and analyze patterns
	fmt.Printf("Header players:\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}

	// The key insight: we have 10 players, but only 7-8 position types
	// Each type might have a sub-identifier for players
	
	// Let's examine B803 structure more carefully
	// The type bytes might include additional info
	fmt.Printf("\nExpected ~1100 positions per player over 85 seconds at 13Hz\n")
	fmt.Printf("B803 has 11,179 positions = ~10.2 players worth\n")
	fmt.Printf("This strongly suggests B803 contains ALL 10 players!\n\n")
	
	// The packet structure after 00 00 60 73 85 fe might be:
	// [type1][type2][X:4][Y:4][Z:4][???]
	// where ??? contains the player identifier
	
	// Let's print what we know about the patterns
	fmt.Printf("Analysis conclusion:\n")
	fmt.Printf("- Type byte (like B803) identifies packet FORMAT, not player\n")
	fmt.Printf("- Player ID is likely in bytes after coordinates\n")
	fmt.Printf("- Or possibly encoded in the 4 bytes BEFORE the marker\n")
	fmt.Printf("\nNeed to parse raw packets to find player ID field.\n")
}

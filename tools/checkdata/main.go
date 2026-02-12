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

	// Access internal buffer using reflection or exported method
	// Since we can't easily access r.b, let's track matches during Read
	
	// Enable movement tracking
	r.EnableMovementTracking(1)

	// Count how many times each listener is called
	fmt.Printf("Decompressed data size from reader logs...\n")
	
	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
		os.Exit(1)
	}

	// Print actual counts
	fmt.Printf("\nActual position counts from PlayerMovements:\n")
	for id, pm := range r.PlayerMovements {
		fmt.Printf("  ID %d (%s): %d positions\n", id, pm.Username, len(pm.Positions))
	}

	// The reader logged decompressed size - check logs above
}

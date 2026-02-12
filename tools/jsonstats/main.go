package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type PlayerPosition struct {
	TimeInSeconds float64 `json:"timeInSeconds"`
	X             float32 `json:"x"`
	Y             float32 `json:"y"`
	Z             float32 `json:"z"`
}

type PlayerMovement struct {
	Username  string           `json:"username"`
	Positions []PlayerPosition `json:"positions"`
}

type Output struct {
	Movements []PlayerMovement `json:"movements"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <movement.json>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var output Output
	if err := json.Unmarshal(data, &output); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	movements := output.Movements
	fmt.Printf("Found %d entities in movement data\n\n", len(movements))

	totalPositions := 0
	for _, m := range movements {
		totalPositions += len(m.Positions)
		
		// Calculate time span
		var minTime, maxTime float64 = 999999, -1
		for _, p := range m.Positions {
			if p.TimeInSeconds < minTime {
				minTime = p.TimeInSeconds
			}
			if p.TimeInSeconds > maxTime {
				maxTime = p.TimeInSeconds
			}
		}
		
		duration := maxTime - minTime
		rate := 0.0
		if duration > 0 {
			rate = float64(len(m.Positions)) / duration
		}
		
		fmt.Printf("%-20s: %5d positions, %.1f-%.1fs (%.1f/sec)\n", 
			m.Username, len(m.Positions), minTime, maxTime, rate)
	}
	
	fmt.Printf("\nTotal positions: %d\n", totalPositions)
}

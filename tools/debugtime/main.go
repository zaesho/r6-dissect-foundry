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

	r.EnableMovementTracking(1)

	if err := r.Read(); err != nil {
		fmt.Printf("Error reading: %v\n", err)
		os.Exit(1)
	}

	const spectatorCameraID = -1000
	cam, exists := r.PlayerMovements[spectatorCameraID]
	if !exists {
		fmt.Println("No spectator camera found!")
		return
	}

	fmt.Printf("Total spectator camera positions: %d\n\n", len(cam.Positions))

	// Do the same bucketing as GetMovementData
	buckets := make(map[int64]int)
	for _, pos := range cam.Positions {
		bucket := int64(pos.TimeInSeconds) / 1000000
		buckets[bucket]++
	}

	// Find max bucket
	var maxBucket int64
	maxCount := 0
	for bucket, count := range buckets {
		if count > maxCount {
			maxCount = count
			maxBucket = bucket
		}
	}
	fmt.Printf("Max bucket: %d with %d positions\n", maxBucket, maxCount)

	// Show all buckets with positions
	fmt.Printf("\nAll buckets:\n")
	for bucket, count := range buckets {
		if count > 0 {
			fmt.Printf("  Bucket %d: %d positions\n", bucket, count)
		}
	}

	// Calculate filter range
	clusterMin := float64((maxBucket - 1) * 1000000)
	clusterMax := float64((maxBucket + 2) * 1000000)
	fmt.Printf("\nFilter range: %.0f - %.0f\n", clusterMin, clusterMax)

	// Filter
	var validPositions []dissect.PlayerPosition
	for _, pos := range cam.Positions {
		if pos.TimeInSeconds >= clusterMin && pos.TimeInSeconds <= clusterMax {
			validPositions = append(validPositions, pos)
		}
	}
	fmt.Printf("Valid positions after filter: %d\n", len(validPositions))

	if len(validPositions) == 0 {
		return
	}

	// Find actual min/max
	actualMin := validPositions[0].TimeInSeconds
	actualMax := validPositions[0].TimeInSeconds
	for _, pos := range validPositions {
		if pos.TimeInSeconds < actualMin {
			actualMin = pos.TimeInSeconds
		}
		if pos.TimeInSeconds > actualMax {
			actualMax = pos.TimeInSeconds
		}
	}
	fmt.Printf("Actual time range: %.0f - %.0f (range: %.0f)\n", actualMin, actualMax, actualMax-actualMin)

	// Calculate as the code does
	cameraDuration := float64(len(validPositions)) / 20.0
	totalTime := 180.0
	if cameraDuration > 30 && cameraDuration < 300 {
		totalTime = cameraDuration
	}
	fmt.Printf("Camera duration: %.2f, totalTime: %.2f\n", cameraDuration, totalTime)

	seqRange := actualMax - actualMin
	tickRate := seqRange / totalTime
	fmt.Printf("Sequence range: %.0f, tick rate: %.2f\n", seqRange, tickRate)

	// Calculate expected normalized times
	normMin := (actualMin - actualMin) / tickRate
	normMax := (actualMax - actualMin) / tickRate
	fmt.Printf("Expected normalized times: %.2f - %.2f\n", normMin, normMax)
}

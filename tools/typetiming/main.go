package main

import (
	"fmt"
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

	// Sort by packet number (time)
	sort.Slice(positions, func(i, j int) bool {
		return positions[i].packetNum < positions[j].packetNum
	})

	// Analyze: at any given time window, which types appear together?
	fmt.Printf("=== Type co-occurrence analysis ===\n")
	windowSize := 100 // packets
	
	// Group positions into time windows
	type window struct {
		startPkt int
		types    map[uint16]int
	}
	
	var windows []window
	currentWindow := window{startPkt: positions[0].packetNum, types: make(map[uint16]int)}
	
	for _, p := range positions {
		if p.packetNum - currentWindow.startPkt > windowSize {
			if len(currentWindow.types) > 0 {
				windows = append(windows, currentWindow)
			}
			currentWindow = window{startPkt: p.packetNum, types: make(map[uint16]int)}
		}
		currentWindow.types[p.typeCode]++
	}
	if len(currentWindow.types) > 0 {
		windows = append(windows, currentWindow)
	}

	fmt.Printf("Total windows: %d\n\n", len(windows))

	// Count how many windows have each type
	typeWindowCount := make(map[uint16]int)
	for _, w := range windows {
		for tc := range w.types {
			typeWindowCount[tc]++
		}
	}

	fmt.Printf("Type presence across time windows:\n")
	for tc, count := range typeWindowCount {
		fmt.Printf("  Type 0x%04X: present in %d/%d windows (%.1f%%)\n", 
			tc, count, len(windows), float64(count)/float64(len(windows))*100)
	}

	// Check if different types appear at same packet numbers (same moment)
	fmt.Printf("\n=== Packets at exact same time ===\n")
	byPacketNum := make(map[int][]positionRecord)
	for _, p := range positions {
		byPacketNum[p.packetNum] = append(byPacketNum[p.packetNum], p)
	}

	// Count how many have multiple types at same packet#
	multiTypeCount := 0
	for _, ps := range byPacketNum {
		types := make(map[uint16]bool)
		for _, p := range ps {
			types[p.typeCode] = true
		}
		if len(types) > 1 {
			multiTypeCount++
		}
	}
	fmt.Printf("Packet numbers with multiple types: %d/%d\n", multiTypeCount, len(byPacketNum))

	// Show some examples of multi-type moments
	fmt.Printf("\nExamples of multi-type packets:\n")
	count := 0
	for pktNum, ps := range byPacketNum {
		types := make(map[uint16]bool)
		for _, p := range ps {
			types[p.typeCode] = true
		}
		if len(types) > 1 && count < 10 {
			fmt.Printf("  Packet %d: ", pktNum)
			for _, p := range ps {
				fmt.Printf("0x%04X(%.1f,%.1f) ", p.typeCode, p.x, p.y)
			}
			fmt.Println()
			count++
		}
	}

	// Analyze XY distributions per type
	fmt.Printf("\n=== XY distribution per type ===\n")
	for tc := range typeWindowCount {
		var sumX, sumY float64
		var count int
		for _, p := range positions {
			if p.typeCode == tc {
				sumX += float64(p.x)
				sumY += float64(p.y)
				count++
			}
		}
		if count > 100 {
			avgX := sumX / float64(count)
			avgY := sumY / float64(count)
			fmt.Printf("  Type 0x%04X: avgPos=(%.1f, %.1f), count=%d\n", tc, avgX, avgY, count)
		}
	}

	// Check if 01 and 03 variants track same entity
	fmt.Printf("\n=== Comparing 01 vs 03 variants ===\n")
	analyze0103("B0", 0xB001, 0xB003)
	analyze0103("B4", 0xB401, 0xB403)
	analyze0103("B8", 0xB801, 0xB803)
	analyze0103("BC", 0xBC01, 0xBC03)
}

func analyze0103(name string, type01, type03 uint16) {
	// Get first 100 positions of each type
	var pos01, pos03 []positionRecord
	for _, p := range positions {
		if p.typeCode == type01 && len(pos01) < 100 {
			pos01 = append(pos01, p)
		}
		if p.typeCode == type03 && len(pos03) < 100 {
			pos03 = append(pos03, p)
		}
	}

	if len(pos01) == 0 || len(pos03) == 0 {
		fmt.Printf("  %s: insufficient data (01:%d, 03:%d)\n", name, len(pos01), len(pos03))
		return
	}

	// Compare positions at similar times
	matches := 0
	for _, p1 := range pos01 {
		for _, p3 := range pos03 {
			// Similar time (within 10 packets)
			if abs(p1.packetNum-p3.packetNum) < 10 {
				// Similar position (within 2 units)
				dx := p1.x - p3.x
				dy := p1.y - p3.y
				if dx*dx+dy*dy < 4 {
					matches++
				}
			}
		}
	}
	fmt.Printf("  %s: type 0x%04X (%d) vs 0x%04X (%d), position matches near same time: %d\n",
		name, type01, len(pos01), type03, len(pos03), matches)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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

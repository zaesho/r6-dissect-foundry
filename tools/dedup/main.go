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
var lastPos positionRecord
var hasLast bool

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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePositionDedup)
	r.Read()

	fmt.Printf("Captured %d UNIQUE positions (after dedup)\n\n", len(positions))

	// Group by type
	byType := make(map[uint16][]positionRecord)
	for _, p := range positions {
		byType[p.typeCode] = append(byType[p.typeCode], p)
	}

	fmt.Printf("Unique positions per type:\n")
	for tc, ps := range byType {
		fmt.Printf("  Type 0x%04X: %d positions\n", tc, len(ps))
	}

	// Sort all by packet number
	sort.Slice(positions, func(i, j int) bool {
		return positions[i].packetNum < positions[j].packetNum
	})

	// Analyze how many distinct positions exist at each time moment
	fmt.Printf("\n=== Simultaneous positions analysis ===\n")
	
	// Group into time windows of 10 unique packets
	windowSize := 30
	
	type windowInfo struct {
		startPkt        int
		positionsTotal  int
		typeBreakdown   map[uint16]int
		distinctXY      int
	}
	var windows []windowInfo

	for i := 0; i < len(positions); i += windowSize {
		end := i + windowSize
		if end > len(positions) {
			end = len(positions)
		}
		
		w := windowInfo{
			startPkt:      positions[i].packetNum,
			typeBreakdown: make(map[uint16]int),
		}
		
		uniqueXY := make(map[string]bool)
		for j := i; j < end; j++ {
			p := positions[j]
			w.positionsTotal++
			w.typeBreakdown[p.typeCode]++
			key := fmt.Sprintf("%.0f,%.0f", p.x, p.y)
			uniqueXY[key] = true
		}
		w.distinctXY = len(uniqueXY)
		windows = append(windows, w)
	}

	// Show first 20 windows
	fmt.Printf("First 20 windows (size=%d unique positions each):\n", windowSize)
	for i := 0; i < 20 && i < len(windows); i++ {
		w := windows[i]
		fmt.Printf("  Window %d: %d distinct XY, types: ", i, w.distinctXY)
		for tc, c := range w.typeBreakdown {
			fmt.Printf("0x%04X(%d) ", tc, c)
		}
		fmt.Println()
	}

	// Average distinct XY per window
	totalDistinct := 0
	for _, w := range windows {
		totalDistinct += w.distinctXY
	}
	avgDistinct := float64(totalDistinct) / float64(len(windows))
	fmt.Printf("\nAverage distinct XY positions per window: %.1f\n", avgDistinct)

	// Now analyze if each type code represents a single player or multiple
	fmt.Printf("\n=== Per-type position clustering ===\n")
	for tc, ps := range byType {
		if len(ps) < 100 {
			continue
		}
		
		// Sort by time
		sort.Slice(ps, func(i, j int) bool {
			return ps[i].packetNum < ps[j].packetNum
		})
		
		// Check within small time windows how many distinct XY there are
		typeWindowSize := 20
		totalDistinctInType := 0
		windowCount := 0
		
		for i := 0; i < len(ps); i += typeWindowSize {
			end := i + typeWindowSize
			if end > len(ps) {
				end = len(ps)
			}
			
			uniqueXY := make(map[string]bool)
			for j := i; j < end; j++ {
				key := fmt.Sprintf("%.0f,%.0f", ps[j].x, ps[j].y)
				uniqueXY[key] = true
			}
			totalDistinctInType += len(uniqueXY)
			windowCount++
		}
		
		avgDistinctInType := float64(totalDistinctInType) / float64(windowCount)
		fmt.Printf("  Type 0x%04X: avg %.1f distinct XY per %d-position window (likely %.0f players)\n",
			tc, avgDistinctInType, typeWindowSize, avgDistinctInType)
	}

	// Calculate expected positions per player
	fmt.Printf("\n=== Position rate calculation ===\n")
	if len(positions) > 0 {
		duration := float64(positions[len(positions)-1].packetNum - positions[0].packetNum)
		rate := float64(len(positions)) / duration * 1000 // positions per 1000 packets
		fmt.Printf("Total unique positions: %d\n", len(positions))
		fmt.Printf("Packet range: %d - %d\n", positions[0].packetNum, positions[len(positions)-1].packetNum)
		fmt.Printf("Position rate: %.1f per 1000 packets\n", rate)
	}
}

func capturePositionDedup(r *dissect.Reader) error {
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

	// Deduplicate: skip if same as previous
	current := positionRecord{
		typeCode:  typeCode,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	}

	if hasLast && lastPos.typeCode == typeCode && lastPos.x == x && lastPos.y == y && lastPos.z == z {
		// Skip duplicate
		return nil
	}

	positions = append(positions, current)
	lastPos = current
	hasLast = true

	return nil
}

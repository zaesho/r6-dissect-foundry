package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type positionRecord struct {
	typeCode    uint16
	packetNum   int
	x, y, z     float32
	postBytes   []byte // bytes after coordinates
}

var positions []positionRecord
var packetNum int
var lastType uint16
var lastX, lastY, lastZ float32

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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureWithContext)
	r.Read()

	fmt.Printf("Captured %d positions\n\n", len(positions))

	// Sort by packet number
	sort.Slice(positions, func(i, j int) bool {
		return positions[i].packetNum < positions[j].packetNum
	})

	// Find consecutive packets that have DIFFERENT positions (different players at same moment)
	fmt.Printf("=== Finding consecutive different positions ===\n")
	fmt.Printf("(these represent different players at nearly the same time)\n\n")

	type playerMoment struct {
		pktNum  int
		players []positionRecord
	}
	var moments []playerMoment

	i := 0
	for i < len(positions) {
		// Collect all positions within 3 packet numbers of each other
		startPkt := positions[i].packetNum
		moment := playerMoment{pktNum: startPkt}
		
		for i < len(positions) && positions[i].packetNum-startPkt <= 3 {
			moment.players = append(moment.players, positions[i])
			i++
		}
		
		// Only keep moments with multiple distinct positions
		if len(moment.players) > 1 {
			uniqueXY := make(map[string]bool)
			for _, p := range moment.players {
				key := fmt.Sprintf("%.1f,%.1f", p.x, p.y)
				uniqueXY[key] = true
			}
			if len(uniqueXY) > 1 {
				moments = append(moments, moment)
			}
		}
	}

	fmt.Printf("Found %d moments with multiple distinct positions\n\n", len(moments))

	// Show first 10 moments in detail
	fmt.Printf("First 10 moments:\n")
	for i := 0; i < 10 && i < len(moments); i++ {
		m := moments[i]
		fmt.Printf("\n  Moment at pkt ~%d (%d positions):\n", m.pktNum, len(m.players))
		for _, p := range m.players {
			fmt.Printf("    pkt=%d type=0x%04X pos=(%.2f, %.2f, %.2f) post=%02X\n",
				p.packetNum, p.typeCode, p.x, p.y, p.z, p.postBytes[:8])
		}
	}

	// Analyze what differs between positions at same moment
	fmt.Printf("\n=== Pattern analysis ===\n")
	
	// Check if postBytes differ between players at same moment
	postBytePatterns := make(map[string]int)
	for _, m := range moments {
		for _, p := range m.players {
			key := fmt.Sprintf("%02X", p.postBytes[:4])
			postBytePatterns[key]++
		}
	}
	
	fmt.Printf("Post-coordinate byte patterns (first 4 bytes):\n")
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range postBytePatterns {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})
	for i := 0; i < 10 && i < len(sorted); i++ {
		fmt.Printf("  %s: %d\n", sorted[i].k, sorted[i].v)
	}

	// Now check if there's a pattern in the type codes that correlates with position
	fmt.Printf("\n=== Type code vs position correlation ===\n")
	
	// Group by rounded (X,Y) and see which types appear at each location
	locationTypes := make(map[string]map[uint16]int)
	for _, m := range moments {
		for _, p := range m.players {
			locKey := fmt.Sprintf("%.0f,%.0f", p.x, p.y)
			if locationTypes[locKey] == nil {
				locationTypes[locKey] = make(map[uint16]int)
			}
			locationTypes[locKey][p.typeCode]++
		}
	}

	// Show locations that have multiple type codes
	fmt.Printf("Locations with multiple type codes:\n")
	count := 0
	for loc, types := range locationTypes {
		if len(types) > 1 && count < 10 {
			fmt.Printf("  Location %s: ", loc)
			for tc, c := range types {
				fmt.Printf("0x%04X(%d) ", tc, c)
			}
			fmt.Println()
			count++
		}
	}
}

func captureWithContext(r *dissect.Reader) error {
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

	// Skip if exact duplicate
	if typeCode == lastType && x == lastX && y == lastY && z == lastZ {
		return nil
	}
	lastType = typeCode
	lastX = x
	lastY = y
	lastZ = z

	// Read bytes after coordinates
	postBytes, err := r.Bytes(16)
	if err != nil {
		postBytes = make([]byte, 16)
	}

	positions = append(positions, positionRecord{
		typeCode:  typeCode,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
		postBytes: postBytes,
	})

	return nil
}

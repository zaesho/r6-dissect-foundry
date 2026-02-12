package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type positionRecord struct {
	typeCode   uint16
	packetNum  int
	x, y, z    float32
	preByte1   byte   // 1 byte before marker
	preByte2   uint16 // 2 bytes before marker
	preByte4   uint32 // 4 bytes before marker
	postBytes  []byte // 16 bytes after coords
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureExtended)
	r.Read()

	// Filter to B803 only
	var b803 []positionRecord
	for _, p := range positions {
		if p.typeCode == 0xB803 {
			b803 = append(b803, p)
		}
	}

	fmt.Printf("B803 packets: %d\n\n", len(b803))

	// Look at post-bytes in detail
	fmt.Printf("=== Post-bytes analysis for B803 ===\n")
	
	// Bytes 0-3 are always 0
	// Bytes 4-7: either 0 or 0x80000000
	// Let's look at bytes 8-15
	
	byte8Counts := make(map[uint32]int)
	byte12Counts := make(map[uint32]int)
	
	for _, p := range b803 {
		if len(p.postBytes) >= 16 {
			b8 := binary.LittleEndian.Uint32(p.postBytes[8:12])
			b12 := binary.LittleEndian.Uint32(p.postBytes[12:16])
			byte8Counts[b8]++
			byte12Counts[b12]++
		}
	}

	fmt.Printf("Bytes 8-11 patterns:\n")
	printTopN(byte8Counts, 15)
	
	fmt.Printf("\nBytes 12-15 patterns:\n")
	printTopN(byte12Counts, 15)

	// Show raw hex for first 20 B803 packets
	fmt.Printf("\n=== First 20 B803 raw dumps ===\n")
	for i := 0; i < 20 && i < len(b803); i++ {
		p := b803[i]
		fmt.Printf("[%d] pkt=%d pos=(%.1f,%.1f,%.1f) post=%02X\n",
			i, p.packetNum, p.x, p.y, p.z, p.postBytes)
	}

	// Group B803 by rough XY location and see if there's any pattern
	fmt.Printf("\n=== B803 location analysis ===\n")
	
	// Sort by packet number
	sort.Slice(b803, func(i, j int) bool {
		return b803[i].packetNum < b803[j].packetNum
	})

	// Look at consecutive packets at different locations
	fmt.Printf("Consecutive B803 at different locations (first 50):\n")
	count := 0
	for i := 1; i < len(b803) && count < 50; i++ {
		// Different location?
		dx := b803[i].x - b803[i-1].x
		dy := b803[i].y - b803[i-1].y
		dist := dx*dx + dy*dy
		if dist > 4 { // >2 units apart
			fmt.Printf("  pkt %d->%d: (%.1f,%.1f)->(%.1f,%.1f) dist=%.1f\n",
				b803[i-1].packetNum, b803[i].packetNum,
				b803[i-1].x, b803[i-1].y,
				b803[i].x, b803[i].y,
				dist)
			count++
		}
	}

	// Check if B803 positions correspond to 01-type positions at same time
	fmt.Printf("\n=== Comparing B803 to 01-type positions ===\n")
	
	// Get all 01-type positions
	var type01 []positionRecord
	for _, p := range positions {
		if p.typeCode&0x00FF == 0x01 {
			type01 = append(type01, p)
		}
	}
	
	fmt.Printf("01-type positions: %d\n", len(type01))
	
	// For first 20 B803, find nearby 01-type at similar time
	fmt.Printf("\nMatching B803 to 01-type:\n")
	for i := 0; i < 20 && i < len(b803); i++ {
		p := b803[i]
		
		// Find 01-type within 10 packets and 2 units distance
		for _, p01 := range type01 {
			pktDiff := p01.packetNum - p.packetNum
			if pktDiff >= -10 && pktDiff <= 10 {
				dx := p.x - p01.x
				dy := p.y - p01.y
				if dx*dx+dy*dy < 4 {
					// Extract player ID from 01-type
					var playerID uint32
					if len(p01.postBytes) >= 8 {
						playerID = binary.LittleEndian.Uint32(p01.postBytes[4:8])
					}
					fmt.Printf("  B803 pkt=%d (%.1f,%.1f) matches 0x%04X pkt=%d (%.1f,%.1f) playerID=%d\n",
						p.packetNum, p.x, p.y,
						p01.typeCode, p01.packetNum, p01.x, p01.y,
						playerID)
					break
				}
			}
		}
	}
}

func printTopN(counts map[uint32]int, n int) {
	type kv struct {
		k uint32
		v int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].v > sorted[j].v
	})
	for i := 0; i < n && i < len(sorted); i++ {
		fmt.Printf("  0x%08X: %d\n", sorted[i].k, sorted[i].v)
	}
}

func captureExtended(r *dissect.Reader) error {
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

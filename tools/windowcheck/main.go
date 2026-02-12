package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	typeCode  uint16
	packetNum int
	playerID  int
	x, y, z   float32
}

var packets []packet
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePacket)
	r.Read()

	// Filter to B803 with valid player IDs
	var b803 []packet
	for _, p := range packets {
		if p.typeCode == 0xB803 && p.playerID >= 5 && p.playerID <= 14 {
			b803 = append(b803, p)
		}
	}

	fmt.Printf("Total B803 packets with valid player IDs: %d\n\n", len(b803))

	// Check player distribution in small time windows
	fmt.Printf("=== Player ID distribution in time windows of 100 packets ===\n\n")
	
	windowSize := 100
	for windowStart := 0; windowStart+windowSize <= len(b803) && windowStart < 1000; windowStart += windowSize {
		playerCounts := make(map[int]int)
		
		for i := windowStart; i < windowStart+windowSize; i++ {
			playerCounts[b803[i].playerID]++
		}
		
		fmt.Printf("Window %d-%d:\n", windowStart, windowStart+windowSize)
		
		var ids []int
		for id := range playerCounts {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		
		for _, id := range ids {
			fmt.Printf("  Player %2d: %3d packets\n", id, playerCounts[id])
		}
		fmt.Printf("  Distinct players: %d\n\n", len(playerCounts))
	}

	// Now check the first 50 packets in detail to see the actual sequence
	fmt.Printf("\n=== First 50 packets (player ID sequence) ===\n")
	for i := 0; i < 50 && i < len(b803); i++ {
		p := b803[i]
		fmt.Printf("[%3d] Player %2d at (%.1f, %.1f, %.1f)\n", i, p.playerID, p.x, p.y, p.z)
	}
}

func capturePacket(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	if typeCode != 0xB803 {
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

	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) {
		return nil
	}

	postBytes, err := r.Bytes(36)
	if err != nil {
		return nil
	}

	// For B803, after coordinates (12 bytes), player ID is at offset 20 in postBytes
	// (which is byte 32 from the start of the packet data after type bytes)
	playerID := int(binary.LittleEndian.Uint32(postBytes[20:24]))

	packets = append(packets, packet{
		typeCode:  typeCode,
		packetNum: packetNum,
		playerID:  playerID,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

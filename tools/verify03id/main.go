package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	typeCode     uint16
	packetNum    int
	x, y, z      float32
	playerID01   int // from bytes 4-7 (01-type)
	playerID03   int // from bytes 20-23 (03-type)
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

	fmt.Printf("Captured %d packets\n\n", len(packets))

	// Count player IDs from 03-type using the new offset
	fmt.Printf("=== 03-type player IDs (from bytes 20-23) ===\n")
	type03IDs := make(map[int]int)
	for _, p := range packets {
		if p.typeCode&0xFF == 0x03 && p.playerID03 >= 1 && p.playerID03 <= 20 {
			type03IDs[p.playerID03]++
		}
	}

	var ids []int
	for id := range type03IDs {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	total03 := 0
	for _, id := range ids {
		fmt.Printf("  Player %2d: %d positions\n", id, type03IDs[id])
		total03 += type03IDs[id]
	}
	fmt.Printf("  Total with valid IDs: %d\n", total03)

	// Count 01-type for comparison
	fmt.Printf("\n=== 01-type player IDs (from bytes 4-7) ===\n")
	type01IDs := make(map[int]int)
	for _, p := range packets {
		if p.typeCode&0xFF == 0x01 && p.playerID01 >= 1 && p.playerID01 <= 20 {
			type01IDs[p.playerID01]++
		}
	}

	total01 := 0
	for _, id := range ids {
		if type01IDs[id] > 0 {
			fmt.Printf("  Player %2d: %d positions\n", id, type01IDs[id])
			total01 += type01IDs[id]
		}
	}
	fmt.Printf("  Total with valid IDs: %d\n", total01)

	// Combined totals
	fmt.Printf("\n=== Combined (01 + 03) ===\n")
	for _, id := range ids {
		total := type01IDs[id] + type03IDs[id]
		rate := float64(total) / 85.0
		fmt.Printf("  Player %2d: %5d positions (%.1f/sec)\n", id, total, rate)
	}

	// Header info
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d) -> Player ID %d\n", i, p.Username, p.TeamIndex, i+5)
	}
}

func capturePacket(r *dissect.Reader) error {
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

	// Read 24 bytes to get both potential player ID locations
	postBytes, err := r.Bytes(24)
	if err != nil {
		return nil
	}

	p := packet{
		typeCode:  typeCode,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	}

	// 01-type: player ID at bytes 4-7
	p.playerID01 = int(binary.LittleEndian.Uint32(postBytes[4:8]))

	// 03-type: player ID at bytes 20-23
	p.playerID03 = int(binary.LittleEndian.Uint32(postBytes[20:24]))

	packets = append(packets, p)

	return nil
}

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
	playerID  int
	packetNum int
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

	fmt.Printf("Total valid packets: %d\n\n", len(packets))

	// Group by player
	playerPackets := make(map[int][]packet)
	for _, p := range packets {
		playerPackets[p.playerID] = append(playerPackets[p.playerID], p)
	}

	// Show distribution
	fmt.Printf("=== Player distribution ===\n")
	var ids []int
	for id := range playerPackets {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	total := 0
	for _, id := range ids {
		count := len(playerPackets[id])
		total += count
		fmt.Printf("  Player %2d: %6d packets\n", id, count)
	}
	fmt.Printf("\n  Total: %d\n", total)

	// Show coordinate ranges per player
	fmt.Printf("\n=== Coordinate ranges per player ===\n")
	for _, id := range ids {
		pkts := playerPackets[id]
		if len(pkts) < 10 {
			continue
		}
		
		minX, maxX := pkts[0].x, pkts[0].x
		minY, maxY := pkts[0].y, pkts[0].y
		minZ, maxZ := pkts[0].z, pkts[0].z
		
		for _, p := range pkts {
			if p.x < minX { minX = p.x }
			if p.x > maxX { maxX = p.x }
			if p.y < minY { minY = p.y }
			if p.y > maxY { maxY = p.y }
			if p.z < minZ { minZ = p.z }
			if p.z > maxZ { maxZ = p.z }
		}
		
		fmt.Printf("  Player %2d: X[%.1f, %.1f] Y[%.1f, %.1f] Z[%.1f, %.1f]\n",
			id, minX, maxX, minY, maxY, minZ, maxZ)
	}

	// Header
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s -> Expected ID %d\n", i, p.Username, i+5)
	}
}

func capturePacket(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	suffix := typeBytes[1]
	prefix := typeBytes[0]

	// Only B0xx 01/03 types
	if (suffix != 0x01 && suffix != 0x03) || prefix < 0xB0 {
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

	// RELAXED coordinate validation - just check they're valid floats in reasonable range
	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) {
		return nil
	}
	if x < -200 || x > 200 || y < -200 || y > 200 || z < -50 || z > 100 {
		return nil
	}

	// Read enough bytes to get player ID
	postBytes, err := r.Bytes(36)
	if err != nil {
		return nil
	}

	// Extract player ID at offset 32 (works for both 01 and 03 types based on analysis)
	playerID := int(binary.LittleEndian.Uint32(postBytes[32:36]))

	// Also try the known locations for 01-type
	if suffix == 0x01 {
		id01 := int(binary.LittleEndian.Uint32(postBytes[4:8]))
		if id01 >= 5 && id01 <= 14 {
			playerID = id01
		}
	}

	if playerID >= 1 && playerID <= 20 {
		packets = append(packets, packet{
			playerID:  playerID,
			packetNum: packetNum,
			x:         x,
			y:         y,
			z:         z,
		})
	}

	return nil
}

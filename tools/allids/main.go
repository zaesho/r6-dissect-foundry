package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

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

	// Collect ALL integer values at offset 32 across all B0xx 01/03 packets
	idCounts := make(map[int]int)
	coordRanges := make(map[int]struct{ minX, maxX, minY, maxY, minZ, maxZ float32 })

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, func(r *dissect.Reader) error {
		packetNum++

		typeBytes, err := r.Bytes(2)
		if err != nil {
			return nil
		}

		suffix := typeBytes[1]
		prefix := typeBytes[0]

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

		if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) {
			return nil
		}
		if x < -200 || x > 200 || y < -200 || y > 200 {
			return nil
		}

		postBytes, err := r.Bytes(36)
		if err != nil {
			return nil
		}

		// Get ID at offset 32
		id := int(binary.LittleEndian.Uint32(postBytes[32:36]))
		
		// For 01-type, also check offset 4
		if suffix == 0x01 {
			id01 := int(binary.LittleEndian.Uint32(postBytes[4:8]))
			if id01 > 0 && id01 < 100 {
				id = id01
			}
		}

		if id > 0 && id < 100 {
			idCounts[id]++
			
			ranges, exists := coordRanges[id]
			if !exists {
				ranges = struct{ minX, maxX, minY, maxY, minZ, maxZ float32 }{x, x, y, y, z, z}
			}
			if x < ranges.minX { ranges.minX = x }
			if x > ranges.maxX { ranges.maxX = x }
			if y < ranges.minY { ranges.minY = y }
			if y > ranges.maxY { ranges.maxY = y }
			if z < ranges.minZ { ranges.minZ = z }
			if z > ranges.maxZ { ranges.maxZ = z }
			coordRanges[id] = ranges
		}

		return nil
	})

	r.Read()

	// Sort IDs
	var ids []int
	for id := range idCounts {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	fmt.Printf("=== ALL entity IDs found (1-100) ===\n\n")
	total := 0
	for _, id := range ids {
		count := idCounts[id]
		total += count
		ranges := coordRanges[id]
		xSpan := ranges.maxX - ranges.minX
		ySpan := ranges.maxY - ranges.minY
		fmt.Printf("  ID %2d: %6d packets, X span=%.0f, Y span=%.0f, Z=[%.1f, %.1f]\n",
			id, count, xSpan, ySpan, ranges.minZ, ranges.maxZ)
	}
	fmt.Printf("\n  Total: %d packets\n", total)

	// Header
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}
}

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

	// Separate 01-type and 03-type
	var type01, type03 []packet
	for _, p := range packets {
		if p.playerID >= 5 && p.playerID <= 14 {
			if p.typeCode&0xFF == 0x01 {
				type01 = append(type01, p)
			} else if p.typeCode&0xFF == 0x03 {
				type03 = append(type03, p)
			}
		}
	}

	fmt.Printf("01-type packets with valid player IDs: %d\n", len(type01))
	fmt.Printf("03-type packets with valid player IDs: %d\n\n", len(type03))

	// Compare distributions
	fmt.Printf("=== 01-type distribution ===\n")
	printDist(type01)
	
	fmt.Printf("\n=== 03-type distribution ===\n")
	printDist(type03)

	// Check if 01 and 03 packets for the same player have same positions
	fmt.Printf("\n=== Checking if 01 and 03 track same players ===\n")
	
	// For each player, compare position ranges
	for playerID := 5; playerID <= 14; playerID++ {
		var pos01, pos03 []packet
		for _, p := range type01 {
			if p.playerID == playerID {
				pos01 = append(pos01, p)
			}
		}
		for _, p := range type03 {
			if p.playerID == playerID {
				pos03 = append(pos03, p)
			}
		}
		
		if len(pos01) > 0 && len(pos03) > 0 {
			// Compare first few positions
			fmt.Printf("\nPlayer %d:\n", playerID)
			fmt.Printf("  01-type (%d): first pos (%.1f, %.1f, %.1f)\n", len(pos01), pos01[0].x, pos01[0].y, pos01[0].z)
			fmt.Printf("  03-type (%d): first pos (%.1f, %.1f, %.1f)\n", len(pos03), pos03[0].x, pos03[0].y, pos03[0].z)
		}
	}

	// Header
	fmt.Printf("\n\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d) -> ID %d\n", i, p.Username, p.TeamIndex, i+5)
	}
}

func printDist(pkts []packet) {
	playerCounts := make(map[int]int)
	for _, p := range pkts {
		playerCounts[p.playerID]++
	}
	
	var ids []int
	total := 0
	for id, count := range playerCounts {
		ids = append(ids, id)
		total += count
	}
	sort.Ints(ids)
	
	for _, id := range ids {
		pct := float64(playerCounts[id]) / float64(total) * 100
		fmt.Printf("  Player %2d: %5d packets (%.1f%%)\n", id, playerCounts[id], pct)
	}
}

func capturePacket(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

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

	postBytes, err := r.Bytes(36)
	if err != nil {
		return nil
	}

	// Extract player ID based on type
	var playerID int
	if suffix == 0x01 {
		// 01-type: player ID at postBytes[4:8]
		playerID = int(binary.LittleEndian.Uint32(postBytes[4:8]))
	} else {
		// 03-type: player ID at postBytes[20:24]
		playerID = int(binary.LittleEndian.Uint32(postBytes[20:24]))
	}

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

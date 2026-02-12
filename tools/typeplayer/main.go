package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type posRecord struct {
	typeCode  uint16
	playerID  int
	packetNum int
	x, y, z   float32
}

var positions []posRecord
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

	// Capture 01-type packets only (they have player IDs)
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureWithID)
	r.Read()

	// Filter to only 01-type with valid player IDs
	var type01 []posRecord
	for _, p := range positions {
		if p.typeCode&0xFF == 0x01 && p.playerID >= 1 && p.playerID <= 20 {
			type01 = append(type01, p)
		}
	}

	fmt.Printf("Total 01-type with valid player IDs: %d\n\n", len(type01))

	// Which player IDs appear in which type codes?
	typePlayerMap := make(map[uint16]map[int]int) // typeCode -> playerID -> count
	for _, p := range type01 {
		if typePlayerMap[p.typeCode] == nil {
			typePlayerMap[p.typeCode] = make(map[int]int)
		}
		typePlayerMap[p.typeCode][p.playerID]++
	}

	fmt.Printf("=== Player IDs by type code ===\n")
	typeCodes := []uint16{0xB001, 0xB401, 0xB801, 0xBC01}
	for _, tc := range typeCodes {
		players := typePlayerMap[tc]
		if players == nil {
			continue
		}
		
		fmt.Printf("\nType 0x%04X:\n", tc)
		
		// Sort by player ID
		var ids []int
		for id := range players {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		
		for _, id := range ids {
			fmt.Printf("  Player %2d: %d positions\n", id, players[id])
		}
	}

	// Now let's see if there's a pattern: do certain players only use certain types?
	fmt.Printf("\n=== Per-player breakdown by type ===\n")
	
	playerTypeMap := make(map[int]map[uint16]int) // playerID -> typeCode -> count
	for _, p := range type01 {
		if playerTypeMap[p.playerID] == nil {
			playerTypeMap[p.playerID] = make(map[uint16]int)
		}
		playerTypeMap[p.playerID][p.typeCode]++
	}

	var playerIDs []int
	for id := range playerTypeMap {
		playerIDs = append(playerIDs, id)
	}
	sort.Ints(playerIDs)

	for _, id := range playerIDs {
		if id < 1 || id > 20 {
			continue
		}
		types := playerTypeMap[id]
		total := 0
		for _, c := range types {
			total += c
		}
		
		fmt.Printf("\nPlayer %2d (total: %d):\n", id, total)
		for _, tc := range typeCodes {
			if types[tc] > 0 {
				pct := float64(types[tc]) / float64(total) * 100
				fmt.Printf("  0x%04X: %4d (%.1f%%)\n", tc, types[tc], pct)
			}
		}
	}

	// Check the header to see player info
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}
}

func captureWithID(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	if typeBytes[1] != 0x01 {
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

	postBytes, err := r.Bytes(8)
	if err != nil {
		return nil
	}

	playerID := int(binary.LittleEndian.Uint32(postBytes[4:8]))

	positions = append(positions, posRecord{
		typeCode:  typeCode,
		playerID:  playerID,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

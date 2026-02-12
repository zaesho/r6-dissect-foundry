package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type positionRecord struct {
	typeCode  uint16
	packetNum int
	x, y, z   float32
	playerID  uint32 // from post-bytes
	postFlag  uint32 // bytes 4-7 after coords
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureWithPlayerID)
	r.Read()

	fmt.Printf("Captured %d positions\n\n", len(positions))

	// Analyze playerID distribution per type
	fmt.Printf("=== Player ID analysis per type ===\n")
	
	byType := make(map[uint16][]positionRecord)
	for _, p := range positions {
		byType[p.typeCode] = append(byType[p.typeCode], p)
	}

	for tc, ps := range byType {
		playerIDs := make(map[uint32]int)
		for _, p := range ps {
			playerIDs[p.playerID]++
		}
		
		fmt.Printf("\nType 0x%04X (%d positions):\n", tc, len(ps))
		fmt.Printf("  Distinct player IDs: %d\n", len(playerIDs))
		
		// Show top player IDs
		type kv struct {
			id    uint32
			count int
		}
		var sorted []kv
		for id, c := range playerIDs {
			sorted = append(sorted, kv{id, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		
		fmt.Printf("  Player ID distribution:\n")
		for i := 0; i < 15 && i < len(sorted); i++ {
			fmt.Printf("    ID %3d: %d positions\n", sorted[i].id, sorted[i].count)
		}
	}

	// Overall player ID analysis
	fmt.Printf("\n=== Overall Player ID summary ===\n")
	allPlayerIDs := make(map[uint32]int)
	for _, p := range positions {
		allPlayerIDs[p.playerID]++
	}
	
	type kv struct {
		id    uint32
		count int
	}
	var sorted []kv
	for id, c := range allPlayerIDs {
		sorted = append(sorted, kv{id, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	
	fmt.Printf("Distinct player IDs: %d\n", len(allPlayerIDs))
	fmt.Printf("Top player IDs:\n")
	for i := 0; i < 20 && i < len(sorted); i++ {
		fmt.Printf("  ID %3d: %d positions\n", sorted[i].id, sorted[i].count)
	}

	// Check if player IDs match header players
	fmt.Printf("\n=== Checking if IDs match expected player count ===\n")
	smallIDs := 0
	for id := range allPlayerIDs {
		if id < 20 {
			smallIDs++
		}
	}
	fmt.Printf("Player IDs < 20: %d\n", smallIDs)

	// Show positions by player ID (first 10 positions for each small ID)
	fmt.Printf("\n=== Sample positions by player ID ===\n")
	for id := uint32(0); id < 20; id++ {
		var playerPositions []positionRecord
		for _, p := range positions {
			if p.playerID == id {
				playerPositions = append(playerPositions, p)
			}
		}
		if len(playerPositions) > 0 {
			fmt.Printf("\nPlayer ID %d (%d total positions):\n", id, len(playerPositions))
			for i := 0; i < 5 && i < len(playerPositions); i++ {
				p := playerPositions[i]
				fmt.Printf("  pkt=%d type=0x%04X pos=(%.1f, %.1f, %.1f)\n",
					p.packetNum, p.typeCode, p.x, p.y, p.z)
			}
		}
	}
}

func captureWithPlayerID(r *dissect.Reader) error {
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
	postBytes, err := r.Bytes(8)
	if err != nil {
		postBytes = make([]byte, 8)
	}

	// Player ID is at bytes 4-7 (little endian)
	playerID := binary.LittleEndian.Uint32(postBytes[4:8])
	postFlag := binary.LittleEndian.Uint32(postBytes[0:4])

	positions = append(positions, positionRecord{
		typeCode:  typeCode,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
		playerID:  playerID,
		postFlag:  postFlag,
	})

	return nil
}

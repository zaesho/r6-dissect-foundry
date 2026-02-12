package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type PacketRecord struct {
	PacketNum int
	Type2     byte
	X, Y, Z   float32
	ID4       uint32 // ID at offset 4
	ID20      uint32 // ID at offset 20
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
	packetCounter  int
	players        []PlayerInfo
)

type PlayerInfo struct {
	Username  string
	Operator  string
	Team      string
	Spawn     string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: firstpos <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating reader: %v\n", err)
		os.Exit(1)
	}

	r.Listen(positionMarker, capturePacket)
	r.Read()

	// Extract player info
	for _, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				team = "ATK"
			} else {
				team = "DEF"
			}
		}
		players = append(players, PlayerInfo{
			Username: p.Username,
			Operator: p.Operator.String(),
			Team:     team,
			Spawn:    p.Spawn,
		})
	}

	fmt.Printf("Captured %d packets\n\n", len(allPackets))

	// Print player info
	fmt.Println("=== PLAYERS ===")
	for _, p := range players {
		fmt.Printf("%-15s %-10s %-5s %s\n", p.Username, p.Operator, p.Team, p.Spawn)
	}

	// Find first position for each ID (using type 0x03 packets, ID at offset 20)
	fmt.Println("\n=== FIRST POSITION PER ID (Type 0x03, ID@20) ===")
	firstPosType03 := findFirstPositionsType03()
	
	fmt.Printf("%-6s %-10s %-10s %-10s %-15s\n", "ID", "FirstX", "FirstY", "FirstZ", "Location")
	fmt.Println("--------------------------------------------------------")
	
	// Sort by ID
	var ids []uint32
	for id := range firstPosType03 {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	
	for _, id := range ids {
		p := firstPosType03[id]
		loc := classifyLocation(p.X, p.Y)
		fmt.Printf("%-6d %-10.1f %-10.1f %-10.1f %-15s\n", id, p.X, p.Y, p.Z, loc)
	}

	// Find first position for each ID (using type 0x01 packets, ID at offset 4)
	fmt.Println("\n=== FIRST POSITION PER ID (Type 0x01, ID@4) ===")
	firstPosType01 := findFirstPositionsType01()
	
	fmt.Printf("%-6s %-10s %-10s %-10s %-15s\n", "ID", "FirstX", "FirstY", "FirstZ", "Location")
	fmt.Println("--------------------------------------------------------")
	
	ids = nil
	for id := range firstPosType01 {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	
	for _, id := range ids {
		p := firstPosType01[id]
		loc := classifyLocation(p.X, p.Y)
		fmt.Printf("%-6d %-10.1f %-10.1f %-10.1f %-15s\n", id, p.X, p.Y, p.Z, loc)
	}

	// Combine and try to match to players
	fmt.Println("\n=== SUGGESTED ID-PLAYER MAPPING ===")
	suggestMapping(firstPosType03)
}

func capturePacket(r *dissect.Reader) error {
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	type1 := typeBytes[0]
	type2 := typeBytes[1]

	if type1 < 0xB0 {
		return nil
	}

	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	postBytes, _ := r.Bytes(64)

	var id4, id20 uint32
	if len(postBytes) >= 8 {
		id4 = binary.LittleEndian.Uint32(postBytes[4:8])
	}
	if len(postBytes) >= 24 {
		id20 = binary.LittleEndian.Uint32(postBytes[20:24])
	}

	allPackets = append(allPackets, PacketRecord{
		PacketNum: packetCounter,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		ID4:       id4,
		ID20:      id20,
	})
	packetCounter++

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func findFirstPositionsType03() map[uint32]PacketRecord {
	result := make(map[uint32]PacketRecord)
	
	for _, p := range allPackets {
		if p.Type2 != 0x03 {
			continue
		}
		id := p.ID20
		if id < 1 || id > 20 {
			continue
		}
		if _, exists := result[id]; !exists {
			result[id] = p
		}
	}
	
	return result
}

func findFirstPositionsType01() map[uint32]PacketRecord {
	result := make(map[uint32]PacketRecord)
	
	for _, p := range allPackets {
		if p.Type2 != 0x01 {
			continue
		}
		id := p.ID4
		if id < 1 || id > 20 {
			continue
		}
		if _, exists := result[id]; !exists {
			result[id] = p
		}
	}
	
	return result
}

func classifyLocation(x, y float32) string {
	// Based on observed patterns
	if y > 40 {
		return "SPAWN (Lakeside?)"
	}
	if y < -15 {
		return "OUTSIDE (yard?)"
	}
	if x < -30 || x > 30 {
		return "OUTSIDE (edge)"
	}
	if y >= -10 && y <= 15 && x >= 0 && x <= 20 {
		return "INSIDE (building)"
	}
	return "UNKNOWN"
}

func suggestMapping(firstPos map[uint32]PacketRecord) {
	// Separate IDs into likely attackers vs defenders
	var attackerIDs, defenderIDs []uint32
	
	for id, p := range firstPos {
		// If first position is at spawn (Y > 40) or outside (Y < -15), likely attacker
		if p.Y > 40 || p.Y < -15 || math.Abs(float64(p.X)) > 30 {
			attackerIDs = append(attackerIDs, id)
		} else {
			defenderIDs = append(defenderIDs, id)
		}
	}
	
	sort.Slice(attackerIDs, func(i, j int) bool { return attackerIDs[i] < attackerIDs[j] })
	sort.Slice(defenderIDs, func(i, j int) bool { return defenderIDs[i] < defenderIDs[j] })
	
	// Get attackers and defenders from player list
	var attackers, defenders []PlayerInfo
	for _, p := range players {
		if p.Team == "ATK" {
			attackers = append(attackers, p)
		} else {
			defenders = append(defenders, p)
		}
	}
	
	fmt.Println("\nDEFENDER IDs (first pos inside building):")
	for i, id := range defenderIDs {
		p := firstPos[id]
		player := "?"
		if i < len(defenders) {
			player = defenders[i].Username + " (" + defenders[i].Operator + ")"
		}
		fmt.Printf("  ID %2d: (%.1f, %.1f) -> %s\n", id, p.X, p.Y, player)
	}
	
	fmt.Println("\nATTACKER IDs (first pos at spawn/outside):")
	
	// Try to group attackers by spawn location
	type idWithPos struct {
		id uint32
		x, y float32
	}
	var atkWithPos []idWithPos
	for _, id := range attackerIDs {
		p := firstPos[id]
		atkWithPos = append(atkWithPos, idWithPos{id, p.X, p.Y})
	}
	
	// Sort by Y to see spawn groupings
	sort.Slice(atkWithPos, func(i, j int) bool {
		return atkWithPos[i].y > atkWithPos[j].y // Higher Y first (spawn at top)
	})
	
	for i, ap := range atkWithPos {
		player := "?"
		if i < len(attackers) {
			player = attackers[i].Username + " (" + attackers[i].Operator + ", " + attackers[i].Spawn + ")"
		}
		fmt.Printf("  ID %2d: (%.1f, %.1f) -> %s\n", ap.id, ap.x, ap.y, player)
	}
	
	fmt.Println("\n=== SPAWN GROUPING ANALYSIS ===")
	// Group attacker IDs by spawn location
	var lakesideGroup, otherGroup []idWithPos
	
	for _, ap := range atkWithPos {
		if ap.y > 40 {
			lakesideGroup = append(lakesideGroup, ap)
		} else if ap.y < -15 {
			otherGroup = append(otherGroup, ap) // Could be Campfire or another area
		} else {
			otherGroup = append(otherGroup, ap)
		}
	}
	
	fmt.Printf("\nLikely Lakeside spawn (Y > 40): %d IDs\n", len(lakesideGroup))
	for _, ap := range lakesideGroup {
		fmt.Printf("  ID %d at (%.1f, %.1f)\n", ap.id, ap.x, ap.y)
	}
	
	fmt.Printf("\nOther locations: %d IDs\n", len(otherGroup))
	for _, ap := range otherGroup {
		fmt.Printf("  ID %d at (%.1f, %.1f)\n", ap.id, ap.x, ap.y)
	}
	
	fmt.Println("\nExpected from header:")
	fmt.Println("  Lakeside: Kiru.UNITY, hattttttttt, BjL- (3 players)")
	fmt.Println("  Campfire: VicBands, Repuhrz (2 players)")
}

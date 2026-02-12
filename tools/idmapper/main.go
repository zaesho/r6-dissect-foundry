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
	Type1     byte
	Type2     byte
	X, Y, Z   float32
	PlayerID  uint32 // Extracted from the appropriate offset
}

type PlayerInfo struct {
	Username  string
	Operator  string
	TeamIndex int
	Team      string // "Attack" or "Defense"
	Spawn     string
	DissectID string
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
	packetCounter  int
	players        []PlayerInfo
	header         *dissect.Header
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: idmapper <replay.rec>")
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

	// Store header reference
	header = &r.Header

	// Register listener for position packets
	r.Listen(positionMarker, capturePositionPacket)

	// Read the file
	err = r.Read()
	if err != nil {
		fmt.Printf("Warning during read: %v\n", err)
	}

	// Extract player info from header
	extractPlayerInfo(r)

	fmt.Printf("Captured %d position packets\n", len(allPackets))
	fmt.Printf("Found %d players in header\n\n", len(players))

	// Print player info
	fmt.Println("=== PLAYERS FROM HEADER ===")
	fmt.Printf("%-15s %-12s %-8s %-12s %-12s\n", "Username", "Operator", "Team", "Role", "Spawn")
	fmt.Println("----------------------------------------------------------------")
	for _, p := range players {
		fmt.Printf("%-15s %-12s %-8d %-12s %-12s\n", 
			truncate(p.Username, 15), truncate(p.Operator, 12), p.TeamIndex, p.Team, p.Spawn)
	}

	// Analyze early packets (first 15% = prep phase) to find spawn positions per ID
	fmt.Println("\n=== EARLY PACKET ANALYSIS (Prep Phase) ===")
	analyzeEarlyPackets()

	// Map IDs to players based on spawn positions
	fmt.Println("\n=== ID TO PLAYER MAPPING ===")
	mapIDsToPlayers()
}

func capturePositionPacket(r *dissect.Reader) error {
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

	if !isValidCoord(x) || !isValidCoord(y) || !isValidCoord(z) {
		return nil
	}
	if z < -10 || z > 50 {
		return nil
	}

	// Read post-bytes to extract player ID
	postBytes, _ := r.Bytes(64)

	// Extract player ID based on packet type
	var playerID uint32
	if type2 == 0x01 {
		// For type 0x01, ID is at offset 4-7
		if len(postBytes) >= 8 {
			playerID = binary.LittleEndian.Uint32(postBytes[4:8])
		}
	} else if type2 == 0x03 {
		// For type 0x03, ID is at offset 20-23
		if len(postBytes) >= 24 {
			playerID = binary.LittleEndian.Uint32(postBytes[20:24])
		}
	} else {
		// For other types, try offset 4 first
		if len(postBytes) >= 8 {
			playerID = binary.LittleEndian.Uint32(postBytes[4:8])
		}
	}

	// Only keep packets with reasonable player IDs (1-20)
	if playerID >= 1 && playerID <= 20 {
		allPackets = append(allPackets, PacketRecord{
			PacketNum: packetCounter,
			Type1:     type1,
			Type2:     type2,
			X:         x,
			Y:         y,
			Z:         z,
			PlayerID:  playerID,
		})
	}
	packetCounter++

	return nil
}

func extractPlayerInfo(r *dissect.Reader) {
	for _, p := range r.Header.Players {
		teamRole := "Unknown"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "Attack"
			} else if r.Header.Teams[p.TeamIndex].Role == dissect.Defense {
				teamRole = "Defense"
			}
		}

		players = append(players, PlayerInfo{
			Username:  p.Username,
			Operator:  p.Operator.String(),
			TeamIndex: p.TeamIndex,
			Team:      teamRole,
			Spawn:     p.Spawn,
			DissectID: fmt.Sprintf("%x", p.DissectID),
		})
	}
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

func analyzeEarlyPackets() {
	if len(allPackets) == 0 {
		fmt.Println("No packets found")
		return
	}

	// Use first 15% of packets (roughly prep phase)
	earlyCount := len(allPackets) * 15 / 100
	if earlyCount < 100 {
		earlyCount = min(100, len(allPackets))
	}

	earlyPackets := allPackets[:earlyCount]

	// Group early packets by ID
	idGroups := make(map[uint32][]PacketRecord)
	for _, p := range earlyPackets {
		idGroups[p.PlayerID] = append(idGroups[p.PlayerID], p)
	}

	fmt.Printf("Analyzing first %d packets (prep phase)\n\n", earlyCount)

	// Calculate starting position for each ID
	type idStart struct {
		id     uint32
		count  int
		firstX float32
		firstY float32
		firstZ float32
		avgX   float64
		avgY   float64
		avgZ   float64
	}

	var starts []idStart
	for id, packets := range idGroups {
		if len(packets) < 5 {
			continue
		}

		// First position
		first := packets[0]

		// Average of first 10 positions
		n := min(10, len(packets))
		var sumX, sumY, sumZ float64
		for i := 0; i < n; i++ {
			sumX += float64(packets[i].X)
			sumY += float64(packets[i].Y)
			sumZ += float64(packets[i].Z)
		}

		starts = append(starts, idStart{
			id:     id,
			count:  len(packets),
			firstX: first.X,
			firstY: first.Y,
			firstZ: first.Z,
			avgX:   sumX / float64(n),
			avgY:   sumY / float64(n),
			avgZ:   sumZ / float64(n),
		})
	}

	// Sort by ID
	sort.Slice(starts, func(i, j int) bool {
		return starts[i].id < starts[j].id
	})

	fmt.Printf("%-6s %-8s %-12s %-12s %-12s %-12s %-12s\n", 
		"ID", "Count", "FirstX", "FirstY", "FirstZ", "AvgX", "AvgY")
	fmt.Println("--------------------------------------------------------------------------------")
	for _, s := range starts {
		fmt.Printf("%-6d %-8d %-12.2f %-12.2f %-12.2f %-12.2f %-12.2f\n",
			s.id, s.count, s.firstX, s.firstY, s.firstZ, s.avgX, s.avgY)
	}

	// Identify clusters (defenders vs attackers based on Y coordinate typically)
	fmt.Println("\n=== POSITION CLUSTERING ===")
	
	// Calculate centroid
	var centroidX, centroidY float64
	for _, s := range starts {
		centroidX += s.avgX
		centroidY += s.avgY
	}
	centroidX /= float64(len(starts))
	centroidY /= float64(len(starts))
	
	fmt.Printf("Centroid: (%.2f, %.2f)\n\n", centroidX, centroidY)

	// Classify by distance from centroid
	type idDist struct {
		id   uint32
		dist float64
		avgX float64
		avgY float64
	}
	var dists []idDist
	for _, s := range starts {
		dx := s.avgX - centroidX
		dy := s.avgY - centroidY
		dist := math.Sqrt(dx*dx + dy*dy)
		dists = append(dists, idDist{s.id, dist, s.avgX, s.avgY})
	}

	sort.Slice(dists, func(i, j int) bool {
		return dists[i].dist < dists[j].dist
	})

	fmt.Println("IDs sorted by distance from centroid (closer = likely defender):")
	for i, d := range dists {
		team := "Defender?"
		if i >= len(dists)/2 {
			team = "Attacker?"
		}
		fmt.Printf("  ID %2d: dist=%.2f pos=(%.1f, %.1f) -> %s\n", 
			d.id, d.dist, d.avgX, d.avgY, team)
	}
}

func mapIDsToPlayers() {
	if len(allPackets) == 0 || len(players) == 0 {
		fmt.Println("No data to map")
		return
	}

	// Get early packets for each ID
	earlyCount := len(allPackets) * 15 / 100
	if earlyCount < 100 {
		earlyCount = min(100, len(allPackets))
	}
	earlyPackets := allPackets[:earlyCount]

	// Calculate average start position for each ID
	type idPos struct {
		id   uint32
		avgX float64
		avgY float64
		avgZ float64
	}
	idPositions := make(map[uint32]*idPos)
	idCounts := make(map[uint32]int)

	for _, p := range earlyPackets {
		if idPositions[p.PlayerID] == nil {
			idPositions[p.PlayerID] = &idPos{id: p.PlayerID}
		}
		idPositions[p.PlayerID].avgX += float64(p.X)
		idPositions[p.PlayerID].avgY += float64(p.Y)
		idPositions[p.PlayerID].avgZ += float64(p.Z)
		idCounts[p.PlayerID]++
	}

	for id, pos := range idPositions {
		count := float64(idCounts[id])
		pos.avgX /= count
		pos.avgY /= count
		pos.avgZ /= count
	}

	// Separate attackers and defenders from players list
	var attackers, defenders []PlayerInfo
	for _, p := range players {
		if p.Team == "Attack" {
			attackers = append(attackers, p)
		} else if p.Team == "Defense" {
			defenders = append(defenders, p)
		}
	}

	// Calculate centroid to separate IDs
	var centroidX, centroidY float64
	var totalIDs int
	for _, pos := range idPositions {
		centroidX += pos.avgX
		centroidY += pos.avgY
		totalIDs++
	}
	centroidX /= float64(totalIDs)
	centroidY /= float64(totalIDs)

	// Sort IDs by distance from centroid
	type idWithDist struct {
		id   uint32
		dist float64
		pos  *idPos
	}
	var sortedIDs []idWithDist
	for id, pos := range idPositions {
		dx := pos.avgX - centroidX
		dy := pos.avgY - centroidY
		dist := math.Sqrt(dx*dx + dy*dy)
		sortedIDs = append(sortedIDs, idWithDist{id, dist, pos})
	}
	sort.Slice(sortedIDs, func(i, j int) bool {
		return sortedIDs[i].dist < sortedIDs[j].dist
	})

	// First half (closest to centroid) = defenders
	// Second half (farthest) = attackers
	defenderIDs := make([]idWithDist, 0)
	attackerIDs := make([]idWithDist, 0)
	
	for i, id := range sortedIDs {
		if i < len(sortedIDs)/2 || i < len(defenders) {
			defenderIDs = append(defenderIDs, id)
		} else {
			attackerIDs = append(attackerIDs, id)
		}
	}

	// Adjust to have exactly 5 of each if possible
	for len(defenderIDs) > len(defenders) && len(attackerIDs) < len(attackers) {
		last := defenderIDs[len(defenderIDs)-1]
		defenderIDs = defenderIDs[:len(defenderIDs)-1]
		attackerIDs = append([]idWithDist{last}, attackerIDs...)
	}
	for len(attackerIDs) > len(attackers) && len(defenderIDs) < len(defenders) {
		first := attackerIDs[0]
		attackerIDs = attackerIDs[1:]
		defenderIDs = append(defenderIDs, first)
	}

	fmt.Println("Defender IDs (closer to centroid/inside building):")
	for i, id := range defenderIDs {
		playerName := "?"
		if i < len(defenders) {
			playerName = defenders[i].Username
		}
		fmt.Printf("  ID %2d -> %s (pos: %.1f, %.1f)\n", 
			id.id, playerName, id.pos.avgX, id.pos.avgY)
	}

	fmt.Println("\nAttacker IDs (farther from centroid/at spawns):")
	for i, id := range attackerIDs {
		playerName := "?"
		if i < len(attackers) {
			playerName = attackers[i].Username
		}
		fmt.Printf("  ID %2d -> %s (pos: %.1f, %.1f)\n", 
			id.id, playerName, id.pos.avgX, id.pos.avgY)
	}

	// Try to match attackers by spawn location
	fmt.Println("\n=== SPAWN-BASED MATCHING (Attackers) ===")
	
	// Group attackers by spawn
	spawnGroups := make(map[string][]PlayerInfo)
	for _, p := range attackers {
		if p.Spawn != "" {
			spawnGroups[p.Spawn] = append(spawnGroups[p.Spawn], p)
		}
	}

	fmt.Println("Attacker spawns from header:")
	for spawn, ps := range spawnGroups {
		names := ""
		for _, p := range ps {
			if names != "" {
				names += ", "
			}
			names += p.Username
		}
		fmt.Printf("  %s: %s\n", spawn, names)
	}

	// Cluster attacker IDs by position
	fmt.Println("\nAttacker ID position clusters:")
	if len(attackerIDs) >= 2 {
		// Simple clustering: group by Y coordinate (spawn locations often differ in Y)
		sort.Slice(attackerIDs, func(i, j int) bool {
			return attackerIDs[i].pos.avgY < attackerIDs[j].pos.avgY
		})
		
		// Find natural breaks in Y
		fmt.Println("Attacker IDs sorted by Y position:")
		for _, id := range attackerIDs {
			fmt.Printf("  ID %2d: Y=%.1f, X=%.1f\n", id.id, id.pos.avgY, id.pos.avgX)
		}
	}

	// Final mapping suggestion
	fmt.Println("\n=== SUGGESTED ID MAPPING ===")
	fmt.Printf("%-6s %-15s %-12s %-10s\n", "ID", "Username", "Operator", "Team")
	fmt.Println("------------------------------------------------")
	
	// Build final mapping
	usedPlayers := make(map[string]bool)
	
	// Map defenders
	for i, id := range defenderIDs {
		if i < len(defenders) && !usedPlayers[defenders[i].Username] {
			fmt.Printf("%-6d %-15s %-12s %-10s\n", 
				id.id, defenders[i].Username, defenders[i].Operator, "Defense")
			usedPlayers[defenders[i].Username] = true
		}
	}
	
	// Map attackers
	for i, id := range attackerIDs {
		if i < len(attackers) && !usedPlayers[attackers[i].Username] {
			fmt.Printf("%-6d %-15s %-12s %-10s\n", 
				id.id, attackers[i].Username, attackers[i].Operator, "Attack")
			usedPlayers[attackers[i].Username] = true
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

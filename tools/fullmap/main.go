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
	PostBytes []byte
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
	players        []PlayerInfo
)

type PlayerInfo struct {
	Username string
	Operator string
	Team     string
	Spawn    string
	Index    int
}

type entityData struct {
	id          uint16
	packets     []PacketRecord
	stateChanges int
	firingBursts int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: fullmap <replay.rec>")
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

	r.Listen(positionMarker, capturePacket)
	r.Read()

	// Extract player info
	for i, p := range r.Header.Players {
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
			Index:    i,
		})
	}

	totalTime := 240.0
	timePerPacket := totalTime / float64(len(allPackets))

	// Build tracks from position data (type 0x03)
	fmt.Println("=== BUILDING POSITION TRACKS ===")
	
	type positionData struct {
		packetNum int
		x, y, z   float32
		posID     uint32
	}
	
	var positions []positionData
	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 24 {
			posID := binary.LittleEndian.Uint32(p.PostBytes[20:24])
			if posID >= 1 && posID <= 20 {
				positions = append(positions, positionData{
					packetNum: p.PacketNum,
					x:         p.X,
					y:         p.Y,
					z:         p.Z,
					posID:     posID,
				})
			}
		}
	}
	
	fmt.Printf("Found %d type 0x03 position packets\n", len(positions))

	// Group positions by posID
	posIDGroups := make(map[uint32][]positionData)
	for _, pos := range positions {
		posIDGroups[pos.posID] = append(posIDGroups[pos.posID], pos)
	}
	
	fmt.Printf("Found %d unique position IDs\n\n", len(posIDGroups))
	
	// For each posID, find first position to help identify team
	fmt.Println("Position ID starting positions:")
	
	type posIDInfo struct {
		id        uint32
		count     int
		firstX    float32
		firstY    float32
		likelyTeam string
	}
	
	var posIDInfos []posIDInfo
	for id, poses := range posIDGroups {
		if len(poses) < 100 {
			continue // Skip sparse IDs
		}
		
		// Get first position
		firstPos := poses[0]
		
		// Classify by spawn location
		team := "DEF" // Default - inside building
		if firstPos.y > 35 || firstPos.y < -10 || firstPos.x > 35 || firstPos.x < -35 {
			team = "ATK"
		}
		
		posIDInfos = append(posIDInfos, posIDInfo{
			id:         id,
			count:      len(poses),
			firstX:     firstPos.x,
			firstY:     firstPos.y,
			likelyTeam: team,
		})
	}
	
	sort.Slice(posIDInfos, func(i, j int) bool {
		return posIDInfos[i].count > posIDInfos[j].count
	})
	
	fmt.Printf("%-6s %-8s %-12s %-12s %-10s\n", "PosID", "Count", "FirstX", "FirstY", "LikelyTeam")
	fmt.Println("----------------------------------------------------")
	for _, info := range posIDInfos {
		fmt.Printf("%-6d %-8d %-12.1f %-12.1f %-10s\n", 
			info.id, info.count, info.firstX, info.firstY, info.likelyTeam)
	}

	// Extract entity IDs from type 0x08 packets
	fmt.Println("\n=== ENTITY ID ANALYSIS ===")
	
	entities := make(map[uint16]*entityData)
	
	for _, p := range allPackets {
		if p.Type2 == 0x08 && len(p.PostBytes) >= 4 {
			if p.PostBytes[0] == 0x01 && p.PostBytes[1] == 0x00 {
				entityID := binary.LittleEndian.Uint16(p.PostBytes[2:4])
				
				if _, exists := entities[entityID]; !exists {
					entities[entityID] = &entityData{id: entityID}
				}
				entities[entityID].packets = append(entities[entityID].packets, p)
			}
		}
	}

	// For each entity, correlate with position IDs
	fmt.Println("\nEntity to Position ID correlation:")
	
	type entityCorrelation struct {
		entityID     uint16
		bestPosID    uint32
		correlation  int
		firstSeen    float64
		lastSeen     float64
		stateChanges int
	}
	
	var correlations []entityCorrelation
	
	for entityID, entity := range entities {
		// Count co-occurrences with position IDs
		posIDCounts := make(map[uint32]int)
		
		for _, ep := range entity.packets {
			// Find position packets within 5 packets
			for _, p := range allPackets {
				if p.Type2 == 0x03 && abs(p.PacketNum-ep.PacketNum) <= 5 {
					if len(p.PostBytes) >= 24 {
						posID := binary.LittleEndian.Uint32(p.PostBytes[20:24])
						if posID >= 1 && posID <= 20 {
							posIDCounts[posID]++
						}
					}
				}
			}
		}
		
		// Find best matching position ID
		var bestID uint32
		bestCount := 0
		for id, count := range posIDCounts {
			if count > bestCount {
				bestCount = count
				bestID = id
			}
		}
		
		// Count state changes
		stateChanges := 0
		var lastState byte
		for _, ep := range entity.packets {
			if len(ep.PostBytes) > 31 {
				state := ep.PostBytes[31]
				if lastState != 0 && state != lastState {
					stateChanges++
				}
				lastState = state
			}
		}
		
		firstSeen := float64(entity.packets[0].PacketNum) * timePerPacket
		lastSeen := float64(entity.packets[len(entity.packets)-1].PacketNum) * timePerPacket
		
		correlations = append(correlations, entityCorrelation{
			entityID:     entityID,
			bestPosID:    bestID,
			correlation:  bestCount,
			firstSeen:    firstSeen,
			lastSeen:     lastSeen,
			stateChanges: stateChanges,
		})
	}
	
	sort.Slice(correlations, func(i, j int) bool {
		return correlations[i].correlation > correlations[j].correlation
	})
	
	fmt.Printf("\n%-8s %-8s %-12s %-12s %-12s %-12s\n", 
		"EntityID", "BestPosID", "Correlation", "FirstSeen", "LastSeen", "StateChg")
	fmt.Println("--------------------------------------------------------------------")
	for _, c := range correlations {
		fmt.Printf("0x%04X   %-8d %-12d %-12.1f %-12.1f %-12d\n",
			c.entityID, c.bestPosID, c.correlation, c.firstSeen, c.lastSeen, c.stateChanges)
	}

	// Now try to map everything to players
	fmt.Println("\n=== PLAYER MAPPING ATTEMPT ===")
	
	// Map position ID to starting position
	posIDStarts := make(map[uint32]struct{ x, y float32 })
	for id, poses := range posIDGroups {
		if len(poses) > 0 {
			posIDStarts[id] = struct{ x, y float32 }{poses[0].x, poses[0].y}
		}
	}
	
	// Group players by team
	var defenders, attackers []PlayerInfo
	for _, p := range players {
		if p.Team == "DEF" {
			defenders = append(defenders, p)
		} else {
			attackers = append(attackers, p)
		}
	}
	
	// Map entities to players based on position correlation and team
	fmt.Println("\nBest guess mapping:")
	fmt.Printf("\n%-8s -> %-8s -> %-15s %-10s %-12s\n", 
		"EntityID", "PosID", "Player", "Operator", "Team")
	fmt.Println("------------------------------------------------------------")
	
	// For attackers, use spawn location
	attackerPosIDs := make([]uint32, 0)
	defenderPosIDs := make([]uint32, 0)
	
	for _, info := range posIDInfos {
		if info.likelyTeam == "ATK" {
			attackerPosIDs = append(attackerPosIDs, info.id)
		} else {
			defenderPosIDs = append(defenderPosIDs, info.id)
		}
	}
	
	fmt.Printf("\nAttacker position IDs: %v\n", attackerPosIDs)
	fmt.Printf("Defender position IDs: %v\n", defenderPosIDs)
	
	// Match attackers by spawn
	fmt.Println("\nAttacker spawn analysis:")
	for _, posID := range attackerPosIDs {
		start := posIDStarts[posID]
		
		// Try to match to attacker by spawn
		spawnType := "Unknown"
		if start.y > 40 {
			spawnType = "Lakeside"
		} else if start.y < -5 {
			spawnType = "Campfire"
		}
		
		// Find matching attacker
		matchedPlayer := "?"
		for _, p := range attackers {
			if p.Spawn == spawnType {
				matchedPlayer = p.Username
				break // Take first match (not ideal but a start)
			}
		}
		
		fmt.Printf("  PosID %d: start=(%.1f, %.1f) -> %s spawn -> likely %s\n",
			posID, start.x, start.y, spawnType, matchedPlayer)
	}

	// Match entity to player via position
	fmt.Println("\n\nFINAL MAPPING (Entity -> PosID -> Player):")
	fmt.Println("------------------------------------------------------------")
	
	usedPlayers := make(map[string]bool)
	
	for _, c := range correlations {
		start, ok := posIDStarts[c.bestPosID]
		if !ok {
			continue
		}
		
		// Determine team from starting position
		isAttacker := start.y > 35 || start.y < -10 || start.x > 35 || start.x < -35
		
		// Find matching player
		matchedPlayer := PlayerInfo{Username: "?"}
		
		if isAttacker {
			// Match by spawn
			spawnType := "Unknown"
			if start.y > 40 {
				spawnType = "Lakeside"
			} else if start.y < -5 || start.x < -25 {
				spawnType = "Campfire"
			}
			
			for _, p := range attackers {
				if p.Spawn == spawnType && !usedPlayers[p.Username] {
					matchedPlayer = p
					usedPlayers[p.Username] = true
					break
				}
			}
		} else {
			// Defenders - just assign by order for now
			for _, p := range defenders {
				if !usedPlayers[p.Username] {
					matchedPlayer = p
					usedPlayers[p.Username] = true
					break
				}
			}
		}
		
		team := "DEF"
		if isAttacker {
			team = "ATK"
		}
		
		fmt.Printf("0x%04X   -> %-8d -> %-15s %-10s %-8s (start: %.1f, %.1f)\n",
			c.entityID, c.bestPosID, matchedPlayer.Username, matchedPlayer.Operator, team, start.x, start.y)
	}

	// Verify with kill data
	fmt.Println("\n=== KILL EVENT VERIFICATION ===")
	
	kills := []struct {
		time   float64
		killer string
		victim string
	}{
		{44, "Repuhrz", "Franklin.ALX"},
		{50, "Repuhrz", "Ewzy4KT"},
		{51, "Ewzy4KT", "hattttttttt"},
		{58, "Kiru.UNITY", "Solo.FF"},
		{72, "BjL-", "Inryo.ALX"},
		{73, "Franklin.ALX", "VicBands"},
		{84, "Repuhrz", "SpiffNP"},
	}
	
	for _, kill := range kills {
		fmt.Printf("\nKill at %.0fs: %s -> %s\n", kill.time, kill.killer, kill.victim)
		
		// Find entity activity around this time
		estPacketNum := int(kill.time / timePerPacket)
		
		for entityID, entity := range entities {
			for _, ep := range entity.packets {
				if abs(ep.PacketNum-estPacketNum) < 100 && len(ep.PostBytes) > 31 {
					// Check for state 5 (possibly firing)
					if ep.PostBytes[31] == 0x05 {
						t := float64(ep.PacketNum) * timePerPacket
						fmt.Printf("  Entity 0x%04X state=5 at %.1fs\n", entityID, t)
						break
					}
				}
			}
		}
	}
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

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		PostBytes: postBytes,
	})

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

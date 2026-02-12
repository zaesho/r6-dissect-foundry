package main

import (
	"encoding/binary"
	"encoding/hex"
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
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entitymap <replay.rec>")
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

	fmt.Println("=== PLAYERS ===")
	for i, p := range players {
		fmt.Printf("%d: %-15s %-10s %-5s %s\n", i, p.Username, p.Operator, p.Team, p.Spawn)
	}

	// Extract entity IDs from type 0x08 packets
	fmt.Println("\n=== TYPE 0x08 ENTITY ANALYSIS ===")
	
	type entityInfo struct {
		id         uint16  // bytes 2-3 of type 0x08 packet
		firstSeen  int
		lastSeen   int
		count      int
		firingHigh int // count of byte31 == 0x05
		firingLow  int // count of byte31 == 0x04
	}
	
	entities := make(map[uint16]*entityInfo)
	
	for _, p := range allPackets {
		if p.Type2 == 0x08 && len(p.PostBytes) >= 4 {
			// Check if it's the 0100XXXX pattern
			if p.PostBytes[0] == 0x01 && p.PostBytes[1] == 0x00 {
				entityID := binary.LittleEndian.Uint16(p.PostBytes[2:4])
				
				if _, exists := entities[entityID]; !exists {
					entities[entityID] = &entityInfo{
						id:        entityID,
						firstSeen: p.PacketNum,
					}
				}
				
				e := entities[entityID]
				e.lastSeen = p.PacketNum
				e.count++
				
				if len(p.PostBytes) > 31 {
					if p.PostBytes[31] == 0x05 {
						e.firingHigh++
					} else if p.PostBytes[31] == 0x04 {
						e.firingLow++
					}
				}
			}
		}
	}

	// Sort entities by count
	type entitySort struct {
		id   uint16
		info *entityInfo
	}
	var sorted []entitySort
	for id, info := range entities {
		sorted = append(sorted, entitySort{id, info})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].info.count > sorted[j].info.count
	})

	totalTime := 240.0
	timePerPacket := totalTime / float64(len(allPackets))

	fmt.Printf("\n%d unique entity IDs found in type 0x08 packets:\n\n", len(sorted))
	fmt.Printf("%-8s %-8s %-12s %-12s %-8s %-8s\n", 
		"ID", "Count", "FirstSeen", "LastSeen", "State5", "State4")
	fmt.Println("------------------------------------------------------------")
	
	for _, es := range sorted {
		firstTime := float64(es.info.firstSeen) * timePerPacket
		lastTime := float64(es.info.lastSeen) * timePerPacket
		fmt.Printf("0x%04X   %-8d %.1fs        %.1fs        %-8d %-8d\n",
			es.id, es.info.count, firstTime, lastTime, es.info.firingHigh, es.info.firingLow)
	}

	// Try to correlate entity IDs with position data
	fmt.Println("\n=== POSITION-ENTITY CORRELATION ===")
	
	// For each entity, find nearby position packets and see if there's a consistent ID
	fmt.Println("Looking at position packets near each entity event...")
	
	for _, es := range sorted[:min(5, len(sorted))] {
		fmt.Printf("\nEntity 0x%04X:\n", es.id)
		
		// Find all type 0x08 packets for this entity
		var entityPacketNums []int
		for _, p := range allPackets {
			if p.Type2 == 0x08 && len(p.PostBytes) >= 4 &&
				p.PostBytes[0] == 0x01 && p.PostBytes[1] == 0x00 {
				entityID := binary.LittleEndian.Uint16(p.PostBytes[2:4])
				if entityID == es.id {
					entityPacketNums = append(entityPacketNums, p.PacketNum)
				}
			}
		}
		
		// For each entity event, look at nearby type 0x03 position packets
		idCounts := make(map[uint32]int)
		for _, pktNum := range entityPacketNums {
			// Find nearest type 0x03 packets
			for _, p := range allPackets {
				if p.Type2 == 0x03 && abs(p.PacketNum-pktNum) < 10 {
					if len(p.PostBytes) >= 24 {
						posID := binary.LittleEndian.Uint32(p.PostBytes[20:24])
						if posID >= 1 && posID <= 20 {
							idCounts[posID]++
						}
					}
				}
			}
		}
		
		if len(idCounts) > 0 {
			fmt.Print("  Correlated position IDs: ")
			for id, count := range idCounts {
				if count >= 3 {
					fmt.Printf("%d(%d) ", id, count)
				}
			}
			fmt.Println()
		}
	}

	// Look for patterns that might indicate weapon firing
	fmt.Println("\n\n=== WEAPON FIRE PATTERN SEARCH ===")
	
	// Type 0x08 packets with byte31=0x05 might be firing
	fmt.Println("\nAnalyzing state changes in type 0x08 packets...")
	
	// Group by entity and look at state transitions
	for _, es := range sorted[:min(3, len(sorted))] {
		fmt.Printf("\nEntity 0x%04X state timeline:\n", es.id)
		
		var lastState byte
		stateChanges := 0
		for _, p := range allPackets {
			if p.Type2 == 0x08 && len(p.PostBytes) >= 32 &&
				p.PostBytes[0] == 0x01 && p.PostBytes[1] == 0x00 {
				entityID := binary.LittleEndian.Uint16(p.PostBytes[2:4])
				if entityID == es.id {
					state := p.PostBytes[31]
					if state != lastState && lastState != 0 {
						t := float64(p.PacketNum) * timePerPacket
						fmt.Printf("  %.1fs: state %d -> %d\n", t, lastState, state)
						stateChanges++
					}
					lastState = state
				}
			}
			if stateChanges >= 10 {
				fmt.Printf("  ... (more state changes)\n")
				break
			}
		}
	}

	// Analyze post-bytes byte 4 which also varies
	fmt.Println("\n=== BYTE 4 ANALYSIS (Type 0x08) ===")
	byte4Counts := make(map[byte]int)
	for _, p := range allPackets {
		if p.Type2 == 0x08 && len(p.PostBytes) >= 5 {
			byte4Counts[p.PostBytes[4]]++
		}
	}
	fmt.Println("Byte 4 values in type 0x08 packets:")
	for v, c := range byte4Counts {
		fmt.Printf("  0x%02X: %d times\n", v, c)
	}

	// Look at the actual hex dump of a few type 0x08 packets with context
	fmt.Println("\n=== DETAILED TYPE 0x08 SAMPLES ===")
	
	sampleCount := 0
	for _, p := range allPackets {
		if p.Type2 == 0x08 && p.PostBytes[0] == 0x01 && sampleCount < 5 {
			t := float64(p.PacketNum) * timePerPacket
			fmt.Printf("\nPacket #%d at %.1fs:\n", p.PacketNum, t)
			fmt.Printf("  Type: 0x%02X 0x%02X\n", p.Type1, p.Type2)
			fmt.Printf("  Pos: (%.2f, %.2f, %.2f)\n", p.X, p.Y, p.Z)
			fmt.Printf("  PostBytes [0:8]:   %s\n", hex.EncodeToString(p.PostBytes[0:8]))
			fmt.Printf("  PostBytes [8:16]:  %s\n", hex.EncodeToString(p.PostBytes[8:16]))
			fmt.Printf("  PostBytes [16:24]: %s\n", hex.EncodeToString(p.PostBytes[16:24]))
			fmt.Printf("  PostBytes [24:32]: %s\n", hex.EncodeToString(p.PostBytes[24:32]))
			fmt.Printf("  PostBytes [32:40]: %s\n", hex.EncodeToString(p.PostBytes[32:40]))
			
			// Parse key fields
			entityID := binary.LittleEndian.Uint16(p.PostBytes[2:4])
			flag := p.PostBytes[4]
			state := p.PostBytes[31]
			fmt.Printf("  Parsed: entityID=0x%04X flag=0x%02X state=%d\n", entityID, flag, state)
			
			sampleCount++
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

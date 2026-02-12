package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"

	"github.com/klauspost/compress/zstd"
	"github.com/redraskal/r6-dissect/dissect"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

// Track entity ID -> player ID mappings
type entityPlayerMapping struct {
	entityID  uint32
	playerIDs map[uint32]int // playerID -> count
	count     int
	firstX    float32
	firstY    float32
}

type PlayerInfo struct {
	Username  string
	Operator  string
	Team      string
	Index     int
	DissectID []byte
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entity_player_link <replay.rec>")
		os.Exit(1)
	}

	// First read with dissect to get player info
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	r.Read()
	f.Close()

	// Extract player info
	var players []PlayerInfo
	fmt.Println("=== HEADER PLAYERS ===")
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
			Username:  p.Username,
			Operator:  p.Operator.String(),
			Team:      team,
			Index:     i,
			DissectID: p.DissectID,
		})
		fmt.Printf("  [%d] %-15s (%s) %-12s DissectID=%x\n", i, p.Username, team, p.Operator.String(), p.DissectID)
	}

	// Now scan raw data
	f, err = os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		fmt.Printf("Error decompressing: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nDecompressed size: %d bytes\n", len(data))

	// Scan for movement packets and extract both entity ID and player ID
	mappings := make(map[uint32]*entityPlayerMapping)

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if pos+36 > len(data) { // Need at least 2 + 12 + 24 bytes after marker
			continue
		}

		typeFirst := data[pos]
		typeSecond := data[pos+1]

		// Only type 0x03 has the player ID field
		if typeSecond != 0x03 {
			continue
		}
		if typeFirst < 0xB0 {
			continue
		}

		// Coordinates at pos+2
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+6 : pos+10]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+10 : pos+14]))

		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}
		if z < -10 || z > 50 {
			continue
		}

		// Entity ID is 4 bytes BEFORE the marker
		if i < 4 {
			continue
		}
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		// Player ID is at bytes 20-23 AFTER the coordinates (offset 14+20 from marker+6)
		// So: marker(6) + type(2) + coords(12) + 20 = offset 40 from marker
		// Player ID at pos + 2 + 12 + 20 = pos + 34
		playerIDOffset := pos + 2 + 12 + 20
		if playerIDOffset+4 > len(data) {
			continue
		}
		playerID := binary.LittleEndian.Uint32(data[playerIDOffset : playerIDOffset+4])

		// Record the mapping
		if mappings[entityID] == nil {
			mappings[entityID] = &entityPlayerMapping{
				entityID:  entityID,
				playerIDs: make(map[uint32]int),
				firstX:    x,
				firstY:    y,
			}
		}
		mappings[entityID].playerIDs[playerID]++
		mappings[entityID].count++
	}

	// Sort mappings by count
	var sorted []*entityPlayerMapping
	for _, m := range mappings {
		sorted = append(sorted, m)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	fmt.Println("\n=== ENTITY -> PLAYER ID MAPPINGS (type 0x03 only) ===")
	fmt.Printf("%-12s %8s %-40s %15s\n", "EntityID", "Count", "PlayerIDs (count)", "First Pos")
	fmt.Println("----------------------------------------------------------------------------------")

	for _, m := range sorted {
		if m.count < 20 {
			continue
		}

		// Build player ID string - show top 5
		type idCount struct {
			id    uint32
			count int
		}
		var idCounts []idCount
		for id, cnt := range m.playerIDs {
			idCounts = append(idCounts, idCount{id, cnt})
		}
		sort.Slice(idCounts, func(i, j int) bool {
			return idCounts[i].count > idCounts[j].count
		})

		playerIDStr := ""
		for i, ic := range idCounts {
			if i >= 5 {
				playerIDStr += fmt.Sprintf(" +%d", len(idCounts)-5)
				break
			}
			playerIDStr += fmt.Sprintf("%d(%d) ", ic.id, ic.count)
		}

		pos := fmt.Sprintf("(%.1f, %.1f)", m.firstX, m.firstY)
		fmt.Printf("0x%08x %8d %-40s %15s\n", m.entityID, m.count, playerIDStr, pos)
	}

	// Analyze dominant player ID for each entity
	fmt.Println("\n=== DOMINANT PLAYER ID PER ENTITY ===")
	fmt.Printf("%-12s %6s %10s %6s %-20s\n", "EntityID", "Count", "PlayerID", "Pct", "Mapped Player")
	fmt.Println("----------------------------------------------------------------------")

	for _, m := range sorted {
		if m.count < 50 {
			continue
		}

		// Find dominant player ID
		var dominantID uint32
		dominantCount := 0
		for id, cnt := range m.playerIDs {
			if cnt > dominantCount {
				dominantCount = cnt
				dominantID = id
			}
		}

		pct := float64(dominantCount) / float64(m.count) * 100

		// Try to map player ID to header player
		mappedPlayer := "?"
		
		// Direct index mapping
		if dominantID < uint32(len(players)) {
			mappedPlayer = fmt.Sprintf("[%d] %s", dominantID, players[dominantID].Username)
		} else if dominantID >= 5 && int(dominantID-5) < len(players) {
			mappedPlayer = fmt.Sprintf("[%d-5=%d] %s", dominantID, dominantID-5, players[dominantID-5].Username)
		}

		fmt.Printf("0x%08x %6d %10d %5.1f%% %-20s\n", m.entityID, m.count, dominantID, pct, mappedPlayer)
	}

	// Look at player ID values
	fmt.Println("\n=== ALL PLAYER ID VALUES ===")
	allPlayerIDs := make(map[uint32]int)
	for _, m := range mappings {
		for id, cnt := range m.playerIDs {
			allPlayerIDs[id] += cnt
		}
	}

	type pidFreq struct {
		id    uint32
		count int
	}
	var pidFreqs []pidFreq
	for id, cnt := range allPlayerIDs {
		pidFreqs = append(pidFreqs, pidFreq{id, cnt})
	}
	sort.Slice(pidFreqs, func(i, j int) bool {
		return pidFreqs[i].count > pidFreqs[j].count
	})

	fmt.Printf("%-12s %8s %12s\n", "PlayerID", "Count", "Hex")
	for _, pf := range pidFreqs {
		if pf.count < 50 {
			continue
		}
		fmt.Printf("%-12d %8d 0x%08x\n", pf.id, pf.count, pf.id)
	}

	// Check if player IDs match small integers (5-14 for 10 players)
	fmt.Println("\n=== CHECKING PLAYER ID -> PLAYER MAPPING ===")
	for _, pf := range pidFreqs {
		if pf.id >= 5 && pf.id <= 14 && pf.count >= 100 {
			idx := int(pf.id - 5)
			if idx < len(players) {
				fmt.Printf("  PlayerID %d (count=%d) -> Player[%d] = %s (%s)\n",
					pf.id, pf.count, idx, players[idx].Username, players[idx].Team)
			}
		}
	}

	// Cross-check: for each entity with a dominant player ID in range 5-14,
	// see if the entity belongs to that player
	fmt.Println("\n=== FINAL ENTITY -> PLAYER MAPPING ===")
	fmt.Printf("%-12s %-15s %-12s %-6s\n", "EntityID", "Player", "Operator", "Team")
	fmt.Println("-------------------------------------------------------")

	for _, m := range sorted {
		if m.count < 100 {
			continue
		}

		// Find dominant player ID
		var dominantID uint32
		dominantCount := 0
		for id, cnt := range m.playerIDs {
			if cnt > dominantCount {
				dominantCount = cnt
				dominantID = id
			}
		}

		// Only use if the dominant ID is consistent (>80% of packets)
		if float64(dominantCount)/float64(m.count) < 0.7 {
			continue
		}

		// Map to player
		if dominantID >= 5 && dominantID <= 14 {
			idx := int(dominantID - 5)
			if idx < len(players) {
				fmt.Printf("0x%08x %-15s %-12s %-6s\n",
					m.entityID, players[idx].Username, players[idx].Operator, players[idx].Team)
			}
		}
	}
}

func decompressReplay(f *os.File) ([]byte, error) {
	br := bufio.NewReader(f)
	temp, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}

	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	isChunked := false
	for i := 0; i < len(temp)-4; i++ {
		if bytes.Equal(temp[i:i+4], zstdMagic) {
			for j := i + 100; j < len(temp)-4; j++ {
				if bytes.Equal(temp[j:j+4], zstdMagic) {
					isChunked = true
					break
				}
			}
			break
		}
	}

	if isChunked {
		zstdReader, _ := zstd.NewReader(nil)
		var result []byte
		offset := 0
		for {
			found := false
			for ; offset < len(temp)-4; offset++ {
				if bytes.Equal(temp[offset:offset+4], zstdMagic) {
					found = true
					break
				}
			}
			if !found {
				break
			}

			chunkReader := bytes.NewReader(temp[offset:])
			if err := zstdReader.Reset(chunkReader); err != nil {
				offset++
				continue
			}
			chunk, err := io.ReadAll(zstdReader)
			if err != nil && !errors.Is(err, zstd.ErrMagicMismatch) {
				if len(chunk) == 0 {
					offset++
					continue
				}
			}
			result = append(result, chunk...)
			offset += 4
		}
		return result, nil
	} else {
		f.Seek(0, 0)
		zstdReader, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(zstdReader)
	}
}

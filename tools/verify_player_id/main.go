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
	"path/filepath"
	"sort"

	"github.com/klauspost/compress/zstd"
	"github.com/redraskal/r6-dissect/dissect"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

type entityMapping struct {
	entityID       uint32
	playerID       uint32 // dominant player ID
	playerIDCount  int
	totalCount     int
	playerUsername string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: verify_player_id <replay.rec> [replay2.rec ...]")
		fmt.Println("       verify_player_id <match_folder>")
		os.Exit(1)
	}

	var files []string
	stat, err := os.Stat(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if stat.IsDir() {
		matches, _ := filepath.Glob(filepath.Join(os.Args[1], "*.rec"))
		files = append(files, matches...)
		sort.Strings(files)
	} else {
		files = os.Args[1:]
	}

	if len(files) == 0 {
		fmt.Println("No .rec files found")
		os.Exit(1)
	}

	fmt.Printf("Analyzing %d replay files...\n\n", len(files))

	// Process each file
	for _, file := range files {
		fmt.Printf("\n=== %s ===\n", filepath.Base(file))
		analyzeReplay(file)
	}
}

func analyzeReplay(filename string) {
	// First read with dissect to get player info
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		f.Close()
		return
	}
	r.Read()
	f.Close()

	// Build player lookup
	type playerInfo struct {
		username string
		team     string
		index    int
	}
	players := make(map[int]playerInfo) // index -> player info
	
	fmt.Println("Players:")
	for i, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				team = "ATK"
			} else {
				team = "DEF"
			}
		}
		players[i] = playerInfo{p.Username, team, i}
		fmt.Printf("  [%d] -> PlayerID %d: %-15s (%s)\n", i, i+5, p.Username, team)
	}

	// Now scan raw data for BOTH type 0x01 and 0x03 packets
	f, err = os.Open(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		fmt.Println("Error decompressing:", err)
		return
	}

	// Track entity -> player mappings separately for 0x01 and 0x03
	type01Mappings := make(map[uint32]map[uint32]int) // entityID -> playerID -> count
	type03Mappings := make(map[uint32]map[uint32]int)

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if pos+50 > len(data) {
			continue
		}

		typeFirst := data[pos]
		typeSecond := data[pos+1]

		if typeSecond != 0x01 && typeSecond != 0x03 {
			continue
		}
		if typeFirst < 0xB0 {
			continue
		}

		// Validate coordinates
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		// Entity ID is 4 bytes before marker
		if i < 4 {
			continue
		}
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		if typeSecond == 0x01 {
			// Type 0x01: check bytes 4-7 after coordinates (offset 14+4 from pos)
			playerIDOffset := pos + 2 + 12 + 4
			if playerIDOffset+4 <= len(data) {
				playerID := binary.LittleEndian.Uint32(data[playerIDOffset : playerIDOffset+4])
				if type01Mappings[entityID] == nil {
					type01Mappings[entityID] = make(map[uint32]int)
				}
				type01Mappings[entityID][playerID]++
			}
		} else { // 0x03
			// Type 0x03: check bytes 20-23 after coordinates
			playerIDOffset := pos + 2 + 12 + 20
			if playerIDOffset+4 <= len(data) {
				playerID := binary.LittleEndian.Uint32(data[playerIDOffset : playerIDOffset+4])
				if type03Mappings[entityID] == nil {
					type03Mappings[entityID] = make(map[uint32]int)
				}
				type03Mappings[entityID][playerID]++
			}
		}
	}

	// Analyze type 0x03 mappings
	fmt.Println("\nType 0x03 Entity -> Player Mapping:")
	fmt.Printf("%-12s %6s %8s %6s %-20s\n", "EntityID", "Count", "PlayerID", "Match%", "Player")
	fmt.Println("------------------------------------------------------------")

	var type03Results []entityMapping
	for entityID, playerIDs := range type03Mappings {
		// Find dominant player ID
		var dominantID uint32
		dominantCount := 0
		totalCount := 0
		for id, cnt := range playerIDs {
			totalCount += cnt
			if cnt > dominantCount {
				dominantCount = cnt
				dominantID = id
			}
		}

		if totalCount < 50 {
			continue
		}

		// Map to player
		username := "?"
		if dominantID >= 5 && int(dominantID-5) < len(players) {
			username = players[int(dominantID-5)].username
		}

		type03Results = append(type03Results, entityMapping{
			entityID:       entityID,
			playerID:       dominantID,
			playerIDCount:  dominantCount,
			totalCount:     totalCount,
			playerUsername: username,
		})
	}

	sort.Slice(type03Results, func(i, j int) bool {
		return type03Results[i].totalCount > type03Results[j].totalCount
	})

	for _, m := range type03Results {
		pct := float64(m.playerIDCount) / float64(m.totalCount) * 100
		fmt.Printf("0x%08x %6d %8d %5.1f%% %-20s\n",
			m.entityID, m.totalCount, m.playerID, pct, m.playerUsername)
	}

	// Analyze type 0x01 mappings
	fmt.Println("\nType 0x01 Entity -> Player Mapping (bytes 4-7):")
	fmt.Printf("%-12s %6s %8s %6s\n", "EntityID", "Count", "PlayerID", "Match%")
	fmt.Println("--------------------------------------------")

	var type01Results []entityMapping
	for entityID, playerIDs := range type01Mappings {
		var dominantID uint32
		dominantCount := 0
		totalCount := 0
		for id, cnt := range playerIDs {
			totalCount += cnt
			if cnt > dominantCount {
				dominantCount = cnt
				dominantID = id
			}
		}

		if totalCount < 50 {
			continue
		}

		type01Results = append(type01Results, entityMapping{
			entityID:      entityID,
			playerID:      dominantID,
			playerIDCount: dominantCount,
			totalCount:    totalCount,
		})
	}

	sort.Slice(type01Results, func(i, j int) bool {
		return type01Results[i].totalCount > type01Results[j].totalCount
	})

	for _, m := range type01Results[:min(10, len(type01Results))] {
		pct := float64(m.playerIDCount) / float64(m.totalCount) * 100
		fmt.Printf("0x%08x %6d %8d %5.1f%%\n",
			m.entityID, m.totalCount, m.playerID, pct)
	}

	// Summary: count unique player identifications
	fmt.Println("\nSummary - Players identified via type 0x03:")
	playerEntityCount := make(map[string]int)
	for _, m := range type03Results {
		if m.playerUsername != "?" && float64(m.playerIDCount)/float64(m.totalCount) > 0.9 {
			playerEntityCount[m.playerUsername]++
		}
	}
	
	for username, count := range playerEntityCount {
		fmt.Printf("  %-15s: %d entities\n", username, count)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

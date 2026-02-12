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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: packetformat <replay.rec>")
		os.Exit(1)
	}

	// Read with dissect
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	if err := r.Read(); err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading:", err)
	}
	f.Close()

	fmt.Println("=== PLAYER DISSECT IDs ===")
	for _, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "ATK"
			} else {
				teamRole = "DEF"
			}
		}
		fmt.Printf("%-15s (%s): %x\n", p.Username, teamRole, p.DissectID)
	}

	// Analyze raw data
	f, err = os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		fmt.Println("Error decompressing:", err)
		os.Exit(1)
	}

	// Analyze the pre-marker structure in detail
	// Looking at patterns like: XXXX4601f0 or XXXX4501f0
	fmt.Println("\n=== ANALYZING PRE-MARKER 'XX46/45/4701f0' PATTERNS ===")

	type preIDInfo struct {
		preID    uint32 // The 4 bytes ending in 01f0/00f0
		count    int
		entities map[uint32]int
	}
	preIDMap := make(map[uint32]*preIDInfo)

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if pos+14 > len(data) {
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

		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		if i < 12 {
			continue
		}

		// Pre-marker layout (16 bytes before marker):
		// [0-3]  : unknown
		// [4-7]  : unknown  
		// [8-11] : preID (often ending in 01f0)
		// [12-15]: entityID
		preID := binary.LittleEndian.Uint32(data[i-8 : i-4])
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		// Only look at IDs ending in f001 or f000
		if (preID & 0xFFFF) == 0xf001 || (preID & 0xFFFF) == 0xf000 {
			if preIDMap[preID] == nil {
				preIDMap[preID] = &preIDInfo{preID: preID, entities: make(map[uint32]int)}
			}
			preIDMap[preID].count++
			preIDMap[preID].entities[entityID]++
		}
	}

	// Sort and display
	var preIDs []*preIDInfo
	for _, p := range preIDMap {
		preIDs = append(preIDs, p)
	}
	sort.Slice(preIDs, func(i, j int) bool {
		return preIDs[i].count > preIDs[j].count
	})

	fmt.Printf("\n%-12s %8s %12s %s\n", "PreID", "Count", "Hi16", "Top Entities")
	for i, p := range preIDs {
		if i >= 20 {
			break
		}
		hi16 := (p.preID >> 16) & 0xFFFF
		
		// Get top 3 entities
		var entities []struct {
			id    uint32
			count int
		}
		for eid, cnt := range p.entities {
			entities = append(entities, struct {
				id    uint32
				count int
			}{eid, cnt})
		}
		sort.Slice(entities, func(a, b int) bool {
			return entities[a].count > entities[b].count
		})
		
		topEntities := ""
		for j, e := range entities {
			if j >= 3 {
				break
			}
			if j > 0 {
				topEntities += ", "
			}
			topEntities += fmt.Sprintf("0x%08x(%d)", e.id, e.count)
		}
		
		fmt.Printf("0x%08x %8d %12x %s\n", p.preID, p.count, hi16, topEntities)
	}

	// Now let's see if hi16 of preID matches anything in player data
	fmt.Println("\n=== CHECKING IF PRE-ID HI16 CORRELATES WITH DISSECT ID ===")
	for _, p := range preIDs[:min(10, len(preIDs))] {
		hi16 := (p.preID >> 16) & 0xFFFF
		fmt.Printf("\nPreID 0x%08x (hi16=0x%04x=%d):\n", p.preID, hi16, hi16)
		
		// Check DissectIDs
		for _, player := range r.Header.Players {
			if len(player.DissectID) < 2 {
				continue
			}
			// Extract bytes from DissectID
			did0 := uint32(player.DissectID[0])
			did1 := uint32(player.DissectID[1])
			didCombo := (did1 << 8) | did0
			
			if didCombo == hi16 {
				fmt.Printf("  -> MATCH with %s DissectID!\n", player.Username)
			}
		}
	}

	// Look at the actual byte layout more carefully
	fmt.Println("\n=== DETAILED BYTE LAYOUT FOR TOP ENTITIES ===")
	topEntities := []uint32{0x008e0000, 0x04840000, 0x04c00000, 0x00af0000, 0x047e0000}
	
	for _, targetEntity := range topEntities {
		fmt.Printf("\nEntity 0x%08x:\n", targetEntity)
		count := 0
		for i := 32; i < len(data)-100 && count < 3; i++ {
			if !bytes.Equal(data[i:i+6], movementMarker) {
				continue
			}

			pos := i + 6
			if pos+14 > len(data) {
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

			entityID := binary.LittleEndian.Uint32(data[i-4 : i])
			if entityID != targetEntity {
				continue
			}

			x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
			if math.IsNaN(float64(x)) || x < -100 || x > 100 {
				continue
			}

			count++
			// Show 32 bytes before marker with annotations
			preBytes := data[i-32 : i]
			fmt.Printf("  Pre-marker 32 bytes:\n")
			fmt.Printf("    [0-7]  : %x\n", preBytes[0:8])
			fmt.Printf("    [8-15] : %x\n", preBytes[8:16])
			fmt.Printf("    [16-23]: %x\n", preBytes[16:24])
			fmt.Printf("    [24-27]: %x (preID)\n", preBytes[24:28])
			fmt.Printf("    [28-31]: %x (entityID)\n", preBytes[28:32])
		}
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

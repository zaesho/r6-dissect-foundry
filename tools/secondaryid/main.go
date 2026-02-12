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
		fmt.Println("Usage: secondaryid <replay.rec>")
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

	// Extract the secondary ID (4 bytes at offset -8 to -4 before marker)
	// and the entity ID (4 bytes at offset -4 to 0 before marker)
	type idPair struct {
		secondaryID uint32
		entityID    uint32
		count       int
		firstX      float32
		firstY      float32
	}

	idPairs := make(map[uint64]*idPair) // key is (secondaryID << 32) | entityID

	secondaryIDCounts := make(map[uint32]int)
	entityIDCounts := make(map[uint32]int)

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
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+6 : pos+10]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		// Extract IDs
		if i < 8 {
			continue
		}
		secondaryID := binary.LittleEndian.Uint32(data[i-8 : i-4])
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		secondaryIDCounts[secondaryID]++
		entityIDCounts[entityID]++

		key := (uint64(secondaryID) << 32) | uint64(entityID)
		if idPairs[key] == nil {
			idPairs[key] = &idPair{secondaryID: secondaryID, entityID: entityID, firstX: x, firstY: y}
		}
		idPairs[key].count++
	}

	// Analyze secondary IDs
	fmt.Println("\n=== SECONDARY IDs (4 bytes at offset -8) ===")
	type idCount struct {
		id    uint32
		count int
	}
	var secIDs []idCount
	for id, count := range secondaryIDCounts {
		secIDs = append(secIDs, idCount{id, count})
	}
	sort.Slice(secIDs, func(i, j int) bool {
		return secIDs[i].count > secIDs[j].count
	})

	fmt.Printf("%-12s %8s %12s\n", "ID", "Count", "Hi/Lo bytes")
	for i, s := range secIDs {
		if i >= 15 {
			break
		}
		hi := (s.id >> 16) & 0xFFFF
		lo := s.id & 0xFFFF
		// Also show as bytes
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, s.id)
		fmt.Printf("0x%08x %8d   %02x%02x %02x%02x (hi=0x%04x lo=0x%04x)\n", 
			s.id, s.count, b[0], b[1], b[2], b[3], hi, lo)
	}

	// Check if secondary IDs match DissectID patterns
	fmt.Println("\n=== CHECKING SECONDARY ID vs DISSECT ID ===")
	for _, p := range r.Header.Players {
		if len(p.DissectID) < 4 {
			continue
		}
		dissectU32 := binary.LittleEndian.Uint32(p.DissectID[:4])
		
		// Check if this appears in secondary IDs
		if count, ok := secondaryIDCounts[dissectU32]; ok {
			fmt.Printf("MATCH: %s's DissectID 0x%08x appears %d times as secondary ID!\n", 
				p.Username, dissectU32, count)
		}
		
		// Also check byte-swapped
		swapped := ((dissectU32 & 0xFF) << 24) | ((dissectU32 & 0xFF00) << 8) | 
			((dissectU32 >> 8) & 0xFF00) | ((dissectU32 >> 24) & 0xFF)
		if count, ok := secondaryIDCounts[swapped]; ok {
			fmt.Printf("MATCH (swapped): %s's DissectID 0x%08x appears %d times!\n", 
				p.Username, swapped, count)
		}
	}

	// Analyze the ID pairs - which secondary IDs go with which entity IDs
	fmt.Println("\n=== ID PAIR ANALYSIS ===")
	var pairs []*idPair
	for _, p := range idPairs {
		pairs = append(pairs, p)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})

	fmt.Printf("%-12s %-12s %8s %25s\n", "SecondaryID", "EntityID", "Count", "First Pos")
	for i, p := range pairs {
		if i >= 20 {
			break
		}
		pos := fmt.Sprintf("(%.1f, %.1f)", p.firstX, p.firstY)
		fmt.Printf("0x%08x 0x%08x %8d %25s\n", p.secondaryID, p.entityID, p.count, pos)
	}

	// Group by secondary ID to see which entity IDs it maps to
	fmt.Println("\n=== ENTITY IDs PER SECONDARY ID ===")
	secToEntities := make(map[uint32]map[uint32]int)
	for _, p := range pairs {
		if secToEntities[p.secondaryID] == nil {
			secToEntities[p.secondaryID] = make(map[uint32]int)
		}
		secToEntities[p.secondaryID][p.entityID] += p.count
	}

	for i, s := range secIDs {
		if i >= 10 {
			break
		}
		entities := secToEntities[s.id]
		if len(entities) > 0 {
			fmt.Printf("\nSecondary 0x%08x (%d total) maps to %d entity IDs:\n", s.id, s.count, len(entities))
			var entityList []idCount
			for eid, cnt := range entities {
				entityList = append(entityList, idCount{eid, cnt})
			}
			sort.Slice(entityList, func(i, j int) bool {
				return entityList[i].count > entityList[j].count
			})
			for j, e := range entityList {
				if j >= 5 {
					fmt.Printf("    ... and %d more\n", len(entityList)-5)
					break
				}
				fmt.Printf("    Entity 0x%08x: %d packets\n", e.id, e.count)
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

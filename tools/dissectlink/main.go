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
		fmt.Println("Usage: dissectlink <replay.rec>")
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

	// Store DissectIDs for matching
	type playerInfo struct {
		username   string
		team       string
		dissectID  []byte
		dissectU32 uint32
	}
	var players []playerInfo

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
		var dissectU32 uint32
		if len(p.DissectID) >= 4 {
			dissectU32 = binary.LittleEndian.Uint32(p.DissectID[:4])
		}
		players = append(players, playerInfo{p.Username, teamRole, p.DissectID, dissectU32})
		fmt.Printf("%-15s (%s): %x (as LE uint32: 0x%08x)\n", p.Username, teamRole, p.DissectID, dissectU32)
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

	// For each movement packet, check pre-marker bytes for DissectID patterns
	type matchInfo struct {
		entityID   uint32
		prePattern []byte
		positions  int
		matchedTo  string
	}

	entityMatches := make(map[uint32]*matchInfo)
	pktNum := 0

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if pos+2 > len(data) {
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
		pos += 2

		if pos+12 > len(data) {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		pktNum++
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		if entityMatches[entityID] == nil {
			prePattern := make([]byte, 16)
			if i >= 16 {
				copy(prePattern, data[i-16:i])
			}
			entityMatches[entityID] = &matchInfo{entityID: entityID, prePattern: prePattern}
		}
		entityMatches[entityID].positions++
	}

	// Sort by position count
	var matches []*matchInfo
	for _, m := range entityMatches {
		matches = append(matches, m)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].positions > matches[j].positions
	})

	// Now check if any DissectID appears in the pre-marker patterns
	fmt.Println("\n=== SEARCHING FOR DISSECT ID PATTERNS IN PRE-MARKER BYTES ===")
	for _, m := range matches[:min(15, len(matches))] {
		fmt.Printf("\nEntity 0x%08x (%d positions):\n", m.entityID, m.positions)
		fmt.Printf("  Pre-marker: %x\n", m.prePattern)

		// Check each byte position for DissectID match
		for _, p := range players {
			if len(p.dissectID) < 4 {
				continue
			}
			// Look for the DissectID bytes anywhere in the pre-marker
			for offset := 0; offset <= len(m.prePattern)-4; offset++ {
				if bytes.Equal(m.prePattern[offset:offset+4], p.dissectID[:4]) {
					fmt.Printf("  -> FOUND %s DissectID at offset %d!\n", p.username, offset)
					m.matchedTo = p.username
				}
			}
			// Also check for partial matches (first 2 bytes)
			for offset := 0; offset <= len(m.prePattern)-2; offset++ {
				if bytes.Equal(m.prePattern[offset:offset+2], p.dissectID[:2]) {
					fmt.Printf("  -> Partial match (2 bytes) with %s at offset %d\n", p.username, offset)
				}
			}
		}
	}

	// Now search globally for DissectID patterns near movement markers
	fmt.Println("\n=== GLOBAL SEARCH: DISSECT IDs WITHIN 50 BYTES OF MOVEMENT MARKERS ===")
	dissectIDLocations := make(map[string][]int)

	for i := 50; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		// Search 50 bytes before and after marker for DissectIDs
		searchStart := i - 50
		searchEnd := i + 50
		if searchStart < 0 {
			searchStart = 0
		}
		if searchEnd > len(data) {
			searchEnd = len(data)
		}

		for _, p := range players {
			if len(p.dissectID) < 4 {
				continue
			}
			for j := searchStart; j <= searchEnd-4; j++ {
				if bytes.Equal(data[j:j+4], p.dissectID[:4]) {
					relOffset := j - i
					key := fmt.Sprintf("%s@%d", p.username, relOffset)
					if len(dissectIDLocations[key]) < 3 { // Only record first 3 occurrences
						dissectIDLocations[key] = append(dissectIDLocations[key], i)
					}
				}
			}
		}
	}

	// Print findings
	for key, offsets := range dissectIDLocations {
		if len(offsets) > 0 {
			fmt.Printf("  %s: found %d times (first at marker offset %d)\n", key, len(offsets), offsets[0])
		}
	}

	// Now check for 01f0 pattern specifically
	fmt.Println("\n=== ANALYZING '01f0' PATTERN (common in DissectIDs) ===")
	pattern01f0 := []byte{0x01, 0xf0}
	countByOffset := make(map[int]int)

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		// Check 20 bytes before marker for 01f0
		for offset := -20; offset < 0; offset++ {
			if i+offset >= 0 && i+offset+2 <= len(data) {
				if bytes.Equal(data[i+offset:i+offset+2], pattern01f0) {
					countByOffset[offset]++
				}
			}
		}
	}

	fmt.Println("  Occurrences of '01f0' at each offset relative to marker:")
	for offset := -20; offset < 0; offset++ {
		if countByOffset[offset] > 100 {
			fmt.Printf("    Offset %d: %d occurrences\n", offset, countByOffset[offset])
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

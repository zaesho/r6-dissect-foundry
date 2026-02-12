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

type entityTrack struct {
	id         uint32
	positions  []posData
	firstPkt   int
	lastPkt    int
}

type posData struct {
	pkt     int
	x, y, z float32
	offset  int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entitydeep <replay.rec>")
		os.Exit(1)
	}

	// First read with dissect to get player info
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

	fmt.Println("=== PLAYER INFO FROM HEADER ===")
	for i, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "ATK"
			} else {
				teamRole = "DEF"
			}
		}
		fmt.Printf("[%d] %-15s (%s) DissectID=%x ID=%d\n", i, p.Username, teamRole, p.DissectID, p.ID)
	}

	// Now analyze raw data
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

	// Build tracks by entity ID
	tracks := make(map[uint32]*entityTrack)
	pktNum := 0

	// Also collect pre-marker byte patterns
	preMarkerPatterns := make(map[string]int)

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
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+8 : pos+12]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		pktNum++

		// Get entity ID (4 bytes before marker)
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		// Also capture 8-16 bytes before marker for pattern analysis
		if i >= 16 {
			prePattern := fmt.Sprintf("%x", data[i-16:i-4])
			preMarkerPatterns[prePattern]++
		}

		if tracks[entityID] == nil {
			tracks[entityID] = &entityTrack{id: entityID, firstPkt: pktNum}
		}
		tracks[entityID].positions = append(tracks[entityID].positions, posData{pktNum, x, y, z, i})
		tracks[entityID].lastPkt = pktNum
	}

	// Sort tracks by position count
	var trackList []*entityTrack
	for _, t := range tracks {
		trackList = append(trackList, t)
	}
	sort.Slice(trackList, func(i, j int) bool {
		return len(trackList[i].positions) > len(trackList[j].positions)
	})

	fmt.Println("\n=== ENTITY IDs BY PACKET COUNT (top 20) ===")
	fmt.Printf("%-12s %8s %8s %8s %25s %25s\n", "EntityID", "Count", "FirstPkt", "LastPkt", "First Pos", "Last Pos")
	for i, t := range trackList {
		if i >= 20 {
			break
		}
		firstPos := fmt.Sprintf("(%.1f, %.1f, %.1f)", t.positions[0].x, t.positions[0].y, t.positions[0].z)
		lastPos := fmt.Sprintf("(%.1f, %.1f, %.1f)", t.positions[len(t.positions)-1].x, t.positions[len(t.positions)-1].y, t.positions[len(t.positions)-1].z)
		fmt.Printf("0x%08x %8d %8d %8d %25s %25s\n", t.id, len(t.positions), t.firstPkt, t.lastPkt, firstPos, lastPos)
	}

	// Analyze entity ID structure
	fmt.Println("\n=== ENTITY ID STRUCTURE ANALYSIS ===")
	for i, t := range trackList {
		if i >= 10 {
			break
		}
		id := t.id
		// Break down the 4 bytes
		b0 := byte(id & 0xFF)
		b1 := byte((id >> 8) & 0xFF)
		b2 := byte((id >> 16) & 0xFF)
		b3 := byte((id >> 24) & 0xFF)
		fmt.Printf("0x%08x: bytes=[%02x %02x %02x %02x] hi16=0x%04x lo16=0x%04x\n",
			id, b0, b1, b2, b3, id>>16, id&0xFFFF)
	}

	// Look for patterns in pre-marker bytes
	fmt.Println("\n=== PRE-MARKER PATTERN ANALYSIS (12 bytes before entity ID) ===")
	type patternCount struct {
		pattern string
		count   int
	}
	var patterns []patternCount
	for p, c := range preMarkerPatterns {
		patterns = append(patterns, patternCount{p, c})
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].count > patterns[j].count
	})
	for i, p := range patterns {
		if i >= 10 {
			break
		}
		fmt.Printf("  %s: %d packets\n", p.pattern, p.count)
	}

	// Examine a few movement packets in detail
	fmt.Println("\n=== DETAILED PACKET EXAMINATION (first 5 from top entity) ===")
	if len(trackList) > 0 {
		topTrack := trackList[0]
		for i := 0; i < 5 && i < len(topTrack.positions); i++ {
			p := topTrack.positions[i]
			// Show 32 bytes before and after the marker
			start := p.offset - 32
			if start < 0 {
				start = 0
			}
			fmt.Printf("\nPacket %d at offset %d, pos=(%.1f, %.1f, %.1f):\n", p.pkt, p.offset, p.x, p.y, p.z)
			fmt.Printf("  Pre-marker (32 bytes): %x\n", data[start:p.offset])
			fmt.Printf("  Post-marker (32 bytes): %x\n", data[p.offset+6:p.offset+6+32])
		}
	}

	// Check if entity IDs have any relationship to DissectIDs
	fmt.Println("\n=== CHECKING ENTITY ID vs DISSECT ID CORRELATION ===")
	for i, p := range r.Header.Players {
		if len(p.DissectID) < 4 {
			continue
		}
		dissectIDUint := binary.LittleEndian.Uint32(p.DissectID[:4])
		fmt.Printf("[%d] %s: DissectID as uint32 = 0x%08x\n", i, p.Username, dissectIDUint)
		
		// Check if any entity ID contains this
		for _, t := range trackList[:min(20, len(trackList))] {
			if t.id == dissectIDUint {
				fmt.Printf("    MATCH! Entity 0x%08x has %d positions\n", t.id, len(t.positions))
			}
			// Also check byte-swapped versions
			swapped := ((t.id & 0xFF) << 24) | ((t.id & 0xFF00) << 8) | ((t.id >> 8) & 0xFF00) | ((t.id >> 24) & 0xFF)
			if swapped == dissectIDUint {
				fmt.Printf("    SWAPPED MATCH! Entity 0x%08x (swapped=0x%08x)\n", t.id, swapped)
			}
		}
	}

	// Look for entity IDs in other parts of the replay (near player data)
	fmt.Println("\n=== SEARCHING FOR ENTITY IDS IN PLAYER DATA SECTIONS ===")
	playerPattern := []byte{0x22, 0x07, 0x94, 0x9B, 0xDC} // Player data marker
	for i := 0; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+len(playerPattern)], playerPattern) {
			continue
		}
		// Found player marker, look for entity IDs nearby
		fmt.Printf("Player marker at offset %d\n", i)
		// Check 200 bytes after for any of our top entity IDs
		for j := 0; j < 200 && i+j+4 < len(data); j += 4 {
			val := binary.LittleEndian.Uint32(data[i+j : i+j+4])
			for _, t := range trackList[:min(10, len(trackList))] {
				if val == t.id {
					fmt.Printf("  Found entity 0x%08x at offset +%d\n", val, j)
				}
			}
		}
		break // Just check first player marker
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

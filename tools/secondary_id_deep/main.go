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

type entityWithSecondary struct {
	entityID    uint32
	secondaryID uint32 // The 4 bytes at offset -8 to -4
	count       int
	firstX      float32
	firstY      float32
	firstZ      float32
	prepMove    float32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: secondary_id_deep <replay.rec>")
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
	}
	f.Close()

	// Extract player info
	fmt.Println("=== PLAYERS AND THEIR DissectIDs ===")
	dissectIDs := make(map[uint32]string) // DissectID -> username
	for _, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				team = "ATK"
			} else {
				team = "DEF"
			}
		}
		
		// Store DissectID as uint32
		if len(p.DissectID) >= 4 {
			dissectU32 := binary.LittleEndian.Uint32(p.DissectID[:4])
			dissectIDs[dissectU32] = p.Username
			fmt.Printf("  %-15s (%s) DissectID: %08x (as uint32: 0x%08x)\n", 
				p.Username, team, p.DissectID, dissectU32)
		}
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

	fmt.Printf("\nDecompressed size: %d bytes\n", len(data))

	// Analyze movement packets - collect unique (secondaryID, entityID) pairs
	type idPair struct {
		secondaryID uint32
		entityID    uint32
	}
	pairCounts := make(map[idPair]*entityWithSecondary)
	
	pktNum := 0
	maxPkt := 0
	
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
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+10 : pos+14]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		pktNum++
		if pktNum > maxPkt {
			maxPkt = pktNum
		}

		if i < 8 {
			continue
		}
		
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])
		secondaryID := binary.LittleEndian.Uint32(data[i-8 : i-4])
		
		pair := idPair{secondaryID, entityID}
		if pairCounts[pair] == nil {
			pairCounts[pair] = &entityWithSecondary{
				entityID:    entityID,
				secondaryID: secondaryID,
				firstX:      x,
				firstY:      y,
				firstZ:      z,
			}
		}
		
		// Track movement for prep phase calculation
		e := pairCounts[pair]
		e.count++
	}

	// Sort pairs by count
	var pairs []*entityWithSecondary
	for _, e := range pairCounts {
		pairs = append(pairs, e)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})

	// Show top pairs
	fmt.Println("\n=== TOP (SecondaryID, EntityID) PAIRS ===")
	fmt.Printf("%-12s %-12s %8s %25s\n", "SecondaryID", "EntityID", "Count", "First Pos")
	for i, p := range pairs {
		if i >= 30 {
			break
		}
		pos := fmt.Sprintf("(%.1f, %.1f, %.1f)", p.firstX, p.firstY, p.firstZ)
		fmt.Printf("0x%08x 0x%08x %8d %25s\n", p.secondaryID, p.entityID, p.count, pos)
	}

	// Check if secondaryIDs match any DissectIDs
	fmt.Println("\n=== CHECKING SECONDARY IDs vs DISSECT IDs ===")
	for _, p := range pairs[:min(30, len(pairs))] {
		if username, ok := dissectIDs[p.secondaryID]; ok {
			fmt.Printf("MATCH: SecondaryID 0x%08x = %s's DissectID (entity 0x%08x, %d packets)\n",
				p.secondaryID, username, p.entityID, p.count)
		}
		// Also try byte-swapped
		swapped := swapBytes(p.secondaryID)
		if username, ok := dissectIDs[swapped]; ok {
			fmt.Printf("MATCH (swapped): SecondaryID 0x%08x (swapped=0x%08x) = %s's DissectID\n",
				p.secondaryID, swapped, username)
		}
	}

	// Group by entity ID and show unique secondary IDs per entity
	fmt.Println("\n=== SECONDARY IDs PER ENTITY ===")
	entitySecondaries := make(map[uint32]map[uint32]int)
	for _, p := range pairs {
		if entitySecondaries[p.entityID] == nil {
			entitySecondaries[p.entityID] = make(map[uint32]int)
		}
		entitySecondaries[p.entityID][p.secondaryID] += p.count
	}

	// Sort entities by total count
	type entitySummary struct {
		entityID     uint32
		secondaries  map[uint32]int
		totalPackets int
	}
	var entities []entitySummary
	for eid, secs := range entitySecondaries {
		total := 0
		for _, c := range secs {
			total += c
		}
		entities = append(entities, entitySummary{eid, secs, total})
	}
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].totalPackets > entities[j].totalPackets
	})

	for i, e := range entities {
		if i >= 15 {
			break
		}
		fmt.Printf("\nEntity 0x%08x (%d total packets, %d unique secondary IDs):\n", 
			e.entityID, e.totalPackets, len(e.secondaries))
		
		// Sort secondaries by count
		type secCount struct {
			secID uint32
			count int
		}
		var secs []secCount
		for sid, cnt := range e.secondaries {
			secs = append(secs, secCount{sid, cnt})
		}
		sort.Slice(secs, func(i, j int) bool {
			return secs[i].count > secs[j].count
		})
		
		for j, s := range secs {
			if j >= 5 {
				fmt.Printf("    ... and %d more secondary IDs\n", len(secs)-5)
				break
			}
			// Check if this secondary ID matches a DissectID
			matchInfo := ""
			if username, ok := dissectIDs[s.secID]; ok {
				matchInfo = fmt.Sprintf(" <-- %s's DissectID", username)
			}
			fmt.Printf("    Secondary 0x%08x: %d packets%s\n", s.secID, s.count, matchInfo)
		}
	}

	// Look at the structure of secondary IDs
	fmt.Println("\n=== SECONDARY ID STRUCTURE ANALYSIS ===")
	secIDUnique := make(map[uint32]bool)
	for _, p := range pairs {
		secIDUnique[p.secondaryID] = true
	}
	
	fmt.Printf("Unique secondary IDs: %d\n", len(secIDUnique))
	
	// Check high byte patterns
	highByteCount := make(map[byte]int)
	for sid := range secIDUnique {
		highByte := byte(sid >> 24)
		highByteCount[highByte]++
	}
	
	fmt.Println("\nHigh byte (most significant) distribution:")
	for b, cnt := range highByteCount {
		fmt.Printf("  0x%02x: %d IDs\n", b, cnt)
	}

	// Look for 01f0 pattern in secondary IDs (common in DissectIDs)
	fmt.Println("\n=== SECONDARY IDs WITH 01f0 PATTERN ===")
	for sid := range secIDUnique {
		// Check if ends in 01f0 (little endian: bytes 2,3 = 01, f0)
		b2 := byte((sid >> 16) & 0xFF)
		b3 := byte((sid >> 24) & 0xFF)
		if b2 == 0x01 && b3 == 0xf0 {
			// Find which entities use this
			for _, p := range pairs {
				if p.secondaryID == sid {
					matchInfo := ""
					if username, ok := dissectIDs[sid]; ok {
						matchInfo = fmt.Sprintf(" = %s's DissectID", username)
					}
					fmt.Printf("  0x%08x (entity 0x%08x, %d pkts)%s\n", 
						sid, p.entityID, p.count, matchInfo)
					break
				}
			}
		}
	}

	// Detailed analysis of the -8 to 0 bytes before marker for top entities
	fmt.Println("\n=== DETAILED PRE-MARKER ANALYSIS (bytes -16 to 0) ===")
	fmt.Println("Examining first few packets for each top entity...\n")
	
	// Re-scan to get actual byte values
	entityPacketExamples := make(map[uint32][][]byte)
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
		if i < 16 {
			continue
		}

		entityID := binary.LittleEndian.Uint32(data[i-4 : i])
		
		// Only collect first 3 examples per entity
		if len(entityPacketExamples[entityID]) < 3 {
			preMarker := make([]byte, 16)
			copy(preMarker, data[i-16:i])
			entityPacketExamples[entityID] = append(entityPacketExamples[entityID], preMarker)
		}
	}

	for i, e := range entities {
		if i >= 10 {
			break
		}
		fmt.Printf("Entity 0x%08x:\n", e.entityID)
		for j, pre := range entityPacketExamples[e.entityID] {
			// Parse the 16 bytes
			// [-16:-12], [-12:-8], [-8:-4], [-4:0]
			secID := binary.LittleEndian.Uint32(pre[8:12])
			entID := binary.LittleEndian.Uint32(pre[12:16])
			
			secMatch := ""
			if username, ok := dissectIDs[secID]; ok {
				secMatch = fmt.Sprintf(" = %s", username)
			}
			
			fmt.Printf("  [%d] %x | %x | %08x%s | %08x\n", 
				j, pre[0:4], pre[4:8], secID, secMatch, entID)
		}
		fmt.Println()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func swapBytes(v uint32) uint32 {
	return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF)
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

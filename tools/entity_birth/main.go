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

// Known packet markers to avoid
var playerMarker = []byte{0x22, 0x07, 0x94, 0x9B, 0xDC}

type entityInfo struct {
	id            uint32
	positionCount int
	firstOffset   int
	firstPktNum   int
	firstX, firstY, firstZ float32
	birthOffset   int // First occurrence in file (non-movement)
	birthContext  []byte
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entity_birth <replay.rec>")
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
		// Ignore EOF
	}
	f.Close()

	fmt.Println("=== PLAYER INFO ===")
	for i, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "ATK"
			} else {
				teamRole = "DEF"
			}
		}
		fmt.Printf("[%d] %-15s (%s) %-12s DissectID=%x\n", i, p.Username, teamRole, p.Operator.String(), p.DissectID)
	}

	// Get death order from kills
	fmt.Println("\n=== DEATH ORDER ===")
	for _, event := range r.MatchFeedback {
		if event.Type == dissect.Kill {
			fmt.Printf("%.0fs: %s killed %s\n", event.TimeInSeconds, event.Username, event.Target)
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

	// First pass: find all movement packets and their entity IDs
	entities := make(map[uint32]*entityInfo)
	pktNum := 0

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

		if i < 4 {
			continue
		}
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		if entities[entityID] == nil {
			entities[entityID] = &entityInfo{
				id:          entityID,
				firstOffset: i,
				firstPktNum: pktNum,
				firstX:      x,
				firstY:      y,
				firstZ:      z,
				birthOffset: -1,
			}
		}
		entities[entityID].positionCount++
	}

	// Sort by position count
	var sorted []*entityInfo
	for _, e := range entities {
		sorted = append(sorted, e)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].positionCount > sorted[j].positionCount
	})

	// Take top 15 entities (likely 10 players + some drones/cams)
	topEntities := sorted
	if len(topEntities) > 15 {
		topEntities = topEntities[:15]
	}

	// Second pass: find the FIRST occurrence of each entity ID in the entire file
	// (before any movement packets)
	fmt.Println("\n=== SEARCHING FOR ENTITY ID BIRTH LOCATIONS ===")
	
	for _, e := range topEntities {
		idBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(idBytes, e.id)
		
		// Find first occurrence
		for i := 0; i < e.firstOffset-4; i++ {
			if bytes.Equal(data[i:i+4], idBytes) {
				e.birthOffset = i
				// Capture context
				start := i - 32
				if start < 0 {
					start = 0
				}
				end := i + 36
				if end > len(data) {
					end = len(data)
				}
				e.birthContext = data[start:end]
				break
			}
		}
	}

	// Show results sorted by birth offset
	sort.Slice(topEntities, func(i, j int) bool {
		if topEntities[i].birthOffset < 0 {
			return false
		}
		if topEntities[j].birthOffset < 0 {
			return true
		}
		return topEntities[i].birthOffset < topEntities[j].birthOffset
	})

	fmt.Println("\nEntity birth locations (sorted by earliest occurrence):")
	fmt.Printf("%-12s %8s %8s %8s %25s\n", "EntityID", "BirthOff", "MoveOff", "Positions", "First Position")
	
	for _, e := range topEntities {
		pos := fmt.Sprintf("(%.1f, %.1f, %.1f)", e.firstX, e.firstY, e.firstZ)
		birthOff := fmt.Sprintf("%d", e.birthOffset)
		if e.birthOffset < 0 {
			birthOff = "N/A"
		}
		fmt.Printf("0x%08x %8s %8d %8d %25s\n", e.id, birthOff, e.firstOffset, e.positionCount, pos)
	}

	// Show birth contexts
	fmt.Println("\n=== ENTITY BIRTH CONTEXTS ===")
	for _, e := range topEntities {
		if e.birthOffset >= 0 && len(e.birthContext) > 0 {
			fmt.Printf("\nEntity 0x%08x birth at offset %d:\n", e.id, e.birthOffset)
			// Show the context with the entity ID highlighted
			idOffset := 32 // the entity ID is at offset 32 in the context
			if e.birthOffset < 32 {
				idOffset = e.birthOffset
			}
			fmt.Printf("  Context: %x | %x | %x\n", 
				e.birthContext[:idOffset], 
				e.birthContext[idOffset:idOffset+4],
				e.birthContext[idOffset+4:])
		}
	}

	// Look for patterns in the bytes BEFORE the entity IDs at birth
	fmt.Println("\n=== PATTERN ANALYSIS: 8 BYTES BEFORE ENTITY AT BIRTH ===")
	prePatterns := make(map[string][]*entityInfo)
	for _, e := range topEntities {
		if e.birthOffset >= 8 && len(e.birthContext) >= 32 {
			idOffset := 32
			if e.birthOffset < 32 {
				idOffset = e.birthOffset
			}
			if idOffset >= 8 {
				pre8 := fmt.Sprintf("%x", e.birthContext[idOffset-8:idOffset])
				prePatterns[pre8] = append(prePatterns[pre8], e)
			}
		}
	}

	for pattern, entities := range prePatterns {
		fmt.Printf("\nPattern %s:\n", pattern)
		for _, e := range entities {
			fmt.Printf("  Entity 0x%08x (positions: %d)\n", e.id, e.positionCount)
		}
	}

	// Try to find where the entity ID is ASSIGNED (look for patterns like spawn/registration)
	fmt.Println("\n=== SEARCHING FOR ENTITY REGISTRATION PATTERNS ===")
	
	// Look for the 01f0 pattern that appears in DissectIDs
	for _, e := range topEntities[:min(5, len(topEntities))] {
		fmt.Printf("\nEntity 0x%08x analysis:\n", e.id)
		
		// Look for nearby DissectID-like patterns (xxe101f0)
		if e.birthOffset > 0 {
			start := e.birthOffset - 100
			if start < 0 {
				start = 0
			}
			end := e.birthOffset + 100
			if end > len(data) {
				end = len(data)
			}
			
			// Search for xxe101f0 pattern in this range
			searchRange := data[start:end]
			for j := 0; j < len(searchRange)-4; j++ {
				// Check for patterns ending in 01f0
				if searchRange[j+2] == 0x01 && searchRange[j+3] == 0xf0 {
					absOffset := start + j
					fmt.Printf("  Found xxxx01f0 pattern at offset %d: %x (relative: %d)\n", 
						absOffset, searchRange[j:j+4], absOffset-e.birthOffset)
				}
			}
		}
	}

	// Investigate first movement packet more closely
	fmt.Println("\n=== FIRST MOVEMENT PACKET ANALYSIS ===")
	for i, e := range topEntities {
		if i >= 5 {
			break
		}
		fmt.Printf("\nEntity 0x%08x first movement at offset %d:\n", e.id, e.firstOffset)
		start := e.firstOffset - 64
		if start < 0 {
			start = 0
		}
		end := e.firstOffset + 64
		if end > len(data) {
			end = len(data)
		}
		
		// Split at marker location
		markerRelOffset := e.firstOffset - start
		fmt.Printf("  Pre-marker:  %x\n", data[start:e.firstOffset])
		fmt.Printf("  Marker+data: %x\n", data[e.firstOffset:min(e.firstOffset+32, end)])
		
		// Analyze the 16 bytes before marker
		if markerRelOffset >= 16 {
			preMarker := data[e.firstOffset-16:e.firstOffset]
			fmt.Printf("  Last 16 bytes before marker breakdown:\n")
			fmt.Printf("    [-16:-12]: %x\n", preMarker[0:4])
			fmt.Printf("    [-12:-8]:  %x\n", preMarker[4:8])
			fmt.Printf("    [-8:-4]:   %x (secondary ID?)\n", preMarker[8:12])
			fmt.Printf("    [-4:0]:    %x (ENTITY ID)\n", preMarker[12:16])
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

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

type entityInfo struct {
	id           uint32
	count        int
	firstX       float32
	firstY       float32
	firstZ       float32
	prepMove     float32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: find_entity_dissect_link <replay.rec>")
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

	// Extract player DissectIDs
	fmt.Println("=== PLAYER DissectIDs ===")
	type playerInfo struct {
		username  string
		team      string
		dissectID []byte
	}
	var players []playerInfo
	for _, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				team = "ATK"
			} else {
				team = "DEF"
			}
		}
		players = append(players, playerInfo{p.Username, team, p.DissectID})
		fmt.Printf("  %-15s (%s) DissectID: %x\n", p.Username, team, p.DissectID)
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

	// Find all entity IDs from movement packets
	entities := make(map[uint32]*entityInfo)
	pktNum := 0
	maxPkt := 0

	var lastX, lastY float32 = 0, 0
	
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

		if i < 4 {
			continue
		}
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		if entities[entityID] == nil {
			entities[entityID] = &entityInfo{
				id:     entityID,
				firstX: x,
				firstY: y,
				firstZ: z,
			}
		}
		
		e := entities[entityID]
		e.count++
		
		// Prep phase movement (first ~20% of packets)
		if pktNum < maxPkt/5 {
			if lastX != 0 || lastY != 0 {
				dx := x - lastX
				dy := y - lastY
				e.prepMove += float32(math.Sqrt(float64(dx*dx + dy*dy)))
			}
		}
		lastX, lastY = x, y
	}

	// Sort entities
	var sortedEntities []*entityInfo
	for _, e := range entities {
		sortedEntities = append(sortedEntities, e)
	}
	sort.Slice(sortedEntities, func(i, j int) bool {
		return sortedEntities[i].count > sortedEntities[j].count
	})

	topEntities := sortedEntities
	if len(topEntities) > 15 {
		topEntities = topEntities[:15]
	}

	fmt.Println("\n=== TOP ENTITIES ===")
	for _, e := range topEntities {
		fmt.Printf("  0x%08x: %d packets, first pos (%.1f, %.1f, %.1f)\n",
			e.id, e.count, e.firstX, e.firstY, e.firstZ)
	}

	// Now search for DissectIDs in the data and look for entity IDs nearby
	fmt.Println("\n=== SEARCHING FOR DissectID -> EntityID LINKS ===")
	
	for _, player := range players {
		if len(player.dissectID) < 4 {
			continue
		}
		
		fmt.Printf("\n--- %s (%s) DissectID=%x ---\n", player.username, player.team, player.dissectID)
		
		// Search for DissectID as bytes
		for i := 0; i < len(data)-len(player.dissectID); i++ {
			if bytes.Equal(data[i:i+len(player.dissectID)], player.dissectID) {
				// Found! Look for entity IDs in nearby area (within 200 bytes)
				fmt.Printf("Found DissectID at offset %d\n", i)
				
				start := i - 100
				if start < 0 {
					start = 0
				}
				end := i + 200
				if end > len(data) {
					end = len(data)
				}
				
				// Search for entity IDs in this range
				found := false
				for _, e := range topEntities {
					idBytes := make([]byte, 4)
					binary.LittleEndian.PutUint32(idBytes, e.id)
					
					for j := start; j < end-4; j++ {
						if bytes.Equal(data[j:j+4], idBytes) {
							relOff := j - i
							fmt.Printf("  -> Entity 0x%08x at relative offset %d\n", e.id, relOff)
							found = true
						}
					}
				}
				
				if !found {
					// Show context around the DissectID
					ctxStart := i - 20
					if ctxStart < 0 {
						ctxStart = 0
					}
					ctxEnd := i + 40
					if ctxEnd > len(data) {
						ctxEnd = len(data)
					}
					fmt.Printf("  Context: %x\n", data[ctxStart:ctxEnd])
				}
			}
		}
	}

	// Try alternative: look for the entity ID high bytes (without the 0000 suffix)
	fmt.Println("\n=== SEARCHING FOR ENTITY HIGH BYTES NEAR DissectIDs ===")
	for _, player := range players {
		if len(player.dissectID) < 4 {
			continue
		}
		
		// Search for DissectID
		for i := 0; i < len(data)-len(player.dissectID); i++ {
			if !bytes.Equal(data[i:i+len(player.dissectID)], player.dissectID) {
				continue
			}
			
			// Found DissectID, look for entity high bytes nearby
			start := i - 50
			if start < 0 {
				start = 0
			}
			end := i + 100
			if end > len(data) {
				end = len(data)
			}
			
			nearbyRange := data[start:end]
			
			for _, e := range topEntities {
				// Entity high bytes (e.g., 0x047e0000 -> 7e 04)
				hiBytes := []byte{byte(e.id >> 16), byte(e.id >> 24)}
				
				for j := 0; j < len(nearbyRange)-2; j++ {
					if nearbyRange[j] == hiBytes[0] && nearbyRange[j+1] == hiBytes[1] {
						absOff := start + j
						relOff := absOff - i
						fmt.Printf("%s: Entity 0x%08x hi-bytes at relative %d (abs %d)\n",
							player.username, e.id, relOff, absOff)
					}
				}
			}
			
			break // Only check first occurrence
		}
	}

	// Look for entity spawning/registration packets
	fmt.Println("\n=== SEARCHING FOR ENTITY SPAWN/REGISTRATION PATTERNS ===")
	
	// Look for sequences where multiple entity IDs appear close together
	// This might indicate a spawn table or entity list
	
	// Find places where 3+ top entity IDs appear within 100 bytes
	for i := 0; i < len(data)-100; i++ {
		matchCount := 0
		var matches []struct {
			entityID uint32
			offset   int
		}
		
		for _, e := range topEntities {
			idBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(idBytes, e.id)
			
			for j := i; j < i+100 && j < len(data)-4; j++ {
				if bytes.Equal(data[j:j+4], idBytes) {
					matchCount++
					matches = append(matches, struct {
						entityID uint32
						offset   int
					}{e.id, j})
					break
				}
			}
		}
		
		if matchCount >= 3 {
			fmt.Printf("\nCluster at offset %d (%d entity IDs found):\n", i, matchCount)
			for _, m := range matches {
				fmt.Printf("  Entity 0x%08x at offset %d\n", m.entityID, m.offset)
			}
			// Show context
			end := i + 100
			if end > len(data) {
				end = len(data)
			}
			fmt.Printf("  Context: %x\n", data[i:end])
			
			i += 100 // Skip ahead
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

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
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/redraskal/r6-dissect/dissect"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

type entityInfo struct {
	id         uint32
	positions  int
	firstPkt   int
	lastPkt    int
	firstX     float32
	firstY     float32
	firstZ     float32
	lastX      float32
	lastY      float32
	lastZ      float32
	firstOff   int
	lastOff    int
	type01     int // Type 0x01 packets
	type03     int // Type 0x03 packets
	totalDist  float32
	active     bool // Still receiving packets at end?
}

type replayEntityData struct {
	filename string
	entities map[uint32]*entityInfo
	players  []playerData
}

type playerData struct {
	username   string
	team       string
	dissectID  []byte
	operator   string
	spawnName  string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entityid_deep <replay.rec> [replay2.rec ...]")
		fmt.Println("       entityid_deep <match_folder>")
		os.Exit(1)
	}

	var files []string
	
	// Check if first arg is a directory
	stat, err := os.Stat(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	
	if stat.IsDir() {
		// Get all .rec files in directory
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

	var allReplays []replayEntityData
	
	for _, file := range files {
		fmt.Printf("Processing: %s\n", filepath.Base(file))
		replay := analyzeReplay(file)
		if replay != nil {
			allReplays = append(allReplays, *replay)
		}
	}

	if len(allReplays) == 0 {
		fmt.Println("No valid replays processed")
		os.Exit(1)
	}

	// Per-replay summary
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("PER-REPLAY ENTITY SUMMARY")
	fmt.Println(strings.Repeat("=", 80))

	for _, r := range allReplays {
		fmt.Printf("\n--- %s ---\n", filepath.Base(r.filename))
		fmt.Println("Players:")
		for _, p := range r.players {
			fmt.Printf("  %-15s (%s) %s DissectID=%x\n", p.username, p.team, p.operator, p.dissectID)
		}
		
		// Sort entities by position count
		var sorted []*entityInfo
		for _, e := range r.entities {
			sorted = append(sorted, e)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].positions > sorted[j].positions
		})
		
		fmt.Println("\nTop 15 Entities:")
		fmt.Printf("%-12s %6s %6s %6s %6s %8s %10s\n", 
			"EntityID", "Pos", "T01", "T03", "Dist", "Duration", "Status")
		for i, e := range sorted {
			if i >= 15 {
				break
			}
			status := "ended"
			if e.active {
				status = "ACTIVE"
			}
			duration := float64(e.lastPkt - e.firstPkt)
			fmt.Printf("0x%08x %6d %6d %6d %6.0f %8.0f %10s\n",
				e.id, e.positions, e.type01, e.type03, e.totalDist, duration, status)
		}
	}

	// Cross-round analysis
	if len(allReplays) > 1 {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("CROSS-ROUND ENTITY ID ANALYSIS")
		fmt.Println(strings.Repeat("=", 80))

		// Collect all entity IDs across rounds
		entityAcrossRounds := make(map[uint32][]int) // entityID -> which rounds it appears in
		for roundIdx, r := range allReplays {
			for entityID := range r.entities {
				entityAcrossRounds[entityID] = append(entityAcrossRounds[entityID], roundIdx)
			}
		}

		// Count how many IDs appear in multiple rounds
		multiRoundIDs := make(map[uint32][]int)
		singleRoundIDs := 0
		for id, rounds := range entityAcrossRounds {
			if len(rounds) > 1 {
				multiRoundIDs[id] = rounds
			} else {
				singleRoundIDs++
			}
		}

		fmt.Printf("\nEntity IDs appearing in multiple rounds: %d\n", len(multiRoundIDs))
		fmt.Printf("Entity IDs appearing in single round: %d\n", singleRoundIDs)

		// Show the multi-round IDs
		if len(multiRoundIDs) > 0 {
			fmt.Println("\nEntity IDs across rounds:")
			type idRounds struct {
				id     uint32
				rounds []int
			}
			var multiList []idRounds
			for id, rounds := range multiRoundIDs {
				multiList = append(multiList, idRounds{id, rounds})
			}
			sort.Slice(multiList, func(i, j int) bool {
				return len(multiList[i].rounds) > len(multiList[j].rounds)
			})
			
			for i, mr := range multiList {
				if i >= 20 {
					fmt.Printf("  ... and %d more\n", len(multiList)-20)
					break
				}
				roundStrs := make([]string, len(mr.rounds))
				for j, r := range mr.rounds {
					roundStrs[j] = fmt.Sprintf("R%02d", r+1)
				}
				fmt.Printf("  0x%08x appears in %d rounds: %v\n", mr.id, len(mr.rounds), roundStrs)
			}
		}

		// Analyze if entity IDs are sequential/related
		fmt.Println("\n--- Entity ID Patterns ---")
		analyzeEntityIDPatterns(allReplays)
	}

	// Deep analysis of first replay
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("DETAILED ANALYSIS (First Replay)")
	fmt.Println(strings.Repeat("=", 80))
	
	analyzeEntityLocations(files[0], allReplays[0])
}

func analyzeReplay(filename string) *replayEntityData {
	// First read with dissect to get player info
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("  Error opening: %v\n", err)
		return nil
	}

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("  Error creating reader: %v\n", err)
		f.Close()
		return nil
	}
	if err := r.Read(); err != nil && err.Error() != "EOF" {
		// Ignore EOF
	}
	f.Close()

	// Extract player info
	var players []playerData
	for _, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "ATK"
			} else {
				teamRole = "DEF"
			}
		}
		players = append(players, playerData{
			username:  p.Username,
			team:      teamRole,
			dissectID: p.DissectID,
			operator:  p.Operator.String(),
			spawnName: p.Spawn,
		})
	}

	// Now analyze raw data
	f, err = os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		fmt.Printf("  Error decompressing: %v\n", err)
		return nil
	}

	entities := make(map[uint32]*entityInfo)
	pktNum := 0
	totalPkts := 0

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

		totalPkts++
		pktNum++

		// Get entity ID (4 bytes before marker)
		if i < 4 {
			continue
		}
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		if entities[entityID] == nil {
			entities[entityID] = &entityInfo{
				id:       entityID,
				firstPkt: pktNum,
				firstX:   x,
				firstY:   y,
				firstZ:   z,
				firstOff: i,
			}
		}
		
		e := entities[entityID]
		
		// Calculate distance from last position
		if e.positions > 0 {
			dx := x - e.lastX
			dy := y - e.lastY
			e.totalDist += float32(math.Sqrt(float64(dx*dx + dy*dy)))
		}
		
		e.positions++
		e.lastPkt = pktNum
		e.lastX = x
		e.lastY = y
		e.lastZ = z
		e.lastOff = i
		
		if typeSecond == 0x01 {
			e.type01++
		} else {
			e.type03++
		}
	}

	// Mark entities that were still active at the end (last packet within 5% of total)
	threshold := int(float64(totalPkts) * 0.95)
	for _, e := range entities {
		if e.lastPkt >= threshold {
			e.active = true
		}
	}

	return &replayEntityData{
		filename: filename,
		entities: entities,
		players:  players,
	}
}

func analyzeEntityIDPatterns(replays []replayEntityData) {
	// Collect all unique entity IDs
	allIDs := make(map[uint32]bool)
	for _, r := range replays {
		for id := range r.entities {
			allIDs[id] = true
		}
	}

	// Analyze the structure
	hi16Count := make(map[uint16]int)
	lo16Count := make(map[uint16]int)
	
	for id := range allIDs {
		hi16 := uint16(id >> 16)
		lo16 := uint16(id & 0xFFFF)
		hi16Count[hi16]++
		lo16Count[lo16]++
	}

	fmt.Printf("\nUnique entity IDs: %d\n", len(allIDs))
	fmt.Printf("Unique hi16 values: %d\n", len(hi16Count))
	fmt.Printf("Unique lo16 values: %d\n", len(lo16Count))

	// Show lo16 distribution
	fmt.Println("\nLo16 distribution:")
	for lo, cnt := range lo16Count {
		fmt.Printf("  0x%04x: %d IDs\n", lo, cnt)
	}

	// Check for sequential patterns in hi16
	var hi16List []uint16
	for h := range hi16Count {
		hi16List = append(hi16List, h)
	}
	sort.Slice(hi16List, func(i, j int) bool {
		return hi16List[i] < hi16List[j]
	})

	fmt.Println("\nHi16 values (sorted):")
	for i := 0; i < len(hi16List) && i < 30; i++ {
		fmt.Printf("  0x%04x ", hi16List[i])
		if (i+1)%10 == 0 {
			fmt.Println()
		}
	}
	if len(hi16List) > 30 {
		fmt.Printf("  ... and %d more\n", len(hi16List)-30)
	}
	fmt.Println()
}

func analyzeEntityLocations(filename string, replay replayEntityData) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		return
	}

	// Get top 10 entity IDs by position count
	var topEntities []*entityInfo
	for _, e := range replay.entities {
		topEntities = append(topEntities, e)
	}
	sort.Slice(topEntities, func(i, j int) bool {
		return topEntities[i].positions > topEntities[j].positions
	})
	if len(topEntities) > 10 {
		topEntities = topEntities[:10]
	}

	fmt.Println("\nSearching for top entity IDs elsewhere in replay...")
	
	// Search for entity IDs in other parts of the file
	for _, e := range topEntities {
		idBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(idBytes, e.id)
		
		// Find all occurrences
		var occurrences []int
		for i := 0; i < len(data)-4; i++ {
			if bytes.Equal(data[i:i+4], idBytes) {
				occurrences = append(occurrences, i)
			}
		}
		
		// Filter out movement packet occurrences
		var nonMovementOccurrences []int
		for _, off := range occurrences {
			// Check if this is NOT a movement packet (marker at off+4)
			if off+10 < len(data) && !bytes.Equal(data[off+4:off+10], movementMarker) {
				nonMovementOccurrences = append(nonMovementOccurrences, off)
			}
		}
		
		fmt.Printf("\nEntity 0x%08x (%d positions):\n", e.id, e.positions)
		fmt.Printf("  Total occurrences: %d, Non-movement: %d\n", len(occurrences), len(nonMovementOccurrences))
		
		// Show first few non-movement occurrences
		for i, off := range nonMovementOccurrences {
			if i >= 5 {
				fmt.Printf("  ... and %d more non-movement occurrences\n", len(nonMovementOccurrences)-5)
				break
			}
			start := off - 16
			if start < 0 {
				start = 0
			}
			end := off + 20
			if end > len(data) {
				end = len(data)
			}
			fmt.Printf("  Offset %d: %x\n", off, data[start:end])
		}
	}

	// Look for entity ID assignment patterns
	fmt.Println("\n--- Searching for Entity ID Registration/Assignment Patterns ---")
	
	// Look for bytes that commonly precede entity IDs in non-movement contexts
	preBytePatterns := make(map[string]int)
	for _, e := range topEntities {
		idBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(idBytes, e.id)
		
		for i := 8; i < len(data)-4; i++ {
			if bytes.Equal(data[i:i+4], idBytes) {
				// Skip if this is a movement packet
				if i+10 < len(data) && bytes.Equal(data[i+4:i+10], movementMarker) {
					continue
				}
				// Record the 4 bytes before
				if i >= 4 {
					prePattern := fmt.Sprintf("%x", data[i-4:i])
					preBytePatterns[prePattern]++
				}
			}
		}
	}

	// Show common pre-patterns
	type patCount struct {
		pattern string
		count   int
	}
	var patterns []patCount
	for p, c := range preBytePatterns {
		if c >= 2 {
			patterns = append(patterns, patCount{p, c})
		}
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].count > patterns[j].count
	})
	
	if len(patterns) > 0 {
		fmt.Println("\nCommon bytes BEFORE entity IDs (non-movement contexts):")
		for i, p := range patterns {
			if i >= 10 {
				break
			}
			fmt.Printf("  %s: %d times\n", p.pattern, p.count)
		}
	}

	// Look for the DissectID -> EntityID relationship
	fmt.Println("\n--- Searching for DissectID near EntityID ---")
	for _, player := range replay.players {
		if len(player.dissectID) < 4 {
			continue
		}
		
		fmt.Printf("\nPlayer %s (DissectID=%x):\n", player.username, player.dissectID)
		
		// Search for DissectID in the data
		for i := 0; i < len(data)-4; i++ {
			if bytes.Equal(data[i:i+len(player.dissectID)], player.dissectID) {
				// Found DissectID, look for entity IDs nearby (within 100 bytes)
				start := i - 50
				if start < 0 {
					start = 0
				}
				end := i + 100
				if end > len(data) {
					end = len(data)
				}
				
				// Check if any top entity ID appears in this range
				for _, e := range topEntities {
					idBytes := make([]byte, 4)
					binary.LittleEndian.PutUint32(idBytes, e.id)
					
					for j := start; j < end-4; j++ {
						if bytes.Equal(data[j:j+4], idBytes) {
							fmt.Printf("  Found entity 0x%08x at offset %d (DissectID at %d, diff=%d)\n",
								e.id, j, i, j-i)
						}
					}
				}
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

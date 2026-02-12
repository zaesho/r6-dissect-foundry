package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/redraskal/r6-dissect/dissect"
)

// Investigation: Can we find throwable gadget (grenade, claymore, breach charge) data?
// Two approaches:
// 1. Map the "gadget" field (34BC4BAA) across many rounds to understand what it is
// 2. Survey ALL distinct packet markers to find undiscovered gadget-related packet types

var knownFieldNames = map[[4]byte]string{
	{0x6D, 0x5B, 0x6D, 0x3E}: "reserve",
	{0x34, 0xBC, 0x4B, 0xAA}: "gadget",
	{0x56, 0xF5, 0x44, 0x0A}: "magCap",
	{0x40, 0x0A, 0xC8, 0x29}: "total",
}

// Known markers from reader.go listener registrations
var knownMarkers = map[string]string{
	"22079498DC": "readPlayer",
	"22A9260BE4": "readAtkOpSwap",
	"AF9899CA":   "readSpawn",
	"1F07EFC9":   "readTime",
	"1EF111AB":   "readY7Time",
	"5934E58B04": "readMatchFeedback",
	"22A9C858D9": "readDefuserTimer",
	"ECDA4F80":   "readScoreboardScore",
	"4D737F9E":   "readScoreboardAssists",
	"1CD2B19D":   "readScoreboardKills",
	"77CA96DE":   "ammoUpdate",
	"000060738CFE": "readPlayerPosition (approx)", // note: may differ slightly
}

type entityInfo struct {
	entityID  uint32
	offset    int
	magAmmo   uint32
	gadgetVal uint32
	magCap    uint32
	reserve   uint32
	total     uint32
	hasGadget bool
	hasMagCap bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/throwable_investigation <replay.rec> [replay2.rec ...]")
		fmt.Println("       go run ./tools/throwable_investigation <match_folder>")
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
		sort.Strings(matches)
		files = append(files, matches...)
	} else {
		files = os.Args[1:]
	}

	if len(files) == 0 {
		fmt.Println("No .rec files found")
		os.Exit(1)
	}

	fmt.Println("===================================================================")
	fmt.Println("THROWABLE GADGET INVESTIGATION")
	fmt.Println("===================================================================")

	// Process each replay file
	for fi, filePath := range files {
		fmt.Printf("\n\n=== File %d: %s ===\n", fi+1, filepath.Base(filePath))
		analyzeReplay(filePath)
	}
}

func analyzeReplay(filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	_ = r.ReadPartial()

	fmt.Println("  PLAYERS:")
	for i, p := range r.Header.Players {
		fmt.Printf("    [%d] %-18s %-14s (%s)\n", i, p.Username, p.Operator, p.RoleName)
	}

	f.Seek(0, 0)
	r2, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	rawBytes, err := decompressReplay(r2)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}

	// PART 1: Map "gadget" field values per entity
	fmt.Println("\n  PART 1: 'gadget' field (34BC4BAA) per entity")
	analyzeGadgetField(rawBytes, r)

	// PART 2: Survey distinct 4-byte patterns that repeat with high frequency
	fmt.Println("\n  PART 2: Undiscovered packet markers survey")
	surveyPacketMarkers(rawBytes)

	// PART 3: Search for text strings that might reference gadgets
	fmt.Println("\n  PART 3: Text string search for gadget references")
	searchGadgetStrings(rawBytes)

	// PART 4: Look for packets near the known match feedback marker that we might be missing
	fmt.Println("\n  PART 4: Match feedback area analysis")
	analyzeFeedbackArea(rawBytes)
}

func analyzeGadgetField(data []byte, r *dissect.Reader) {
	marker := []byte{0x77, 0xCA, 0x96, 0xDE}
	offsets := findAllOccurrences(data, marker)

	// Parse all entities with their initial full snapshot
	entityFirstSnap := map[uint32]*entityInfo{}
	entityOrder := []uint32{}

	for _, off := range offsets {
		info := parseAmmoEntity(data, off)
		if info == nil {
			continue
		}
		if _, exists := entityFirstSnap[info.entityID]; !exists {
			entityFirstSnap[info.entityID] = info
			entityOrder = append(entityOrder, info.entityID)
		}
	}

	// Group into player groups by gap
	type group struct {
		entities []uint32
	}
	var groups []group
	var curGroup group
	var lastOff int

	for i, eid := range entityOrder {
		info := entityFirstSnap[eid]
		if i == 0 {
			curGroup = group{entities: []uint32{eid}}
			lastOff = info.offset
		} else {
			gap := info.offset - lastOff
			if gap > 400 {
				groups = append(groups, curGroup)
				curGroup = group{entities: []uint32{eid}}
			} else {
				curGroup.entities = append(curGroup.entities, eid)
			}
			lastOff = info.offset
		}
	}
	if len(curGroup.entities) > 0 {
		groups = append(groups, curGroup)
	}

	// Print table
	fmt.Printf("    %-18s %-14s %-8s %-6s %-6s %-6s %-6s %-6s\n",
		"Player", "Operator", "Entity", "MagAm", "MagCap", "Reserv", "Total", "Gadget")
	fmt.Println("    " + strings.Repeat("-", 88))

	for gi, g := range groups {
		playerLabel := ""
		operatorLabel := ""
		if gi < len(r.Header.Players) {
			playerLabel = r.Header.Players[gi].Username
			operatorLabel = string(r.Header.Players[gi].Operator)
		}

		for ei, eid := range g.entities {
			info := entityFirstSnap[eid]
			label := "PRIMARY"
			if ei == 1 {
				label = "SECONDARY"
			} else if ei > 1 {
				label = fmt.Sprintf("ENTITY_%d", ei+1)
			}

			gadgetStr := "-"
			if info.hasGadget {
				gadgetStr = fmt.Sprintf("%d", info.gadgetVal)
			}
			magCapStr := "-"
			if info.hasMagCap {
				magCapStr = fmt.Sprintf("%d", info.magCap)
			}

			fmt.Printf("    %-18s %-14s %-8s %-6d %-6s %-6d %-6d %-6s\n",
				playerLabel, operatorLabel, label, info.magAmmo, magCapStr, info.reserve, info.total, gadgetStr)
			// Only show player name on first line
			playerLabel = ""
			operatorLabel = ""
		}
	}
}

func surveyPacketMarkers(data []byte) {
	// Look for 4-byte patterns that occur many times (potential markers)
	// Count occurrences of all 4-byte sequences preceded by specific "tag" bytes
	// In the replay, known markers often follow specific patterns

	// Approach: find all 4-byte patterns that appear 50+ times
	if len(data) < 4 {
		return
	}

	// Sample the data: count 4-byte sequences
	counts := map[uint32]int{}
	for i := 0; i <= len(data)-4; i++ {
		key := binary.LittleEndian.Uint32(data[i : i+4])
		// Skip zero and common low/high values
		if key == 0 || key == 0xFFFFFFFF {
			continue
		}
		counts[key]++
	}

	// Filter to patterns with high frequency
	type patternCount struct {
		pattern uint32
		count   int
	}
	var highFreq []patternCount
	for p, c := range counts {
		if c >= 100 { // Appears 100+ times - likely a marker
			highFreq = append(highFreq, patternCount{p, c})
		}
	}

	sort.Slice(highFreq, func(i, j int) bool {
		return highFreq[i].count > highFreq[j].count
	})

	// Show top patterns, excluding known markers
	fmt.Printf("    High-frequency 4-byte patterns (count >= 100, showing top 30):\n")
	shown := 0
	for _, pc := range highFreq {
		if shown >= 30 {
			break
		}
		hex := fmt.Sprintf("%08X", pc.pattern)
		// Check if known
		isKnown := false
		for km := range knownMarkers {
			if strings.Contains(km, hex) || strings.Contains(hex, km[:min(len(km), 8)]) {
				isKnown = true
				break
			}
		}
		knownLabel := ""
		if isKnown {
			knownLabel = " [KNOWN]"
		}
		// Check if it could be a tag
		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, pc.pattern)
		fmt.Printf("    %02X %02X %02X %02X  (count=%d)%s\n", bytes[0], bytes[1], bytes[2], bytes[3], pc.count, knownLabel)
		shown++
	}
}

func searchGadgetStrings(data []byte) {
	// Search for ASCII/UTF-8 strings related to gadgets
	gadgetTerms := []string{
		"grenade", "claymore", "breach", "stun", "smoke", "flash",
		"impact", "frag", "nitro", "c4", "wire", "barbed",
		"proximity", "alarm", "deploy", "throw", "gadget",
		"Grenade", "Claymore", "Breach", "Stun", "Smoke", "Flash",
		"Impact", "Frag", "Nitro", "C4", "Wire", "Barbed",
		"Deploy", "Throw", "Gadget",
	}

	found := 0
	for _, term := range gadgetTerms {
		termBytes := []byte(term)
		positions := findAllOccurrences(data, termBytes)
		if len(positions) > 0 {
			fmt.Printf("    Found '%s' at %d positions: ", term, len(positions))
			// Show first 3
			for i := 0; i < min(3, len(positions)); i++ {
				fmt.Printf("0x%X ", positions[i])
			}
			if len(positions) > 3 {
				fmt.Printf("...")
			}
			fmt.Println()
			found++

			// Show surrounding bytes for context at first occurrence
			pos := positions[0]
			start := max(0, pos-16)
			end := min(len(data), pos+len(term)+16)
			fmt.Printf("      Context at 0x%X: ", pos)
			for i := start; i < end; i++ {
				if data[i] >= 32 && data[i] < 127 {
					fmt.Printf("%c", data[i])
				} else {
					fmt.Printf(".")
				}
			}
			fmt.Println()
		}
	}
	if found == 0 {
		fmt.Println("    No gadget-related strings found in binary data")
	}
}

func analyzeFeedbackArea(data []byte) {
	// The match feedback marker is 0x5934E58B04 (5 bytes)
	// Look for what types of events are reported after this marker
	feedbackMarker := []byte{0x59, 0x34, 0xE5, 0x8B, 0x04}
	positions := findAllOccurrences(data, feedbackMarker)
	fmt.Printf("    Match feedback markers found: %d\n", len(positions))

	// For each, look at what comes after
	// The kill indicator is 22D9133CBA
	killIndicator := []byte{0x22, 0xD9, 0x13, 0x3C, 0xBA}

	killCount := 0
	nonKillCount := 0
	for _, pos := range positions {
		// After the marker, there's skip data, then a size
		// Look for kill indicator within 100 bytes
		foundKill := false
		for i := pos + 5; i < min(pos+100, len(data)-5); i++ {
			if data[i] == killIndicator[0] &&
				i+5 <= len(data) &&
				data[i+1] == killIndicator[1] &&
				data[i+2] == killIndicator[2] &&
				data[i+3] == killIndicator[3] &&
				data[i+4] == killIndicator[4] {
				foundKill = true
				killCount++
				break
			}
		}
		if !foundKill {
			nonKillCount++
		}
	}
	fmt.Printf("    Kill-type events: %d, Non-kill events: %d\n", killCount, nonKillCount)

	// Show the byte content of non-kill events (these might include gadget events)
	if nonKillCount > 0 && nonKillCount <= 20 {
		fmt.Println("    Non-kill feedback event samples:")
		count := 0
		for _, pos := range positions {
			foundKill := false
			for i := pos + 5; i < min(pos+100, len(data)-5); i++ {
				if data[i] == killIndicator[0] &&
					i+5 <= len(data) &&
					data[i+1] == killIndicator[1] &&
					data[i+2] == killIndicator[2] &&
					data[i+3] == killIndicator[3] &&
					data[i+4] == killIndicator[4] {
					foundKill = true
					break
				}
			}
			if !foundKill {
				end := min(pos+80, len(data))
				fmt.Printf("      @0x%X: ", pos)
				for i := pos; i < end; i++ {
					fmt.Printf("%02X ", data[i])
				}
				fmt.Println()
				// Show ASCII interpretation
				fmt.Printf("      ASCII: ")
				for i := pos; i < end; i++ {
					if data[i] >= 32 && data[i] < 127 {
						fmt.Printf("%c", data[i])
					} else {
						fmt.Printf(".")
					}
				}
				fmt.Println()
				count++
				if count >= 10 {
					break
				}
			}
		}
	}

	// PART 5: Look for patterns that appear specifically between known time markers and ammo markers
	// These could be gadget deployment events
	fmt.Println("\n  PART 5: Patterns between time and ammo markers")
	timeMarker := []byte{0x1F, 0x07, 0xEF, 0xC9}
	ammoMarker := []byte{0x77, 0xCA, 0x96, 0xDE}

	timePositions := findAllOccurrences(data, timeMarker)
	ammoPositions := findAllOccurrences(data, ammoMarker)

	fmt.Printf("    Time markers: %d, Ammo markers: %d\n", len(timePositions), len(ammoPositions))

	// Look for repeated 4-byte sequences that appear between consecutive time markers
	// but are NOT known markers. These could be gadget packets.
	// Collect all "gap" bytes between time markers
	betweenMarkerPatterns := map[uint32]int{}
	for i := 0; i < len(timePositions)-1; i++ {
		start := timePositions[i] + 4
		end := timePositions[i+1]
		if end-start < 8 {
			continue
		}
		// Scan for 0x22 tag followed by 4 bytes (common pattern for tagged fields)
		for j := start; j < end-5; j++ {
			if data[j] == 0x22 {
				key := binary.LittleEndian.Uint32(data[j+1 : j+5])
				if key != 0 && key != 0xFFFFFFFF {
					betweenMarkerPatterns[key]++
				}
			}
		}
	}

	// Show top 0x22-prefixed patterns
	type pc struct {
		pattern uint32
		count   int
	}
	var tagged []pc
	for p, c := range betweenMarkerPatterns {
		if c >= 20 {
			tagged = append(tagged, pc{p, c})
		}
	}
	sort.Slice(tagged, func(i, j int) bool {
		return tagged[i].count > tagged[j].count
	})

	fmt.Printf("    High-frequency 0x22-tagged patterns (count >= 20, top 20):\n")
	shown := 0
	for _, t := range tagged {
		if shown >= 20 {
			break
		}
		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, t.pattern)
		known := ""
		// Check against known listener prefixes
		hex := fmt.Sprintf("22%02X%02X%02X%02X", bytes[0], bytes[1], bytes[2], bytes[3])
		for km, name := range knownMarkers {
			if strings.HasPrefix(km, hex[:min(len(hex), len(km))]) || strings.HasPrefix(hex, km[:min(len(km), len(hex))]) {
				known = " <- " + name
				break
			}
		}
		// Also check ammo field IDs
		var fid [4]byte
		copy(fid[:], bytes)
		if name, ok := knownFieldNames[fid]; ok {
			known = " <- ammo field: " + name
		}
		fmt.Printf("      22 %02X %02X %02X %02X  (count=%d)%s\n", bytes[0], bytes[1], bytes[2], bytes[3], t.count, known)
		shown++
	}

	// PART 6: Look for completely new marker types we haven't seen
	// Specifically look for patterns that could be "event" markers
	fmt.Println("\n  PART 6: Searching for gadget event patterns near known match events")
	_ = ammoPositions // prevent unused

	// Look for any unique byte sequences that appear only during action phases (not in the initial burst)
	// The initial ammo burst happens at the start. After that, any new repeating patterns could be events.
	if len(ammoPositions) > 20 {
		// Find the end of the initial burst (where consecutive ammo markers have large gaps)
		burstEnd := ammoPositions[0]
		for i := 1; i < len(ammoPositions); i++ {
			gap := ammoPositions[i] - ammoPositions[i-1]
			if gap > 5000 { // Large gap = end of initial burst
				burstEnd = ammoPositions[i-1]
				break
			}
		}
		fmt.Printf("    Initial ammo burst ends around offset 0x%X\n", burstEnd)

		// After burst, look for any 5-byte patterns that repeat (5 bytes because many known markers are 5 bytes)
		afterBurst := data[burstEnd:]
		fiveByteCounts := map[[5]byte]int{}
		for i := 0; i < len(afterBurst)-5; i++ {
			var key [5]byte
			copy(key[:], afterBurst[i:i+5])
			// Skip all-zero and common padding
			if key == [5]byte{} || key == [5]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF} {
				continue
			}
			fiveByteCounts[key]++
		}

		type fiveBytePC struct {
			pattern [5]byte
			count   int
		}
		var highFreq5 []fiveBytePC
		for p, c := range fiveByteCounts {
			if c >= 50 && c < 10000 { // Moderate frequency = likely event markers
				highFreq5 = append(highFreq5, fiveBytePC{p, c})
			}
		}
		sort.Slice(highFreq5, func(i, j int) bool {
			return highFreq5[i].count > highFreq5[j].count
		})

		fmt.Printf("    5-byte patterns appearing 50-10000 times after burst (top 15):\n")
		shown := 0
		for _, pc := range highFreq5 {
			if shown >= 15 {
				break
			}
			hex := fmt.Sprintf("%02X%02X%02X%02X%02X", pc.pattern[0], pc.pattern[1], pc.pattern[2], pc.pattern[3], pc.pattern[4])
			known := ""
			for km, name := range knownMarkers {
				if hex == km {
					known = " <- " + name
					break
				}
			}
			fmt.Printf("      %s (count=%d)%s\n", hex, pc.count, known)
			shown++
		}
	}
}

func parseAmmoEntity(data []byte, off int) *entityInfo {
	if off < 8 {
		return nil
	}

	entityID := binary.LittleEndian.Uint32(data[off-8 : off-4])
	if data[off-4] != 0 || data[off-3] != 0 || data[off-2] != 0 || data[off-1] != 0 {
		return nil
	}
	if entityID == 0 {
		return nil
	}

	pos := off + 4
	info := &entityInfo{
		entityID: entityID,
		offset:   off,
	}

	if pos+5 <= len(data) && data[pos] == 0x04 {
		info.magAmmo = binary.LittleEndian.Uint32(data[pos+1 : pos+5])
		if info.magAmmo > 10000 {
			return nil
		}
		pos += 5
	}

	for pos+6 <= len(data) && data[pos] == 0x22 {
		var fid [4]byte
		copy(fid[:], data[pos+1:pos+5])
		typeByte := data[pos+5]

		switch typeByte {
		case 0x04:
			if pos+10 > len(data) {
				return info
			}
			val := binary.LittleEndian.Uint32(data[pos+6 : pos+10])
			switch fid {
			case [4]byte{0x6D, 0x5B, 0x6D, 0x3E}:
				info.reserve = val
			case [4]byte{0x34, 0xBC, 0x4B, 0xAA}:
				info.gadgetVal = val
				info.hasGadget = true
			case [4]byte{0x56, 0xF5, 0x44, 0x0A}:
				info.magCap = val
				info.hasMagCap = true
			case [4]byte{0x40, 0x0A, 0xC8, 0x29}:
				info.total = val
			}
			pos += 10
		case 0x08:
			if pos+14 > len(data) {
				return info
			}
			pos += 14
		case 0x01:
			if pos+7 > len(data) {
				return info
			}
			pos += 7
		default:
			return info
		}
	}

	return info
}

func findAllOccurrences(data, pattern []byte) []int {
	var result []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			result = append(result, i)
		}
	}
	return result
}

func decompressReplay(r *dissect.Reader) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "replay-decomp-*.bin")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	_, err = r.Write(tmpFile)
	if err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()
	return os.ReadFile(tmpFile.Name())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: analyze <file> [command]")
		fmt.Println("Commands: patterns, defuser, players, movement, header, movementmarkers")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File size: %d bytes\n\n", len(data))

	cmd := "patterns"
	if len(os.Args) > 2 {
		cmd = os.Args[2]
	}

	switch cmd {
	case "patterns":
		analyzePatterns(data)
	case "defuser":
		analyzeDefuser(data)
	case "players":
		analyzePlayers(data)
	case "movement":
		analyzeMovement(data)
	case "movementmarkers":
		analyzeMovementMarkers(data)
	case "header":
		analyzeHeader(data)
	case "bans":
		analyzeBans(data)
	default:
		analyzePatterns(data)
	}
}

func analyzePatterns(data []byte) {
	patterns := map[string][]byte{
		"DefuserTimer":      {0x22, 0xA9, 0xC8, 0x58, 0xD9},
		"Player":            {0x22, 0x07, 0x94, 0x9B, 0xDC},
		"AtkOpSwap":         {0x22, 0xA9, 0x26, 0x0B, 0xE4},
		"Spawn":             {0xAF, 0x98, 0x99, 0xCA},
		"Time":              {0x1F, 0x07, 0xEF, 0xC9},
		"MatchFeedback":     {0x59, 0x34, 0xE5, 0x8B, 0x04},
		"ScoreboardScore":   {0xEC, 0xDA, 0x4F, 0x80},
		"ScoreboardAssists": {0x4D, 0x73, 0x7F, 0x9E},
		"ScoreboardKills":   {0x1C, 0xD2, 0xB1, 0x9D},
		"KillIndicator":     {0x22, 0xD9, 0x13, 0x3C, 0xBA},
		"PlayerID":          {0x33, 0xD8, 0x3D, 0x4F, 0x23},
		"ProfileID":         {0x8A, 0x50, 0x9B, 0xD0},
	}

	for name, pattern := range patterns {
		matches := findPattern(data, pattern)
		fmt.Printf("%s (0x%s): %d matches\n", name, hex.EncodeToString(pattern), len(matches))
		if len(matches) > 0 && len(matches) <= 10 {
			for i, offset := range matches {
				fmt.Printf("  [%d] 0x%08X\n", i, offset)
			}
		}
	}
}

func analyzeMovementMarkers(data []byte) {
	fmt.Println("Searching for high-frequency 4-byte markers that could indicate movement packets...")
	
	// Count occurrences of each 4-byte sequence
	markerCounts := make(map[string]int)
	markerPositions := make(map[string][]int)
	
	for i := 0; i < len(data)-4; i += 1 {
		marker := hex.EncodeToString(data[i : i+4])
		markerCounts[marker]++
		if len(markerPositions[marker]) < 5 {
			markerPositions[marker] = append(markerPositions[marker], i)
		}
	}
	
	// Find markers with very high occurrence (potential movement/update packets)
	type markerInfo struct {
		marker string
		count  int
	}
	var markers []markerInfo
	for m, c := range markerCounts {
		if c >= 1000 && c <= 100000 { // Look for moderately frequent patterns
			markers = append(markers, markerInfo{m, c})
		}
	}
	
	sort.Slice(markers, func(i, j int) bool {
		return markers[i].count > markers[j].count
	})
	
	fmt.Printf("Found %d markers with 1000-100000 occurrences:\n", len(markers))
	for i, m := range markers {
		if i >= 30 {
			break
		}
		positions := markerPositions[m.marker]
		fmt.Printf("  %s: %d times", m.marker, m.count)
		if len(positions) > 0 {
			fmt.Printf(" (first at 0x%X)", positions[0])
		}
		fmt.Println()
		
		// For very frequent markers, check if they're followed by coordinate-like data
		if m.count >= 5000 && len(positions) > 0 {
			offset := positions[0]
			if offset+20 < len(data) {
				// Check for 3 floats after marker+4 bytes
				f1 := readFloat32LE(data[offset+8:])
				f2 := readFloat32LE(data[offset+12:])
				f3 := readFloat32LE(data[offset+16:])
				if isReasonableCoord(f1) && isReasonableCoord(f2) && isReasonableCoord(f3) {
					fmt.Printf("    Possible coords at +8: (%.2f, %.2f, %.2f)\n", f1, f2, f3)
				}
			}
		}
	}
}

func analyzeDefuser(data []byte) {
	defuserPattern := []byte{0x22, 0xA9, 0xC8, 0x58, 0xD9}
	matches := findPattern(data, defuserPattern)
	
	fmt.Printf("Found %d DefuserTimer events\n\n", len(matches))
	
	timerEvents := 0
	emptyEvents := 0
	
	for i, offset := range matches {
		if offset+6 >= len(data) {
			continue
		}
		
		strLen := int(data[offset+5])
		
		if strLen > 0 && strLen < 20 && offset+6+strLen < len(data) {
			timerStr := string(data[offset+6 : offset+6+strLen])
			timerEvents++
			
			if timerEvents <= 30 {
				idOffset := offset + 6 + strLen + 34
				if idOffset+4 < len(data) {
					playerID := data[idOffset : idOffset+4]
					fmt.Printf("[%d] Offset 0x%08X: Timer='%s', PlayerID=%02X%02X%02X%02X\n", 
						i, offset, timerStr, playerID[0], playerID[1], playerID[2], playerID[3])
					
					fmt.Printf("    Full structure after pattern:\n")
					hexDumpInline(data[offset+5:offset+5+60], offset+5)
				}
			}
		} else {
			emptyEvents++
		}
	}
	
	fmt.Printf("\nSummary: %d timer events, %d empty/status events\n", timerEvents, emptyEvents)
}

func analyzePlayers(data []byte) {
	playerPattern := []byte{0x22, 0x07, 0x94, 0x9B, 0xDC}
	playerIDPattern := []byte{0x33, 0xD8, 0x3D, 0x4F, 0x23}
	
	playerMatches := findPattern(data, playerPattern)
	idMatches := findPattern(data, playerIDPattern)
	
	fmt.Printf("Found %d Player patterns, %d PlayerID patterns\n\n", len(playerMatches), len(idMatches))
	
	fmt.Println("--- Player Info ---")
	for i, offset := range playerMatches {
		if offset+6 >= len(data) {
			continue
		}
		
		strLen := int(data[offset+5])
		if strLen > 0 && strLen < 50 && offset+6+strLen < len(data) {
			username := string(data[offset+6 : offset+6+strLen])
			fmt.Printf("[%d] Offset 0x%08X: Username='%s'\n", i, offset, username)
		}
	}
	
	fmt.Println("\n--- Player IDs ---")
	for i, offset := range idMatches {
		if offset+5+4 >= len(data) {
			continue
		}
		playerID := data[offset+5 : offset+5+4]
		fmt.Printf("[%d] Offset 0x%08X: DissectID=%02X%02X%02X%02X\n", 
			i, offset, playerID[0], playerID[1], playerID[2], playerID[3])
	}
}

func analyzeMovement(data []byte) {
	fmt.Println("Searching for potential movement packets...")
	fmt.Println("Looking for patterns with 3 consecutive floats (position data)")
	
	floatPatterns := 0
	samples := make([]int, 0)
	
	for i := 0; i < len(data)-12; i += 4 {
		f1 := readFloat32LE(data[i:])
		f2 := readFloat32LE(data[i+4:])
		f3 := readFloat32LE(data[i+8:])
		
		if isReasonableCoord(f1) && isReasonableCoord(f2) && isReasonableCoord(f3) {
			floatPatterns++
			if len(samples) < 20 {
				samples = append(samples, i)
			}
		}
	}
	
	fmt.Printf("Found %d potential coordinate triplets\n\n", floatPatterns)
	
	for _, offset := range samples {
		f1 := readFloat32LE(data[offset:])
		f2 := readFloat32LE(data[offset+4:])
		f3 := readFloat32LE(data[offset+8:])
		fmt.Printf("Offset 0x%08X: (%.2f, %.2f, %.2f)\n", offset, f1, f2, f3)
		hexDumpInline(data[offset:offset+32], offset)
	}
	
	fmt.Println("\n--- Searching for potential movement markers ---")
	markers := [][]byte{
		{0x22, 0x51, 0xB4, 0x4C, 0x48},
		{0x26, 0x51, 0xB4, 0x4C, 0x48},
	}
	
	for _, marker := range markers {
		matches := findPattern(data, marker)
		fmt.Printf("Marker %s: %d matches\n", hex.EncodeToString(marker), len(matches))
	}
}

func analyzeBans(data []byte) {
	fmt.Println("Searching for potential operator ban data...")
	
	// Search for operator IDs in the header area (first 50KB)
	headerEnd := 50000
	if len(data) < headerEnd {
		headerEnd = len(data)
	}
	
	// Known operator IDs (as uint64 little-endian)
	operatorIDs := map[string]uint64{
		"Smoke":       92270642396,
		"Mute":        92270642318,
		"Castle":      92270642682,
		"Ash":         92270642656,
		"Thermite":    92270642760,
		"Sledge":      92270642344,
		"Thatcher":    92270642422,
		"Recruit":     359656345734,
		"Ace":         104189664390,
		"Kali":        104189663920,
		"Aruni":       104189664704,
		"Mozzie":      174977508820,
		"Melusi":      104189664273,
		"Clash":       104189662280,
		"Fenrir":      288200867339,
		"Grim":        374667788042,
	}
	
	fmt.Println("Searching for operator IDs in header region...")
	for name, id := range operatorIDs {
		idBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(idBytes, id)
		matches := findPattern(data[:headerEnd], idBytes)
		if len(matches) > 0 {
			fmt.Printf("  %s (%d): %d matches at: ", name, id, len(matches))
			for _, m := range matches {
				fmt.Printf("0x%X ", m)
			}
			fmt.Println()
		}
	}
	
	// Search for "ban" related strings
	fmt.Println("\nSearching for ban-related strings...")
	banStrings := []string{"ban", "Ban", "BAN", "Pick", "pick", "PICK", "banned", "Banned"}
	for _, s := range banStrings {
		matches := findPattern(data[:headerEnd], []byte(s))
		if len(matches) > 0 {
			fmt.Printf("  '%s': %d matches\n", s, len(matches))
			for _, m := range matches {
				start := m - 10
				if start < 0 {
					start = 0
				}
				end := m + len(s) + 20
				if end > len(data) {
					end = len(data)
				}
				fmt.Printf("    0x%X: %s\n", m, sanitizeString(data[start:end]))
			}
		}
	}
	
	// Look for patterns that might indicate ban phase data
	// This would typically be in the header/game settings area
	fmt.Println("\nLooking at GMSettings area for potential ban data...")
	// The GMSettings are numbers stored in the header
	// Ban information might be stored there or in a separate section
}

func analyzeHeader(data []byte) {
	fmt.Println("--- Header Analysis (first 10KB) ---")
	
	headerEnd := 10240
	if len(data) < headerEnd {
		headerEnd = len(data)
	}
	
	operatorIDs := map[string]uint64{
		"Smoke":   92270642396,
		"Mute":    92270642318,
		"Castle":  92270642682,
		"Ash":     92270642656,
		"Thermite": 92270642760,
		"Sledge":  92270642344,
		"Thatcher": 92270642422,
	}
	
	fmt.Println("Searching for operator IDs...")
	for name, id := range operatorIDs {
		idBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(idBytes, id)
		matches := findPattern(data[:headerEnd], idBytes)
		if len(matches) > 0 {
			fmt.Printf("  %s (%d): %d matches at offsets: ", name, id, len(matches))
			for _, m := range matches {
				fmt.Printf("0x%X ", m)
			}
			fmt.Println()
		}
	}
	
	fmt.Println("\nSearching for potential ban-related data...")
	
	stringsFound := findStrings(data[:headerEnd], 4)
	fmt.Printf("Found %d strings in header\n", len(stringsFound))
	for _, s := range stringsFound[:min(50, len(stringsFound))] {
		fmt.Printf("  0x%08X: %s\n", s.offset, s.value)
	}
}

type foundString struct {
	offset int
	value  string
}

func findStrings(data []byte, minLen int) []foundString {
	var results []foundString
	var current strings.Builder
	startOffset := 0
	
	for i, b := range data {
		if b >= 32 && b < 127 {
			if current.Len() == 0 {
				startOffset = i
			}
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				results = append(results, foundString{startOffset, current.String()})
			}
			current.Reset()
		}
	}
	
	return results
}

func findPattern(data, pattern []byte) []int {
	var matches []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			matches = append(matches, i)
		}
	}
	return matches
}

func readFloat32LE(data []byte) float32 {
	bits := binary.LittleEndian.Uint32(data)
	return math.Float32frombits(bits)
}

func isReasonableCoord(f float32) bool {
	if f != f {
		return false
	}
	if f > 1e10 || f < -1e10 {
		return false
	}
	return f >= -500 && f <= 500
}

func sanitizeString(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			result.WriteByte(b)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return result.String()
}

func hexDumpInline(data []byte, baseOffset int) {
	fmt.Printf("    ")
	for i, b := range data {
		if i > 0 && i%16 == 0 {
			fmt.Printf("\n    ")
		}
		fmt.Printf("%02X ", b)
	}
	fmt.Println()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

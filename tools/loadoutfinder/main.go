package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
)

// Patterns to search for
var (
	ammoPattern        = []byte{0x77, 0xCA, 0x96, 0xDE}
	playerPattern      = []byte{0x22, 0x07, 0x94, 0x9B, 0xDC}
	playerIDPattern    = []byte{0x33, 0xD8, 0x3D, 0x4F, 0x23}
	spawnPattern       = []byte{0xAF, 0x98, 0x99, 0xCA}
	profileIDPattern   = []byte{0x8A, 0x50, 0x9B, 0xD0}
	unknownAppearance  = []byte{0x22, 0xEE, 0xD4, 0x45, 0xC8, 0x08}
	uiIDPattern        = []byte{0x38, 0xDF, 0xEE, 0x88}
	opSwapPattern      = []byte{0x22, 0xA9, 0x26, 0x0B, 0xE4}
	seekD99D           = []byte{0xD9, 0x9D}
	feedbackPattern    = []byte{0x59, 0x34, 0xE5, 0x8B, 0x04}
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: loadoutfinder <dump.bin>")
		fmt.Println("Analyzes decompressed replay binary for loadout/weapon/ammo patterns")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File size: %d bytes (%.1f MB)\n\n", len(data), float64(len(data))/1024/1024)

	// ==============================
	// 1. Search for ammo pattern (0x77CA96DE)
	// ==============================
	fmt.Println("=" + repeat("=", 69))
	fmt.Println("  AMMO PATTERN ANALYSIS (0x77CA96DE)")
	fmt.Println("=" + repeat("=", 69))
	analyzeAmmoPattern(data)

	// ==============================
	// 2. Analyze player setup packets for loadout data
	// ==============================
	fmt.Println("\n" + "=" + repeat("=", 69))
	fmt.Println("  PLAYER PACKET ANALYSIS")
	fmt.Println("=" + repeat("=", 69))
	analyzePlayerPackets(data)

	// ==============================
	// 3. Search for unknown appearance pattern
	// ==============================
	fmt.Println("\n" + "=" + repeat("=", 69))
	fmt.Println("  APPEARANCE PATTERN (0x22EED445C808)")
	fmt.Println("=" + repeat("=", 69))
	analyzeAppearancePattern(data)

	// ==============================
	// 4. Look for uint64 patterns near player data that could be weapon IDs
	// ==============================
	fmt.Println("\n" + "=" + repeat("=", 69))
	fmt.Println("  WEAPON ID SEARCH (uint64 near player data)")
	fmt.Println("=" + repeat("=", 69))
	searchWeaponIDs(data)

	// ==============================
	// 5. Analyze the header-to-packet gap
	// ==============================
	fmt.Println("\n" + "=" + repeat("=", 69))
	fmt.Println("  HEADER-TO-PACKET GAP ANALYSIS")
	fmt.Println("=" + repeat("=", 69))
	analyzeHeaderGap(data)
}

func analyzeAmmoPattern(data []byte) {
	matches := findPattern(data, ammoPattern)
	fmt.Printf("Found %d ammo pattern (0x77CA96DE) occurrences\n\n", len(matches))

	for i, offset := range matches {
		fmt.Printf("--- Ammo Event #%d at offset 0x%08X ---\n", i+1, offset)

		// The pattern is followed by ammo data
		// PR #63 structure: pattern -> Uint32(available) -> Skip(5) -> Uint32(capacity) -> Seek(D9 9D) -> playerID(4)
		pos := offset + len(ammoPattern)

		// Read available ammo (Uint32 = skip 1 byte size + 4 bytes LE)
		if pos+5 < len(data) {
			sizeByte := data[pos]
			available := binary.LittleEndian.Uint32(data[pos+1 : pos+5])
			fmt.Printf("  Size byte: 0x%02X, Available ammo: %d\n", sizeByte, available)
			pos += 5
		}

		// Skip 5 bytes
		if pos+5 < len(data) {
			fmt.Printf("  Skipped 5 bytes: %s\n", hex.EncodeToString(data[pos:pos+5]))
			pos += 5
		}

		// Read capacity (Uint32 = skip 1 byte size + 4 bytes LE)
		if pos+5 < len(data) {
			sizeByte := data[pos]
			capacity := binary.LittleEndian.Uint32(data[pos+1 : pos+5])
			fmt.Printf("  Size byte: 0x%02X, Capacity: %d\n", sizeByte, capacity)
			pos += 5
		}

		// Look for D9 9D marker nearby
		searchEnd := pos + 200
		if searchEnd > len(data) {
			searchEnd = len(data)
		}
		d99dIdx := bytes.Index(data[pos:searchEnd], seekD99D)
		if d99dIdx >= 0 {
			idPos := pos + d99dIdx + len(seekD99D)
			if idPos+4 <= len(data) {
				playerID := data[idPos : idPos+4]
				fmt.Printf("  D9 9D found at +%d, PlayerID: %s\n", d99dIdx, hex.EncodeToString(playerID))
			}
			fmt.Printf("  Bytes between capacity and D9 9D (%d bytes): %s\n",
				d99dIdx, hex.EncodeToString(data[pos:pos+min(d99dIdx, 60)]))
		}

		// Dump broader context around the ammo pattern
		contextStart := offset - 40
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := offset + 80
		if contextEnd > len(data) {
			contextEnd = len(data)
		}
		fmt.Printf("  Context (offset-40 to offset+80):\n")
		hexDumpLines(data[contextStart:contextEnd], contextStart, offset)
		fmt.Println()

		if i >= 30 {
			fmt.Printf("  ... and %d more ammo events\n", len(matches)-30)
			break
		}
	}

	// Aggregate statistics
	if len(matches) > 0 {
		fmt.Printf("\n--- Ammo Aggregate Stats ---\n")
		var ammoValues []uint32
		var capValues []uint32
		for _, offset := range matches {
			pos := offset + len(ammoPattern)
			if pos+5 < len(data) {
				available := binary.LittleEndian.Uint32(data[pos+1 : pos+5])
				ammoValues = append(ammoValues, available)
			}
			pos += 10
			if pos+5 < len(data) {
				capacity := binary.LittleEndian.Uint32(data[pos+1 : pos+5])
				capValues = append(capValues, capacity)
			}
		}
		fmt.Printf("  Available ammo values: ")
		printUniqueUint32(ammoValues)
		fmt.Printf("  Capacity values: ")
		printUniqueUint32(capValues)
	}
}

func analyzePlayerPackets(data []byte) {
	playerMatches := findPattern(data, playerPattern)
	fmt.Printf("Found %d player packets\n\n", len(playerMatches))

	for i, offset := range playerMatches {
		fmt.Printf("--- Player Packet #%d at offset 0x%08X ---\n", i+1, offset)

		pos := offset + len(playerPattern)

		// Read username (String = 1 byte len + data)
		if pos+1 < len(data) {
			nameLen := int(data[pos])
			pos++
			if pos+nameLen <= len(data) && nameLen > 0 && nameLen < 50 {
				username := string(data[pos : pos+nameLen])
				fmt.Printf("  Username: %s\n", username)
				pos += nameLen
			}
		}

		// Find opSwap/0x40F21504 pattern for operator
		searchEnd := offset + 2000
		if searchEnd > len(data) {
			searchEnd = len(data)
		}

		// Look for 0x40F21504 which appears before operator ID
		opMarker := []byte{0x40, 0xF2, 0x15, 0x04}
		opIdx := bytes.Index(data[pos:searchEnd], opMarker)
		if opIdx >= 0 {
			opPos := pos + opIdx + len(opMarker)
			// Skip 8 bytes + 1 byte swap check
			if opPos+9 < len(data) {
				opPos += 9
				// Now we should be near the opSwap marker, look for it
			}
		}

		// Look for playerID indicator
		idIdx := bytes.Index(data[pos:searchEnd], playerIDPattern)
		if idIdx >= 0 {
			idPos := pos + idIdx + len(playerIDPattern)
			if idPos+4 <= len(data) {
				playerID := data[idPos : idPos+4]
				fmt.Printf("  DissectID: %s (at offset 0x%08X)\n",
					hex.EncodeToString(playerID), idPos)

				// Dump everything between username and player ID
				gapSize := pos + idIdx - pos
				if gapSize > 0 && gapSize < 1000 {
					fmt.Printf("  Gap between username and playerID (%d bytes):\n", gapSize)
					hexDumpLines(data[pos:pos+idIdx], pos, -1)
				}
			}
		}

		// Look for spawn indicator
		spawnIdx := bytes.Index(data[pos:searchEnd], spawnPattern)
		if spawnIdx >= 0 {
			spawnPos := pos + spawnIdx + len(spawnPattern)
			if spawnPos+1 < len(data) {
				spawnLen := int(data[spawnPos])
				if spawnPos+1+spawnLen <= len(data) && spawnLen < 100 {
					spawn := string(data[spawnPos+1 : spawnPos+1+spawnLen])
					fmt.Printf("  Spawn: %s\n", spawn)
				}
			}
		}

		// Look for profileID indicator
		profIdx := bytes.Index(data[pos:searchEnd], profileIDPattern)
		if profIdx >= 0 {
			profPos := pos + profIdx + len(profileIDPattern)
			if profPos+1 < len(data) {
				profLen := int(data[profPos])
				if profPos+1+profLen <= len(data) && profLen < 100 {
					profileID := string(data[profPos+1 : profPos+1+profLen])
					fmt.Printf("  ProfileID: %s\n", profileID)
				}
			}
		}

		// Look for appearance pattern between playerID and spawn
		appIdx := bytes.Index(data[pos:searchEnd], unknownAppearance)
		if appIdx >= 0 {
			appPos := pos + appIdx + len(unknownAppearance)
			fmt.Printf("  Appearance pattern at offset 0x%08X\n", pos+appIdx)
			if appPos+60 <= len(data) {
				fmt.Printf("  Data after appearance pattern (60 bytes):\n")
				hexDumpLines(data[appPos:appPos+60], appPos, -1)
			}
		}

		// Look for uiID pattern
		uiIdx := bytes.Index(data[pos:searchEnd], uiIDPattern)
		if uiIdx >= 0 {
			fmt.Printf("  uiID pattern at offset 0x%08X\n", pos+uiIdx)
		}

		fmt.Println()
	}
}

func analyzeAppearancePattern(data []byte) {
	matches := findPattern(data, unknownAppearance)
	fmt.Printf("Found %d appearance pattern (0x22EED445C808) occurrences\n\n", len(matches))

	for i, offset := range matches {
		fmt.Printf("--- Appearance #%d at offset 0x%08X ---\n", i+1, offset)

		pos := offset + len(unknownAppearance)

		// Dump 120 bytes after pattern
		dumpEnd := pos + 120
		if dumpEnd > len(data) {
			dumpEnd = len(data)
		}
		fmt.Printf("  Data after pattern (%d bytes):\n", dumpEnd-pos)
		hexDumpLines(data[pos:dumpEnd], pos, -1)

		// Try reading as Uint64 (could be weapon/skin ID)
		if pos+9 <= len(data) {
			// Skip size byte, read uint64
			val := binary.LittleEndian.Uint64(data[pos+1 : pos+9])
			fmt.Printf("  As Uint64 (after skip 1): %d (0x%016X)\n", val, val)
		}

		// Look for strings nearby
		searchStrings(data, pos, pos+120)

		fmt.Println()
		if i >= 20 {
			fmt.Printf("  ... and %d more\n", len(matches)-20)
			break
		}
	}
}

func searchWeaponIDs(data []byte) {
	// After each player packet, look for uint64 values in the operator ID range
	// Known operator IDs are in ranges like 92270641980-92270644345, 104189661861-104189664704, etc.
	// Weapon IDs might follow similar patterns

	playerMatches := findPattern(data, playerPattern)
	fmt.Printf("Searching for uint64 values near %d player packets...\n\n", len(playerMatches))

	// Collect all uint64 values found in player packet vicinity
	valueCounts := make(map[uint64]int)
	valueLocations := make(map[uint64][]int)

	for _, offset := range playerMatches {
		start := offset + len(playerPattern)
		end := start + 2000
		if end > len(data)-8 {
			end = len(data) - 8
		}

		for pos := start; pos < end; pos++ {
			if pos+9 > len(data) {
				break
			}
			// Look for size byte 0x08 followed by 8 bytes (Uint64 format used in dissect)
			if data[pos] == 0x08 {
				val := binary.LittleEndian.Uint64(data[pos+1 : pos+9])
				// Filter for plausible ID ranges (not tiny, not huge, not all zeros/ones)
				if val > 1000000 && val < 1000000000000 {
					valueCounts[val]++
					if len(valueLocations[val]) < 3 {
						valueLocations[val] = append(valueLocations[val], pos)
					}
				}
			}
		}
	}

	// Sort by count and display
	type valCount struct {
		val   uint64
		count int
	}
	var sorted []valCount
	for v, c := range valueCounts {
		sorted = append(sorted, valCount{v, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	// Known operator IDs to filter out
	knownOps := map[uint64]bool{
		359656345734: true, 92270642682: true, 104189664704: true,
		161289666230: true, 174977508820: true, 92270642708: true,
		104189664390: true, 92270642214: true, 378305069945: true,
		391752120891: true, 92270644215: true, 92270644189: true,
		92270644267: true, 104189662920: true, 92270644319: true,
		92270642344: true, 104189664273: true, 92270642526: true,
		92270642188: true, 92270644059: true, 92270641980: true,
		291191151607: true, 104189664038: true, 92270642656: true,
		92270642136: true, 288200867444: true, 373711624351: true,
		92270642604: true, 104189663920: true, 92270642760: true,
		288200866821: true, 104189663607: true, 92270642292: true,
		92270642266: true, 92270644007: true, 104189661861: true,
		92270642032: true, 92270642396: true, 92270644293: true,
		92270642318: true, 104189663698: true, 104189663803: true,
		92270644163: true, 92270644033: true, 104189663024: true,
		104189662071: true, 104189661965: true, 92270644241: true,
		161289666248: true, 288200867351: true, 384797789346: true,
		92270642578: true, 92270642539: true, 92270642240: true,
		104189662384: true, 328397386974: true, 92270642474: true,
		92270644111: true, 174977508808: true, 92270642422: true,
		92270642084: true, 92270644345: true, 374667788042: true,
		291437347686: true, 104189664155: true, 92270642500: true,
		104189662175: true, 104189662280: true, 288200867339: true,
		395943091136: true, 288200867549: true, 374667787816: true,
		409899350463: true, 409899350403: true, 386098331713: true,
		386098331923: true, 374667787937: true,
	}

	fmt.Printf("Unique uint64 values (not known operators) found near player packets:\n\n")
	shown := 0
	for _, vc := range sorted {
		if knownOps[vc.val] {
			continue
		}
		if shown >= 50 {
			break
		}
		fmt.Printf("  %d (0x%012X): %d times, first at 0x%08X\n",
			vc.val, vc.val, vc.count, valueLocations[vc.val][0])
		shown++
	}
}

func analyzeHeaderGap(data []byte) {
	// Find the "dissect" magic and then search for the gap between header and packets
	dissectMagic := []byte("dissect")
	magicIdx := bytes.Index(data, dissectMagic)
	if magicIdx < 0 {
		fmt.Println("No 'dissect' magic found - this may be a pre-decompressed dump")

		// Try to find the first player packet as anchor
		firstPlayer := bytes.Index(data, playerPattern)
		if firstPlayer > 0 {
			fmt.Printf("First player packet at offset 0x%08X\n", firstPlayer)

			// Look at the data before the first player packet
			// Search for incrementing pattern sections
			scanStart := 0
			if firstPlayer > 10000 {
				scanStart = firstPlayer - 10000
			}
			analyzeIncrementingSection(data[scanStart:firstPlayer], scanStart)
		}
		return
	}

	fmt.Printf("'dissect' magic at offset 0x%08X\n", magicIdx)

	// Find first player packet
	firstPlayer := bytes.Index(data, playerPattern)
	if firstPlayer < 0 {
		fmt.Println("No player packets found")
		return
	}
	fmt.Printf("First player packet at offset 0x%08X\n", firstPlayer)
	fmt.Printf("Gap between dissect header and first player: %d bytes\n\n", firstPlayer-magicIdx)

	// Find first feedback packet (marks the start of game data)
	firstFeedback := bytes.Index(data, feedbackPattern)
	if firstFeedback > 0 {
		fmt.Printf("First feedback packet at offset 0x%08X\n", firstFeedback)
	}

	// Analyze the section between header strings and first player packet
	// Look for incrementing patterns
	analyzeIncrementingSection(data[magicIdx:firstPlayer], magicIdx)
}

func analyzeIncrementingSection(data []byte, baseOffset int) {
	fmt.Printf("\nSearching for incrementing pattern section in %d bytes...\n", len(data))

	// Look for a section where 2-byte values increment
	streaks := 0
	bestStart := 0
	bestLen := 0
	currentStart := 0
	currentLen := 0

	for i := 2; i < len(data)-2; i += 2 {
		prev := binary.LittleEndian.Uint16(data[i-2 : i])
		curr := binary.LittleEndian.Uint16(data[i : i+2])

		if curr == prev+1 {
			if currentLen == 0 {
				currentStart = i - 2
			}
			currentLen++
		} else {
			if currentLen > 5 {
				streaks++
				if currentLen > bestLen {
					bestLen = currentLen
					bestStart = currentStart
				}
			}
			currentLen = 0
		}
	}

	if bestLen > 0 {
		fmt.Printf("Longest incrementing streak: %d values starting at offset 0x%08X\n",
			bestLen, baseOffset+bestStart)

		// Dump some of the incrementing section
		dumpStart := bestStart
		dumpEnd := bestStart + min(200, bestLen*2)
		if dumpEnd > len(data) {
			dumpEnd = len(data)
		}
		fmt.Printf("Sample from incrementing section:\n")
		hexDumpLines(data[dumpStart:dumpEnd], baseOffset+dumpStart, -1)
	}
	fmt.Printf("Total incrementing streaks (>5): %d\n", streaks)
}

// =========== Helpers ===========

func findPattern(data, pattern []byte) []int {
	var matches []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			matches = append(matches, i)
		}
	}
	return matches
}

func hexDumpLines(data []byte, baseOffset int, highlightOffset int) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]

		// Offset
		fmt.Printf("    %08X: ", baseOffset+i)

		// Hex
		for j, b := range line {
			absOffset := baseOffset + i + j
			if absOffset >= highlightOffset && absOffset < highlightOffset+4 && highlightOffset >= 0 {
				fmt.Printf("[%02X]", b)
			} else {
				fmt.Printf("%02X ", b)
			}
		}
		// Padding
		for j := len(line); j < 16; j++ {
			fmt.Print("   ")
		}

		// ASCII
		fmt.Print(" |")
		for _, b := range line {
			if b >= 32 && b < 127 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

func searchStrings(data []byte, start, end int) {
	if end > len(data) {
		end = len(data)
	}
	var current []byte
	startOffset := 0
	for i := start; i < end; i++ {
		if data[i] >= 32 && data[i] < 127 {
			if len(current) == 0 {
				startOffset = i
			}
			current = append(current, data[i])
		} else {
			if len(current) >= 4 {
				fmt.Printf("  String at 0x%08X: %q\n", startOffset, string(current))
			}
			current = current[:0]
		}
	}
	if len(current) >= 4 {
		fmt.Printf("  String at 0x%08X: %q\n", startOffset, string(current))
	}
}

func printUniqueUint32(values []uint32) {
	counts := make(map[uint32]int)
	for _, v := range values {
		counts[v]++
	}
	type vc struct {
		val   uint32
		count int
	}
	var sorted []vc
	for v, c := range counts {
		sorted = append(sorted, vc{v, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	for i, s := range sorted {
		if i >= 20 {
			fmt.Printf("... and %d more unique values", len(sorted)-20)
			break
		}
		fmt.Printf("%d(%dx) ", s.val, s.count)
	}
	fmt.Println()
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Unused but available for further analysis
func readFloat32LE(data []byte) float32 {
	bits := binary.LittleEndian.Uint32(data)
	return math.Float32frombits(bits)
}

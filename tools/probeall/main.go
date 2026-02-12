// probeall: Deep analysis of ALL movement packet types after the 60 73 85 fe marker.
//
// For every packet type found, this tool:
//   1. Checks if player IDs (5-14) exist at known offsets (+4 for 01-like, +20 for 03-like)
//   2. Checks if player IDs exist at ANY 4-byte offset (brute force scan)
//   3. Compares coordinate spatial overlap with known 0x01/0x03 player tracks
//   4. Checks prefix families (0x30 vs 0xB0 etc.) to see if structure is the same
//
// Run: go run ./tools/probeall <replay.rec>
package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type rawPkt struct {
	num       int
	prefix    byte
	suffix    byte
	entityID  uint32
	rawBytes  []byte // 80 bytes after type bytes
}

var (
	allPkts  []rawPkt
	pktCount int
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/probeall <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capture)
	r.Read()

	fmt.Printf("Total packets: %d\n", len(allPkts))
	fmt.Printf("Season: %s (code: %d)\n", r.Header.GameVersion, r.Header.CodeVersion)
	fmt.Printf("Map: %s\n\n", r.Header.Map.String())

	fmt.Println("Players:")
	for i, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex < len(r.Header.Teams) {
			team = string(r.Header.Teams[p.TeamIndex].Role)
		}
		fmt.Printf("  [%d] %-18s Team %d (%s) -> Player ID %d\n", i, p.Username, p.TeamIndex, team, i+5)
	}

	// =========================================================================
	// ANALYSIS 1: Player ID probe at known offsets, by full type code
	// =========================================================================
	fmt.Println("\n" + sep("ANALYSIS 1: Player ID Probe at Known Offsets (by full type code)"))

	type typeStats struct {
		code       uint16
		total      int
		validCoord int
		// Player ID found at 01-style offset (postBytes[4:8])
		id01Hits  int
		id01Dist  map[uint32]int
		// Player ID found at 03-style offset (postBytes[20:24])
		id03Hits  int
		id03Dist  map[uint32]int
	}

	byType := make(map[uint16]*typeStats)
	for _, p := range allPkts {
		code := uint16(p.prefix)<<8 | uint16(p.suffix)
		if byType[code] == nil {
			byType[code] = &typeStats{code: code, id01Dist: make(map[uint32]int), id03Dist: make(map[uint32]int)}
		}
		ts := byType[code]
		ts.total++

		if len(p.rawBytes) < 12 {
			continue
		}

		x := f32(p.rawBytes[0:4])
		y := f32(p.rawBytes[4:8])
		z := f32(p.rawBytes[8:12])
		if validCoord(x) && validCoord(y) && z >= -10 && z <= 50 {
			ts.validCoord++
		}

		// Check 01-style offset: player ID at postBytes[16:20] (coords are 12 bytes, then +4 = offset 16)
		if len(p.rawBytes) >= 20 {
			id := binary.LittleEndian.Uint32(p.rawBytes[16:20])
			if id >= 5 && id <= 14 {
				ts.id01Hits++
				ts.id01Dist[id]++
			}
		}

		// Check 03-style offset: player ID at postBytes[32:36] (coords 12 bytes, then +20 = offset 32)
		if len(p.rawBytes) >= 36 {
			id := binary.LittleEndian.Uint32(p.rawBytes[32:36])
			if id >= 5 && id <= 14 {
				ts.id03Hits++
				ts.id03Dist[id]++
			}
		}
	}

	var types []*typeStats
	for _, ts := range byType {
		types = append(types, ts)
	}
	sort.Slice(types, func(i, j int) bool { return types[i].total > types[j].total })

	fmt.Printf("\n%-8s %6s %6s %8s %8s %8s %8s\n",
		"Type", "Total", "Coords", "ID@+16", "IDs(+16)", "ID@+32", "IDs(+32)")
	fmt.Println("--------------------------------------------------------------")

	for _, ts := range types {
		if ts.total < 10 {
			continue
		}
		prefix := byte(ts.code >> 8)
		suffix := byte(ts.code & 0xFF)
		coordPct := ""
		if ts.validCoord > 0 {
			coordPct = fmt.Sprintf("%5.1f%%", float64(ts.validCoord)/float64(ts.total)*100)
		}
		id01Pct := ""
		if ts.id01Hits > 0 {
			id01Pct = fmt.Sprintf("%5.1f%%", float64(ts.id01Hits)/float64(ts.total)*100)
		}
		id03Pct := ""
		if ts.id03Hits > 0 {
			id03Pct = fmt.Sprintf("%5.1f%%", float64(ts.id03Hits)/float64(ts.total)*100)
		}

		fmt.Printf("0x%02X%02X %6d %6s %8s %8d %8s %8d\n",
			prefix, suffix, ts.total, coordPct, id01Pct, len(ts.id01Dist), id03Pct, len(ts.id03Dist))
	}

	// =========================================================================
	// ANALYSIS 2: Brute-force player ID scan at ALL offsets, by suffix
	// =========================================================================
	fmt.Println("\n" + sep("ANALYSIS 2: Brute-Force Player ID Scan (all offsets, by suffix)"))

	type suffixOffsetHit struct {
		suffix byte
		offset int
		hits   int
		ids    map[uint32]int
	}

	suffixBest := make(map[byte]*suffixOffsetHit) // best offset per suffix

	for suffix := byte(0); suffix <= 0x1F; suffix++ {
		var pktsForSuffix []rawPkt
		for _, p := range allPkts {
			if p.suffix == suffix {
				pktsForSuffix = append(pktsForSuffix, p)
			}
		}
		if len(pktsForSuffix) < 20 {
			continue
		}

		bestOff := -1
		bestScore := 0
		var bestDist map[uint32]int

		for off := 0; off+4 <= 80; off += 4 {
			dist := make(map[uint32]int)
			hits := 0
			for _, p := range pktsForSuffix {
				if off+4 > len(p.rawBytes) {
					continue
				}
				id := binary.LittleEndian.Uint32(p.rawBytes[off : off+4])
				if id >= 5 && id <= 14 {
					hits++
					dist[id]++
				}
			}
			// Score: prefer offsets with many hits AND many unique IDs
			score := hits * len(dist)
			if score > bestScore {
				bestScore = score
				bestOff = off
				bestDist = dist
			}
		}

		if bestOff >= 0 && bestScore > 0 {
			suffixBest[suffix] = &suffixOffsetHit{
				suffix: suffix,
				offset: bestOff,
				hits:   0,
				ids:    bestDist,
			}
			total := 0
			for _, c := range bestDist {
				total += c
			}
			suffixBest[suffix].hits = total
		}
	}

	fmt.Printf("\n%-8s %6s %8s %6s  %s\n", "Suffix", "Pkts", "BestOff", "Hits", "Unique IDs -> Distribution")
	fmt.Println("-------------------------------------------------------------------------")

	var suffKeys []byte
	for k := range suffixBest {
		suffKeys = append(suffKeys, k)
	}
	sort.Slice(suffKeys, func(i, j int) bool { return suffKeys[i] < suffKeys[j] })

	for _, suffix := range suffKeys {
		sh := suffixBest[suffix]
		totalPkts := 0
		for _, p := range allPkts {
			if p.suffix == suffix {
				totalPkts++
			}
		}
		hitPct := float64(sh.hits) / float64(totalPkts) * 100

		distStr := ""
		for id := uint32(5); id <= 14; id++ {
			if sh.ids[id] > 0 {
				distStr += fmt.Sprintf("%d:%d ", id, sh.ids[id])
			}
		}

		quality := ""
		if len(sh.ids) >= 8 && hitPct > 30 {
			quality = " *** STRONG ***"
		} else if len(sh.ids) >= 5 && hitPct > 15 {
			quality = " ** MODERATE **"
		}

		fmt.Printf("  0x%02X %6d   +%-4d %5.1f%% %2d unique  %s%s\n",
			suffix, totalPkts, sh.offset, hitPct, len(sh.ids), distStr, quality)
	}

	// =========================================================================
	// ANALYSIS 3: Prefix comparison (same suffix, different prefix)
	// =========================================================================
	fmt.Println("\n" + sep("ANALYSIS 3: Prefix Family Comparison (same suffix, different prefix)"))

	// For each suffix that we capture (0x01, 0x03), compare structure across prefixes
	for _, targetSuffix := range []byte{0x01, 0x03, 0x02, 0x04, 0x05, 0x06} {
		prefixGroups := make(map[byte][]rawPkt)
		for _, p := range allPkts {
			if p.suffix == targetSuffix {
				prefixGroups[p.prefix] = append(prefixGroups[p.prefix], p)
			}
		}
		if len(prefixGroups) < 2 {
			continue
		}

		fmt.Printf("\n  Suffix 0x%02X across prefix families:\n", targetSuffix)

		var prefixes []byte
		for k := range prefixGroups {
			prefixes = append(prefixes, k)
		}
		sort.Slice(prefixes, func(i, j int) bool { return prefixes[i] < prefixes[j] })

		// Use the best offset from Analysis 2 for this suffix
		bestOff := -1
		if sh, ok := suffixBest[targetSuffix]; ok {
			bestOff = sh.offset
		}

		for _, prefix := range prefixes {
			pkts := prefixGroups[prefix]
			if len(pkts) < 5 {
				continue
			}

			// Count valid coords
			coordCount := 0
			for _, p := range pkts {
				if len(p.rawBytes) >= 12 {
					x := f32(p.rawBytes[0:4])
					y := f32(p.rawBytes[4:8])
					z := f32(p.rawBytes[8:12])
					if validCoord(x) && validCoord(y) && z >= -10 && z <= 50 {
						coordCount++
					}
				}
			}

			// Check player IDs at best offset
			idCount := 0
			uniqueIDs := make(map[uint32]bool)
			if bestOff >= 0 {
				for _, p := range pkts {
					if bestOff+4 <= len(p.rawBytes) {
						id := binary.LittleEndian.Uint32(p.rawBytes[bestOff : bestOff+4])
						if id >= 5 && id <= 14 {
							idCount++
							uniqueIDs[id] = true
						}
					}
				}
			}

			captured := ""
			if prefix >= 0xB0 && (targetSuffix == 0x01 || targetSuffix == 0x03) {
				captured = " [CAPTURED]"
			} else {
				captured = " [MISSED]"
			}

			coordPct := float64(coordCount) / float64(len(pkts)) * 100
			idPct := float64(idCount) / float64(len(pkts)) * 100

			fmt.Printf("    0x%02X%02X: %5d pkts, coords=%5.1f%%, playerIDs(+%d)=%5.1f%% (%d unique)%s\n",
				prefix, targetSuffix, len(pkts), coordPct, bestOff, idPct, len(uniqueIDs), captured)
		}
	}

	// =========================================================================
	// ANALYSIS 4: Spatial correlation - do non-captured types track the same positions?
	// =========================================================================
	fmt.Println("\n" + sep("ANALYSIS 4: Spatial Correlation with Captured 0x01/0x03 Tracks"))

	// Build position grid from captured types (B0xx/B8xx/BCxx with suffix 01/03)
	type gridKey struct{ x, y int }
	capturedGrid := make(map[gridKey]bool)
	capturedCount := 0

	for _, p := range allPkts {
		if (p.suffix == 0x01 || p.suffix == 0x03) && p.prefix >= 0xB0 {
			if len(p.rawBytes) >= 12 {
				x := f32(p.rawBytes[0:4])
				y := f32(p.rawBytes[4:8])
				if validCoord(x) && validCoord(y) {
					capturedGrid[gridKey{int(math.Round(float64(x))), int(math.Round(float64(y)))}] = true
					capturedCount++
				}
			}
		}
	}

	fmt.Printf("\nCaptured position grid: %d unique cells from %d packets\n\n", len(capturedGrid), capturedCount)

	// For each non-captured suffix, check overlap
	type overlapResult struct {
		suffix  byte
		total   int
		overlap int
	}
	var overlaps []overlapResult

	suffixPkts := make(map[byte][]rawPkt)
	for _, p := range allPkts {
		// Skip already-captured types
		if (p.suffix == 0x01 || p.suffix == 0x03) && p.prefix >= 0xB0 {
			continue
		}
		suffixPkts[p.suffix] = append(suffixPkts[p.suffix], p)
	}

	for suffix, pkts := range suffixPkts {
		total := 0
		overlap := 0
		for _, p := range pkts {
			if len(p.rawBytes) < 12 {
				continue
			}
			x := f32(p.rawBytes[0:4])
			y := f32(p.rawBytes[4:8])
			z := f32(p.rawBytes[8:12])
			if !validCoord(x) || !validCoord(y) || z < -10 || z > 50 {
				continue
			}
			total++
			key := gridKey{int(math.Round(float64(x))), int(math.Round(float64(y)))}
			if capturedGrid[key] {
				overlap++
			}
		}
		if total > 20 {
			overlaps = append(overlaps, overlapResult{suffix, total, overlap})
		}
	}

	sort.Slice(overlaps, func(i, j int) bool { return overlaps[i].total > overlaps[j].total })

	fmt.Printf("%-8s %6s %8s %8s  %s\n", "Suffix", "Valid", "Overlap", "Pct", "Assessment")
	fmt.Println("------------------------------------------------------")
	for _, o := range overlaps {
		pct := float64(o.overlap) / float64(o.total) * 100
		assessment := ""
		if pct > 70 {
			assessment = "SAME PLAYER POSITIONS - high value"
		} else if pct > 40 {
			assessment = "LIKELY RELATED - moderate value"
		} else if pct > 15 {
			assessment = "SOME OVERLAP - may include other entities"
		} else {
			assessment = "DIFFERENT DATA - likely non-player"
		}
		fmt.Printf("  0x%02X %6d %8d %7.1f%%  %s\n", o.suffix, o.total, o.overlap, pct, assessment)
	}

	// =========================================================================
	// ANALYSIS 5: Entity ID comparison between prefix families
	// =========================================================================
	fmt.Println("\n" + sep("ANALYSIS 5: Entity ID Sharing Between Prefix Families"))

	// For suffix 0x03 (our main type), check if entity IDs from 0x30 prefix
	// overlap with entity IDs from 0xB8 prefix
	for _, targetSuffix := range []byte{0x03, 0x01} {
		entityByPrefix := make(map[byte]map[uint32]int) // prefix -> entityID -> count
		for _, p := range allPkts {
			if p.suffix != targetSuffix {
				continue
			}
			if entityByPrefix[p.prefix] == nil {
				entityByPrefix[p.prefix] = make(map[uint32]int)
			}
			entityByPrefix[p.prefix][p.entityID]++
		}

		if len(entityByPrefix) < 2 {
			continue
		}

		fmt.Printf("\n  Suffix 0x%02X entity ID comparison:\n", targetSuffix)

		var pKeys []byte
		for k := range entityByPrefix {
			pKeys = append(pKeys, k)
		}
		sort.Slice(pKeys, func(i, j int) bool { return pKeys[i] < pKeys[j] })

		for _, prefix := range pKeys {
			entities := entityByPrefix[prefix]
			if len(entities) < 3 {
				continue
			}
			fmt.Printf("    Prefix 0x%02X: %d unique entities, top: ", prefix, len(entities))
			// Show top 3 entities
			type eidCount struct {
				id    uint32
				count int
			}
			var sorted []eidCount
			for id, c := range entities {
				sorted = append(sorted, eidCount{id, c})
			}
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
			for i := 0; i < min(5, len(sorted)); i++ {
				fmt.Printf("0x%08X(%d) ", sorted[i].id, sorted[i].count)
			}
			fmt.Println()
		}

		// Check overlap: do B8 and 30 share entity IDs?
		highEntities := entityByPrefix[0xB8]
		lowEntities := entityByPrefix[0x30]
		if highEntities != nil && lowEntities != nil {
			shared := 0
			for id := range highEntities {
				if lowEntities[id] > 0 {
					shared++
				}
			}
			fmt.Printf("    Entity IDs shared between 0xB8 and 0x30: %d (of %d B8, %d 30)\n",
				shared, len(highEntities), len(lowEntities))
			if shared > 0 {
				fmt.Printf("    ==> SAME ENTITIES across prefix families!\n")
			} else {
				fmt.Printf("    ==> DIFFERENT ENTITIES - prefixes track different things\n")
			}
		}
	}
}

func capture(r *dissect.Reader) error {
	pktCount++

	// Entity ID from 4 bytes before marker (marker is 6 bytes)
	// PeekBack(10) gives us 4 entity bytes + 6 marker bytes
	raw := r.PeekBack(10)
	entityID := uint32(0)
	if len(raw) >= 10 {
		entityID = binary.LittleEndian.Uint32(raw[:4])
	}

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	rawBytes, err := r.Bytes(80)
	if err != nil {
		rawBytes = make([]byte, 0)
	}

	allPkts = append(allPkts, rawPkt{
		num:      pktCount,
		prefix:   typeBytes[0],
		suffix:   typeBytes[1],
		entityID: entityID,
		rawBytes: rawBytes,
	})
	return nil
}

func f32(b []byte) float32 {
	if len(b) < 4 {
		return float32(math.NaN())
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(b))
}

func validCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func sep(title string) string {
	return fmt.Sprintf("========================================================================\n%s\n========================================================================", title)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// investigate3f deeply analyzes all packet types found after the 60 73 85 fe movement marker,
// with special focus on the 0x3F suffix type that PR #105 (redraskal/r6-dissect) used
// but our current movement reader filters out.
//
// Run: go run ./tools/investigate3f <replay.rec>
//
// This tool answers:
//  1. Does 0x3F exist at all in the packet stream?
//  2. What type codes exist besides 0x01 and 0x03?
//  3. For 0x3F packets: do they contain valid world coordinates? Where?
//  4. For 0x3F packets: can we find player IDs (5-14) at any offset?
//  5. How does 0x3F volume compare to 0x01 and 0x03?
//  6. Do 0x3F positions correlate spatially with known 0x01/0x03 positions?
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// rawPacket stores every packet captured after the marker, regardless of type
type rawPacket struct {
	packetNum int
	typeFirst byte   // first type byte (prefix)
	typeSecond byte  // second type byte (suffix)
	rawBytes  []byte // up to 128 bytes after the type bytes
}

var (
	allPackets []rawPacket
	packetNum  int
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/investigate3f <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating reader: %v\n", err)
		os.Exit(1)
	}

	// Capture ALL packets after the movement marker - zero filtering
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureAll)
	r.Read()

	fmt.Printf("Total packets captured after 00 00 60 73 85 fe marker: %d\n\n", len(allPackets))

	// =========================================================================
	// SECTION 1: Overall type distribution
	// =========================================================================
	fmt.Println("=" + repeatStr("=", 70))
	fmt.Println("SECTION 1: Type Distribution (all suffix bytes)")
	fmt.Println("=" + repeatStr("=", 70))

	suffixCounts := make(map[byte]int)
	fullTypeCounts := make(map[uint16]int) // full 2-byte type code
	for _, p := range allPackets {
		suffixCounts[p.typeSecond]++
		code := uint16(p.typeFirst)<<8 | uint16(p.typeSecond)
		fullTypeCounts[code]++
	}

	// Sort suffix by count
	type kv struct {
		key   byte
		count int
	}
	var suffixes []kv
	for k, v := range suffixCounts {
		suffixes = append(suffixes, kv{k, v})
	}
	sort.Slice(suffixes, func(i, j int) bool { return suffixes[i].count > suffixes[j].count })

	fmt.Printf("\nBy suffix (second type byte):\n")
	for _, s := range suffixes {
		pct := float64(s.count) / float64(len(allPackets)) * 100
		marker := ""
		switch s.key {
		case 0x01:
			marker = " <-- currently captured (compact position)"
		case 0x03:
			marker = " <-- currently captured (full position + rotation)"
		case 0x3F:
			marker = " <-- PR #105 used this type (C0 3F)"
		}
		fmt.Printf("  0x%02X: %6d packets (%5.1f%%)%s\n", s.key, s.count, pct, marker)
	}

	// Full 2-byte type codes
	type kv16 struct {
		key   uint16
		count int
	}
	var fullTypes []kv16
	for k, v := range fullTypeCounts {
		fullTypes = append(fullTypes, kv16{k, v})
	}
	sort.Slice(fullTypes, func(i, j int) bool { return fullTypes[i].count > fullTypes[j].count })

	fmt.Printf("\nBy full type code (prefix+suffix):\n")
	for _, t := range fullTypes {
		if t.count < 10 {
			continue
		}
		pct := float64(t.count) / float64(len(allPackets)) * 100
		prefix := byte(t.key >> 8)
		suffix := byte(t.key & 0xFF)
		fmt.Printf("  0x%02X%02X: %6d packets (%5.1f%%)\n", prefix, suffix, t.count, pct)
	}

	// =========================================================================
	// SECTION 2: Deep dive into 0x3F packets
	// =========================================================================
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("SECTION 2: Deep Dive into 0x3F Suffix Packets")
	fmt.Println(repeatStr("=", 71))

	var packets3F []rawPacket
	for _, p := range allPackets {
		if p.typeSecond == 0x3F {
			packets3F = append(packets3F, p)
		}
	}

	if len(packets3F) == 0 {
		fmt.Println("\n  *** No 0x3F packets found in this replay. ***")
		fmt.Println("  This type may be season-specific or absent in this replay file.")
		printOtherTypes()
		printHeader(r)
		return
	}

	fmt.Printf("\nFound %d packets with suffix 0x3F\n", len(packets3F))

	// Check what prefix bytes appear with 0x3F
	prefixWith3F := make(map[byte]int)
	for _, p := range packets3F {
		prefixWith3F[p.typeFirst]++
	}
	fmt.Printf("\nPrefix bytes paired with 0x3F:\n")
	for prefix, count := range prefixWith3F {
		fmt.Printf("  0x%02X: %d (full code: 0x%02X3F)\n", prefix, count, prefix)
		if prefix == 0xC0 {
			fmt.Printf("    ^^^ This is the C0 3F type that PR #105 specifically captured\n")
		}
	}

	// =========================================================================
	// SECTION 3: Try to find coordinates in 0x3F packets
	// =========================================================================
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("SECTION 3: Coordinate Search in 0x3F Packets")
	fmt.Println(repeatStr("=", 71))

	// Try reading XYZ at every 4-byte aligned offset in the raw data
	// to see if there are world-valid coordinate triplets hiding anywhere
	type coordHit struct {
		offset    int
		x, y, z   float32
		hitCount  int
	}
	offsetHits := make(map[int]*coordHit)

	for _, p := range packets3F {
		for off := 0; off+12 <= len(p.rawBytes); off += 4 {
			x := readF32(p.rawBytes[off:])
			y := readF32(p.rawBytes[off+4:])
			z := readF32(p.rawBytes[off+8:])

			if isWorldCoord(x) && isWorldCoord(y) && z >= -10 && z <= 50 {
				if offsetHits[off] == nil {
					offsetHits[off] = &coordHit{offset: off}
				}
				offsetHits[off].hitCount++
				offsetHits[off].x = x
				offsetHits[off].y = y
				offsetHits[off].z = z
			}
		}
	}

	if len(offsetHits) == 0 {
		fmt.Println("\n  No valid world coordinate triplets found at any offset.")
		fmt.Println("  0x3F packets may not contain position data in the expected format.")
	} else {
		// Sort by hit count
		var hits []*coordHit
		for _, h := range offsetHits {
			hits = append(hits, h)
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].hitCount > hits[j].hitCount })

		fmt.Printf("\nOffsets where valid XYZ triplets were found (out of %d packets):\n", len(packets3F))
		for _, h := range hits {
			pct := float64(h.hitCount) / float64(len(packets3F)) * 100
			confidence := "LOW"
			if pct > 50 {
				confidence = "HIGH"
			} else if pct > 20 {
				confidence = "MEDIUM"
			}
			fmt.Printf("  Offset +%d: %d hits (%.1f%%) [%s] last=(%.2f, %.2f, %.2f)\n",
				h.offset, h.hitCount, pct, confidence, h.x, h.y, h.z)
		}

		// For the best offset, show coordinate spread
		if hits[0].hitCount > 10 {
			bestOff := hits[0].offset
			fmt.Printf("\nCoordinate spread at best offset (+%d):\n", bestOff)
			var xs, ys, zs []float32
			for _, p := range packets3F {
				if bestOff+12 <= len(p.rawBytes) {
					x := readF32(p.rawBytes[bestOff:])
					y := readF32(p.rawBytes[bestOff+4:])
					z := readF32(p.rawBytes[bestOff+8:])
					if isWorldCoord(x) && isWorldCoord(y) && z >= -10 && z <= 50 {
						xs = append(xs, x)
						ys = append(ys, y)
						zs = append(zs, z)
					}
				}
			}
			if len(xs) > 0 {
				fmt.Printf("  X: %.2f to %.2f (range: %.2f)\n", minSlice(xs), maxSlice(xs), maxSlice(xs)-minSlice(xs))
				fmt.Printf("  Y: %.2f to %.2f (range: %.2f)\n", minSlice(ys), maxSlice(ys), maxSlice(ys)-minSlice(ys))
				fmt.Printf("  Z: %.2f to %.2f (range: %.2f)\n", minSlice(zs), maxSlice(zs), maxSlice(zs)-minSlice(zs))

				// Check if positions look like player movement (spread + continuity)
				xRange := maxSlice(xs) - minSlice(xs)
				yRange := maxSlice(ys) - minSlice(ys)
				if xRange > 5 && yRange > 5 {
					fmt.Printf("  ==> Coordinate spread suggests REAL PLAYER MOVEMENT data!\n")
				} else if xRange < 1 && yRange < 1 {
					fmt.Printf("  ==> Coordinates are very clustered - may be a static object or origin point\n")
				}
			}
		}
	}

	// =========================================================================
	// SECTION 4: Player ID search in 0x3F packets
	// =========================================================================
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("SECTION 4: Player ID Search in 0x3F Packets")
	fmt.Println(repeatStr("=", 71))

	// Try to find player IDs (uint32 values 5-14) at every 4-byte offset
	type idHit struct {
		offset   int
		idCounts map[uint32]int
		total    int
	}
	idOffsets := make(map[int]*idHit)

	for _, p := range packets3F {
		for off := 0; off+4 <= len(p.rawBytes); off += 4 {
			id := binary.LittleEndian.Uint32(p.rawBytes[off : off+4])
			if id >= 5 && id <= 14 {
				if idOffsets[off] == nil {
					idOffsets[off] = &idHit{offset: off, idCounts: make(map[uint32]int)}
				}
				idOffsets[off].idCounts[id]++
				idOffsets[off].total++
			}
		}
	}

	if len(idOffsets) == 0 {
		fmt.Println("\n  No player IDs (5-14) found at any 4-byte aligned offset.")
		fmt.Println("  0x3F packets may use a different identification scheme.")
	} else {
		var idHits []*idHit
		for _, h := range idOffsets {
			idHits = append(idHits, h)
		}
		sort.Slice(idHits, func(i, j int) bool { return idHits[i].total > idHits[j].total })

		fmt.Printf("\nOffsets where player IDs (5-14) were found:\n")
		for _, h := range idHits {
			if h.total < 5 {
				continue
			}
			pct := float64(h.total) / float64(len(packets3F)) * 100
			uniqueIDs := len(h.idCounts)
			fmt.Printf("  Offset +%d: %d hits (%.1f%%), %d unique IDs\n", h.offset, h.total, pct, uniqueIDs)

			// Show distribution if it looks meaningful (multiple IDs, reasonable distribution)
			if uniqueIDs >= 3 && h.total > 20 {
				fmt.Printf("    ==> PROMISING! Distribution:\n")
				for id := uint32(5); id <= 14; id++ {
					if h.idCounts[id] > 0 {
						fmt.Printf("        Player %d: %d\n", id, h.idCounts[id])
					}
				}
			}
		}
	}

	// =========================================================================
	// SECTION 5: Raw hex dump of sample 0x3F packets
	// =========================================================================
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("SECTION 5: Raw Hex Dump of First 5 0x3F Packets")
	fmt.Println(repeatStr("=", 71))

	for i := 0; i < min(5, len(packets3F)); i++ {
		p := packets3F[i]
		fmt.Printf("\nPacket #%d (type: 0x%02X%02X, stream position: %d):\n",
			i, p.typeFirst, p.typeSecond, p.packetNum)

		// Print hex dump in 16-byte rows
		for row := 0; row < len(p.rawBytes); row += 16 {
			end := row + 16
			if end > len(p.rawBytes) {
				end = len(p.rawBytes)
			}
			fmt.Printf("  +%03d: %s", row, hex.EncodeToString(p.rawBytes[row:end]))

			// Annotate with float interpretations
			for off := row; off+4 <= end; off += 4 {
				v := readF32(p.rawBytes[off:])
				if !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0) && math.Abs(float64(v)) < 1000 {
					fmt.Printf("  [+%d=%.2f]", off, v)
				}
			}
			fmt.Println()
		}
	}

	// =========================================================================
	// SECTION 6: Spatial correlation with 0x01/0x03 positions
	// =========================================================================
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("SECTION 6: Spatial Correlation with Known 0x01/0x03 Positions")
	fmt.Println(repeatStr("=", 71))

	// Collect all known positions from 0x01 and 0x03
	type pos2D struct{ x, y float32 }
	knownPositions := make(map[pos2D]bool)

	for _, p := range allPackets {
		if (p.typeSecond == 0x01 || p.typeSecond == 0x03) && p.typeFirst >= 0xB0 {
			if len(p.rawBytes) >= 12 {
				x := readF32(p.rawBytes[0:])
				y := readF32(p.rawBytes[4:])
				if isWorldCoord(x) && isWorldCoord(y) {
					// Quantize to 1-unit grid for matching
					key := pos2D{float32(math.Round(float64(x))), float32(math.Round(float64(y)))}
					knownPositions[key] = true
				}
			}
		}
	}

	fmt.Printf("\nKnown positions from 0x01/0x03 packets: %d unique grid cells\n", len(knownPositions))

	// For the best coordinate offset in 0x3F, check how many positions overlap
	if len(offsetHits) > 0 {
		var bestHits []*coordHit
		for _, h := range offsetHits {
			bestHits = append(bestHits, h)
		}
		sort.Slice(bestHits, func(i, j int) bool { return bestHits[i].hitCount > bestHits[j].hitCount })

		for _, bestHit := range bestHits[:min(3, len(bestHits))] {
			overlap := 0
			total := 0
			for _, p := range packets3F {
				off := bestHit.offset
				if off+12 > len(p.rawBytes) {
					continue
				}
				x := readF32(p.rawBytes[off:])
				y := readF32(p.rawBytes[off+4:])
				if !isWorldCoord(x) || !isWorldCoord(y) {
					continue
				}
				total++
				key := pos2D{float32(math.Round(float64(x))), float32(math.Round(float64(y)))}
				if knownPositions[key] {
					overlap++
				}
			}
			if total > 0 {
				pct := float64(overlap) / float64(total) * 100
				fmt.Printf("\n  Offset +%d: %d/%d (%.1f%%) overlap with known positions\n",
					bestHit.offset, overlap, total, pct)
				if pct > 50 {
					fmt.Printf("  ==> HIGH CORRELATION - these are likely the same player positions!\n")
				} else if pct > 20 {
					fmt.Printf("  ==> MODERATE CORRELATION - may be related position data\n")
				} else {
					fmt.Printf("  ==> LOW CORRELATION - positions don't match 0x01/0x03 data\n")
				}
			}
		}
	}

	printOtherTypes()
	printHeader(r)
}

func printOtherTypes() {
	// =========================================================================
	// BONUS: Check ALL non-01/non-03 suffix types for hidden position data
	// =========================================================================
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("BONUS: Other Suffix Types with Potential Position Data")
	fmt.Println(repeatStr("=", 71))

	otherSuffixes := make(map[byte][]rawPacket)
	for _, p := range allPackets {
		if p.typeSecond != 0x01 && p.typeSecond != 0x03 {
			otherSuffixes[p.typeSecond] = append(otherSuffixes[p.typeSecond], p)
		}
	}

	for suffix, pkts := range otherSuffixes {
		if len(pkts) < 50 {
			continue
		}
		// Check if offset +0 has valid coordinates (same layout as 0x01/0x03)
		validAt0 := 0
		for _, p := range pkts {
			if len(p.rawBytes) >= 12 {
				x := readF32(p.rawBytes[0:])
				y := readF32(p.rawBytes[4:])
				z := readF32(p.rawBytes[8:])
				if isWorldCoord(x) && isWorldCoord(y) && z >= -10 && z <= 50 {
					validAt0++
				}
			}
		}
		if validAt0 > 0 {
			pct := float64(validAt0) / float64(len(pkts)) * 100
			fmt.Printf("  Suffix 0x%02X: %d packets, %d (%.1f%%) have valid coords at offset +0\n",
				suffix, len(pkts), validAt0, pct)
		}
	}
}

func printHeader(r *dissect.Reader) {
	fmt.Println("\n" + repeatStr("=", 71))
	fmt.Println("REPLAY INFO")
	fmt.Println(repeatStr("=", 71))
	fmt.Printf("  Season: %s (code: %d)\n", r.Header.GameVersion, r.Header.CodeVersion)
	fmt.Printf("  Map: %s\n", r.Header.Map.String())
	fmt.Printf("  Players:\n")
	for i, p := range r.Header.Players {
		fmt.Printf("    [%d] %s (Team %d) -> Expected Player ID %d\n", i, p.Username, p.TeamIndex, i+5)
	}
}

func captureAll(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	// Read up to 128 bytes of raw data after the type bytes
	raw, err := r.Bytes(128)
	if err != nil {
		// Try smaller read
		raw, err = r.Bytes(64)
		if err != nil {
			raw = []byte{}
		}
	}

	allPackets = append(allPackets, rawPacket{
		packetNum:  packetNum,
		typeFirst:  typeBytes[0],
		typeSecond: typeBytes[1],
		rawBytes:   raw,
	})

	return nil
}

func readF32(b []byte) float32 {
	if len(b) < 4 {
		return float32(math.NaN())
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(b))
}

func isWorldCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func minSlice(fs []float32) float32 {
	if len(fs) == 0 {
		return 0
	}
	m := fs[0]
	for _, f := range fs {
		if f < m {
			m = f
		}
	}
	return m
}

func maxSlice(fs []float32) float32 {
	if len(fs) == 0 {
		return 0
	}
	m := fs[0]
	for _, f := range fs {
		if f > m {
			m = f
		}
	}
	return m
}

func repeatStr(s string, n int) string {
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

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/redraskal/r6-dissect/dissect"
)

type PacketRecord struct {
	PacketNum int
	Type1     byte
	Type2     byte
	X, Y, Z   float32
	PostBytes []byte
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
	matchFeedback  []dissect.MatchUpdate
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: deepdive <replay.rec>")
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

	r.Listen(positionMarker, capturePacket)
	r.Read()

	matchFeedback = r.MatchFeedback

	fmt.Printf("Captured %d position packets\n", len(allPackets))
	fmt.Printf("Match feedback events: %d\n\n", len(matchFeedback))

	// Print match events for reference
	fmt.Println("=== MATCH EVENTS (from feedback) ===")
	for _, ev := range matchFeedback {
		fmt.Printf("  [%.1fs] %s: %s -> %s\n", ev.TimeInSeconds, ev.Type.String(), ev.Username, ev.Target)
	}

	// Analyze different packet types in detail
	fmt.Println("\n=== PACKET TYPE DEEP ANALYSIS ===")
	analyzeAllTypes()

	// Look for rotation/angle data in post-bytes
	fmt.Println("\n=== ROTATION/ANGLE ANALYSIS ===")
	analyzeRotationData()

	// Look for patterns that might indicate state changes
	fmt.Println("\n=== STATE CHANGE PATTERNS ===")
	analyzeStatePatterns()

	// Search for other markers in the data
	fmt.Println("\n=== OTHER MARKER SEARCH ===")
	searchForMarkers()
}

func capturePacket(r *dissect.Reader) error {
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	type1 := typeBytes[0]
	type2 := typeBytes[1]

	if type1 < 0xB0 {
		return nil
	}

	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	postBytes, _ := r.Bytes(64)

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		PostBytes: postBytes,
	})

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func analyzeAllTypes() {
	// Group by type
	typeGroups := make(map[uint16][]PacketRecord)
	for _, p := range allPackets {
		key := uint16(p.Type1)<<8 | uint16(p.Type2)
		typeGroups[key] = append(typeGroups[key], p)
	}

	// Sort by count
	type typeCount struct {
		key   uint16
		count int
	}
	var sorted []typeCount
	for k, v := range typeGroups {
		sorted = append(sorted, typeCount{k, len(v)})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	for _, tc := range sorted {
		type1 := byte(tc.key >> 8)
		type2 := byte(tc.key & 0xFF)
		packets := typeGroups[tc.key]

		fmt.Printf("\n--- Type 0x%02X 0x%02X (%d packets) ---\n", type1, type2, tc.count)

		if len(packets) < 10 {
			// Print all examples for rare types
			for _, p := range packets {
				fmt.Printf("  pos=(%.1f,%.1f,%.1f) post=%s\n", 
					p.X, p.Y, p.Z, hex.EncodeToString(p.PostBytes[:min(24, len(p.PostBytes))]))
			}
			continue
		}

		// Analyze float patterns in post-bytes
		analyzeFloatPatterns(packets, type1, type2)
	}
}

func analyzeFloatPatterns(packets []PacketRecord, type1, type2 byte) {
	// Check various offsets for float32 values that could be angles
	floatOffsets := []int{0, 4, 8, 12, 16, 20, 24, 28, 32}
	
	for _, offset := range floatOffsets {
		if offset+4 > len(packets[0].PostBytes) {
			break
		}

		var validFloats int
		var minVal, maxVal float32 = 999999, -999999
		var sumVal float64

		for _, p := range packets {
			if offset+4 <= len(p.PostBytes) {
				bits := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
				f := math.Float32frombits(bits)
				
				// Check if it looks like a valid angle or small float
				if !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) && f >= -10 && f <= 10 {
					validFloats++
					if f < minVal { minVal = f }
					if f > maxVal { maxVal = f }
					sumVal += float64(f)
				}
			}
		}

		pct := float64(validFloats) * 100 / float64(len(packets))
		if pct > 50 && maxVal-minVal > 0.1 { // Interesting if varies
			avg := sumVal / float64(validFloats)
			fmt.Printf("  Float@%d: %.1f%% valid, range [%.3f, %.3f], avg=%.3f\n", 
				offset, pct, minVal, maxVal, avg)
		}
	}

	// Check for byte patterns that might be flags
	for pos := 0; pos < min(40, len(packets[0].PostBytes)); pos++ {
		values := make(map[byte]int)
		for _, p := range packets {
			if pos < len(p.PostBytes) {
				values[p.PostBytes[pos]]++
			}
		}
		
		// Interesting if exactly 2-4 values (flags/states)
		if len(values) >= 2 && len(values) <= 4 {
			var desc strings.Builder
			for v, c := range values {
				pct := float64(c) * 100 / float64(len(packets))
				if pct >= 5 {
					desc.WriteString(fmt.Sprintf("0x%02X(%.0f%%) ", v, pct))
				}
			}
			if desc.Len() > 0 {
				fmt.Printf("  Byte@%d (potential flag): %s\n", pos, desc.String())
			}
		}
	}
}

func analyzeRotationData() {
	// Focus on type 0x01 packets which seem to have more data
	var type01 []PacketRecord
	for _, p := range allPackets {
		if p.Type2 == 0x01 {
			type01 = append(type01, p)
		}
	}

	if len(type01) == 0 {
		fmt.Println("No type 0x01 packets found")
		return
	}

	fmt.Printf("Analyzing %d type 0x01 packets for rotation data\n\n", len(type01))

	// Look for float32 values that could be angles (-pi to pi or 0 to 2pi)
	// Typical rotation values: yaw (0-360 or -180 to 180), pitch (-90 to 90)
	
	floatOffsets := []int{14, 18, 22, 26, 30, 34, 38}
	
	for _, offset := range floatOffsets {
		var angleCount int
		var minAngle, maxAngle float32 = 999, -999
		
		for _, p := range type01 {
			if offset+4 <= len(p.PostBytes) {
				bits := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
				f := math.Float32frombits(bits)
				
				// Check if could be normalized angle (-1 to 1 range like sine/cosine)
				if !math.IsNaN(float64(f)) && f >= -1.5 && f <= 1.5 {
					angleCount++
					if f < minAngle { minAngle = f }
					if f > maxAngle { maxAngle = f }
				}
			}
		}
		
		pct := float64(angleCount) * 100 / float64(len(type01))
		if pct > 80 {
			fmt.Printf("  Offset %d: %.1f%% in [-1.5, 1.5], range [%.4f, %.4f] - POSSIBLE ROTATION\n",
				offset, pct, minAngle, maxAngle)
		}
	}

	// Print example packets with potential rotation values
	fmt.Println("\nExample type 0x01 packets with float interpretation:")
	for i, p := range type01 {
		if i >= 5 {
			break
		}
		fmt.Printf("  pos=(%.1f, %.1f)\n", p.X, p.Y)
		
		// Print floats at various offsets
		for offset := 14; offset <= 38 && offset+4 <= len(p.PostBytes); offset += 4 {
			bits := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
			f := math.Float32frombits(bits)
			if !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) {
				fmt.Printf("    f@%d = %.4f", offset, f)
				if f >= -1 && f <= 1 {
					fmt.Printf(" (angle?)")
				}
			}
		}
		fmt.Println()
	}
}

func analyzeStatePatterns() {
	// Look for packets where state might change (byte values flip)
	
	// Track byte values over time for specific positions
	positions := []int{5, 7, 8, 21, 23}
	
	for _, pos := range positions {
		var changes int
		var lastVal byte = 0
		var firstSet bool
		
		for _, p := range allPackets {
			if pos < len(p.PostBytes) {
				if firstSet && p.PostBytes[pos] != lastVal {
					changes++
				}
				lastVal = p.PostBytes[pos]
				firstSet = true
			}
		}
		
		if changes > 10 && changes < len(allPackets)/2 {
			fmt.Printf("  Byte@%d changes %d times (%.1f%% of packets) - possible state indicator\n",
				pos, changes, float64(changes)*100/float64(len(allPackets)))
		}
	}

	// Look for patterns in type 0x08 packets (less common, might be events)
	var type08 []PacketRecord
	for _, p := range allPackets {
		if p.Type2 == 0x08 {
			type08 = append(type08, p)
		}
	}

	if len(type08) > 0 {
		fmt.Printf("\n=== TYPE 0x08 PACKETS (%d) - Possible Events ===\n", len(type08))
		for i, p := range type08 {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(type08)-10)
				break
			}
			fmt.Printf("  #%d pos=(%.1f,%.1f) post=%s\n", 
				p.PacketNum, p.X, p.Y, hex.EncodeToString(p.PostBytes[:min(32, len(p.PostBytes))]))
		}
	}

	// Look at type 0x02 packets
	var type02 []PacketRecord
	for _, p := range allPackets {
		if p.Type2 == 0x02 {
			type02 = append(type02, p)
		}
	}

	if len(type02) > 0 {
		fmt.Printf("\n=== TYPE 0x02 PACKETS (%d) ===\n", len(type02))
		
		// Analyze unique post-byte patterns
		patterns := make(map[string]int)
		for _, p := range type02 {
			if len(p.PostBytes) >= 8 {
				pattern := hex.EncodeToString(p.PostBytes[0:8])
				patterns[pattern]++
			}
		}
		
		fmt.Printf("Unique 8-byte prefix patterns: %d\n", len(patterns))
		
		// Show top patterns
		type patCount struct {
			pat   string
			count int
		}
		var sorted []patCount
		for p, c := range patterns {
			sorted = append(sorted, patCount{p, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		
		for i, pc := range sorted {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s: %d times\n", pc.pat, pc.count)
		}
	}
}

func searchForMarkers() {
	// Build raw data from all post-bytes
	var allData []byte
	for _, p := range allPackets {
		allData = append(allData, p.PostBytes...)
	}
	
	fmt.Printf("Searching in %d bytes of post-data...\n\n", len(allData))

	// Search for potential string markers
	stringMarkers := []string{
		"kill", "death", "plant", "defuse", "reinforce", 
		"gadget", "fire", "reload", "down", "revive",
	}
	
	for _, marker := range stringMarkers {
		count := 0
		markerBytes := []byte(marker)
		for i := 0; i <= len(allData)-len(markerBytes); i++ {
			match := true
			for j, b := range markerBytes {
				if allData[i+j] != b && allData[i+j] != b-32 { // case insensitive
					match = false
					break
				}
			}
			if match {
				count++
			}
		}
		if count > 0 {
			fmt.Printf("Found '%s': %d times\n", marker, count)
		}
	}

	// Search for repeating byte patterns that might be type identifiers
	fmt.Println("\nSearching for FE 85 73 pattern variations...")
	patternCounts := make(map[string]int)
	
	for _, p := range allPackets {
		for i := 0; i <= len(p.PostBytes)-4; i++ {
			// Look for patterns like XX XX 85 FE or similar
			if p.PostBytes[i+2] == 0x85 || p.PostBytes[i+2] == 0x73 {
				pattern := hex.EncodeToString(p.PostBytes[i : i+4])
				patternCounts[pattern]++
			}
		}
	}
	
	// Show patterns appearing 100+ times
	type patCount struct {
		pat   string
		count int
	}
	var sorted []patCount
	for p, c := range patternCounts {
		if c >= 100 {
			sorted = append(sorted, patCount{p, c})
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	
	fmt.Println("Patterns with 0x85 or 0x73 (100+ occurrences):")
	for i, pc := range sorted {
		if i >= 10 {
			break
		}
		fmt.Printf("  %s: %d times\n", pc.pat, pc.count)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

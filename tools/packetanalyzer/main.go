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

// Packet types we've seen
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
	packetCounter  int
	
	// Collect all markers we find
	markerCounts = make(map[string]int)
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: packetanalyzer <replay.rec>")
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

	// Register listener for position packets
	r.Listen(positionMarker, capturePositionPacket)
	
	// Read the file
	err = r.Read()
	if err != nil {
		fmt.Printf("Warning during read: %v\n", err)
	}

	fmt.Printf("\nCaptured %d position packets\n\n", len(allPackets))

	// Analyze packets by type
	analyzeByType()
	
	// Look for player ID patterns
	analyzePlayerIDs()
}

func capturePositionPacket(r *dissect.Reader) error {
	// Read type bytes
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	
	type1 := typeBytes[0]
	type2 := typeBytes[1]
	
	// Only process B0+ family
	if type1 < 0xB0 {
		return nil
	}

	// Read coordinates
	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	// Validate coordinates
	if !isValidCoord(x) || !isValidCoord(y) || !isValidCoord(z) {
		return nil
	}

	// Z should be reasonable floor height
	if z < -10 || z > 50 {
		return nil
	}

	// Read post-bytes (up to 64 bytes for analysis)
	postBytes, _ := r.Bytes(64)

	allPackets = append(allPackets, PacketRecord{
		PacketNum: packetCounter,
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		PostBytes: postBytes,
	})
	packetCounter++

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func analyzeByType() {
	// Group packets by type
	typeGroups := make(map[uint16][]PacketRecord)
	
	for _, p := range allPackets {
		key := uint16(p.Type1)<<8 | uint16(p.Type2)
		typeGroups[key] = append(typeGroups[key], p)
	}

	fmt.Println("=== PACKET TYPES ===")
	fmt.Printf("%-12s %-12s %-10s\n", "Type1", "Type2", "Count")
	fmt.Println("------------------------------------")

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
		fmt.Printf("0x%02X         0x%02X         %d\n", type1, type2, tc.count)
	}

	// Detailed analysis for top types
	fmt.Println("\n=== DETAILED ANALYSIS ===")
	for i, tc := range sorted {
		if i >= 3 { // Analyze top 3 types
			break
		}
		type1 := byte(tc.key >> 8)
		type2 := byte(tc.key & 0xFF)
		packets := typeGroups[tc.key]
		
		fmt.Printf("\n--- Type 0x%02X 0x%02X (%d packets) ---\n", type1, type2, tc.count)
		analyzePacketGroup(packets)
	}
}

func analyzePacketGroup(packets []PacketRecord) {
	if len(packets) == 0 {
		return
	}

	// Analyze byte positions in post-bytes
	fmt.Println("Post-bytes byte-by-byte analysis:")
	
	maxPos := 40
	if len(packets[0].PostBytes) < maxPos {
		maxPos = len(packets[0].PostBytes)
	}

	for pos := 0; pos < maxPos; pos++ {
		values := make(map[byte]int)
		for _, p := range packets {
			if pos < len(p.PostBytes) {
				values[p.PostBytes[pos]]++
			}
		}

		uniqueCount := len(values)
		
		// Report interesting positions
		if uniqueCount == 1 {
			for v := range values {
				fmt.Printf("  [%2d]: CONSTANT 0x%02X\n", pos, v)
			}
		} else if uniqueCount <= 15 && len(packets) > 50 {
			fmt.Printf("  [%2d]: %d unique: ", pos, uniqueCount)
			// Sort by frequency
			type valFreq struct {
				val  byte
				freq int
			}
			var vf []valFreq
			for v, c := range values {
				vf = append(vf, valFreq{v, c})
			}
			sort.Slice(vf, func(i, j int) bool {
				return vf[i].freq > vf[j].freq
			})
			for i, v := range vf {
				if i >= 8 {
					fmt.Printf("...")
					break
				}
				fmt.Printf("0x%02X(%d) ", v.val, v.freq)
			}
			fmt.Println()
		}
	}

	// Analyze uint32 fields
	fmt.Println("\nUint32 field analysis:")
	for offset := 0; offset <= 36; offset += 4 {
		if offset+4 > len(packets[0].PostBytes) {
			break
		}

		values := make(map[uint32]int)
		for _, p := range packets {
			if offset+4 <= len(p.PostBytes) {
				val := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
				values[val]++
			}
		}

		uniqueCount := len(values)
		
		// Interesting if 5-15 unique values (potential player IDs)
		if uniqueCount >= 5 && uniqueCount <= 20 {
			fmt.Printf("  [%2d-%2d] uint32: %d unique values", offset, offset+3, uniqueCount)
			
			// Check if values are around 5-14 (potential player IDs)
			smallCount := 0
			for v := range values {
				if v >= 1 && v <= 20 {
					smallCount++
				}
			}
			if smallCount == uniqueCount {
				fmt.Printf(" [LIKELY PLAYER ID - all values 1-20]")
			}
			fmt.Println()
			
			// Print value distribution
			type valFreq struct {
				val  uint32
				freq int
			}
			var vf []valFreq
			for v, c := range values {
				vf = append(vf, valFreq{v, c})
			}
			sort.Slice(vf, func(i, j int) bool {
				return vf[i].freq > vf[j].freq
			})
			for i, v := range vf {
				if i >= 12 {
					fmt.Printf("      ... and %d more values\n", len(vf)-12)
					break
				}
				fmt.Printf("      %d: %d times (%.1f%%)\n", v.val, v.freq, float64(v.freq)*100/float64(len(packets)))
			}
		}
	}

	// Print example packets
	fmt.Println("\nExample packets:")
	for i, p := range packets {
		if i >= 5 {
			break
		}
		fmt.Printf("  #%5d: pos=(%.2f, %.2f, %.2f)\n", p.PacketNum, p.X, p.Y, p.Z)
		postHex := hex.EncodeToString(p.PostBytes[:min(32, len(p.PostBytes))])
		fmt.Printf("          post: %s\n", postHex)
	}
}

func analyzePlayerIDs() {
	fmt.Println("\n=== PLAYER ID CORRELATION ANALYSIS ===")
	
	// For packets with type2 = 0x01 and 0x03, check if ID at different offsets
	// correlates with position clusters
	
	type01Packets := make([]PacketRecord, 0)
	type03Packets := make([]PacketRecord, 0)
	
	for _, p := range allPackets {
		if p.Type2 == 0x01 {
			type01Packets = append(type01Packets, p)
		} else if p.Type2 == 0x03 {
			type03Packets = append(type03Packets, p)
		}
	}

	fmt.Printf("\nType 0x01 packets: %d\n", len(type01Packets))
	fmt.Printf("Type 0x03 packets: %d\n", len(type03Packets))

	// For type 0x01, check offset 4-7 (bytes 4,5,6,7 after coords)
	if len(type01Packets) > 100 {
		fmt.Println("\nType 0x01 - ID candidate at offset 4-7:")
		analyzeIDAtOffset(type01Packets, 4)
	}

	// For type 0x03, check offset 20-23
	if len(type03Packets) > 100 {
		fmt.Println("\nType 0x03 - ID candidate at offset 20-23:")
		analyzeIDAtOffset(type03Packets, 20)
	}

	// Check if there's a consistent ID across all packet types
	fmt.Println("\n=== CROSS-TYPE ID ANALYSIS ===")
	checkCrossTypeIDs()
}

func analyzeIDAtOffset(packets []PacketRecord, offset int) {
	// Group packets by the uint32 at this offset
	idGroups := make(map[uint32][]PacketRecord)
	
	for _, p := range packets {
		if offset+4 <= len(p.PostBytes) {
			id := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
			idGroups[id] = append(idGroups[id], p)
		}
	}

	fmt.Printf("  Found %d unique IDs\n", len(idGroups))
	
	// For each ID, calculate position statistics
	type idStats struct {
		id       uint32
		count    int
		avgX     float64
		avgY     float64
		avgZ     float64
		stdDevXY float64
	}
	
	var stats []idStats
	for id, group := range idGroups {
		if len(group) < 10 {
			continue
		}
		
		// Calculate average position
		var sumX, sumY, sumZ float64
		for _, p := range group {
			sumX += float64(p.X)
			sumY += float64(p.Y)
			sumZ += float64(p.Z)
		}
		avgX := sumX / float64(len(group))
		avgY := sumY / float64(len(group))
		avgZ := sumZ / float64(len(group))
		
		// Calculate standard deviation
		var sumSqDiff float64
		for _, p := range group {
			dx := float64(p.X) - avgX
			dy := float64(p.Y) - avgY
			sumSqDiff += dx*dx + dy*dy
		}
		stdDev := math.Sqrt(sumSqDiff / float64(len(group)))
		
		stats = append(stats, idStats{
			id:       id,
			count:    len(group),
			avgX:     avgX,
			avgY:     avgY,
			avgZ:     avgZ,
			stdDevXY: stdDev,
		})
	}

	// Sort by count
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].count > stats[j].count
	})

	// Print stats
	fmt.Printf("  %-10s %-8s %-10s %-10s %-10s %-10s\n", "ID", "Count", "AvgX", "AvgY", "AvgZ", "StdDevXY")
	for i, s := range stats {
		if i >= 15 {
			break
		}
		fmt.Printf("  %-10d %-8d %-10.2f %-10.2f %-10.2f %-10.2f\n",
			s.id, s.count, s.avgX, s.avgY, s.avgZ, s.stdDevXY)
	}
	
	// If there are ~10 IDs with similar counts and low std dev, likely player IDs
	if len(stats) >= 8 && len(stats) <= 15 {
		lowStdDevCount := 0
		for _, s := range stats[:min(10, len(stats))] {
			if s.stdDevXY < 50 { // Reasonable movement range
				lowStdDevCount++
			}
		}
		if lowStdDevCount >= 8 {
			fmt.Println("\n  *** HIGH CONFIDENCE: These look like player IDs! ***")
		}
	}
}

func checkCrossTypeIDs() {
	// Check multiple offsets across all packets to find consistent player ID field
	offsets := []int{0, 4, 8, 12, 16, 20, 24, 28, 32}
	
	for _, offset := range offsets {
		idCounts := make(map[uint32]int)
		validPackets := 0
		
		for _, p := range allPackets {
			if offset+4 <= len(p.PostBytes) {
				id := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
				// Only count small IDs (likely player IDs are 1-20 or small numbers)
				if id >= 1 && id <= 100 {
					idCounts[id]++
					validPackets++
				}
			}
		}

		// Check if this offset has ~10 dominant IDs
		if len(idCounts) >= 8 && len(idCounts) <= 20 {
			// Check distribution
			total := 0
			for _, c := range idCounts {
				total += c
			}
			
			if total > len(allPackets)/2 {
				fmt.Printf("Offset [%d-%d]: %d small IDs found, %d total occurrences\n", 
					offset, offset+3, len(idCounts), total)
				
				// Print distribution
				type idFreq struct {
					id   uint32
					freq int
				}
				var sorted []idFreq
				for id, c := range idCounts {
					sorted = append(sorted, idFreq{id, c})
				}
				sort.Slice(sorted, func(i, j int) bool {
					return sorted[i].freq > sorted[j].freq
				})
				
				for i, v := range sorted {
					if i >= 12 {
						break
					}
					fmt.Printf("  ID %2d: %5d packets (%.1f%%)\n", v.id, v.freq, float64(v.freq)*100/float64(validPackets))
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

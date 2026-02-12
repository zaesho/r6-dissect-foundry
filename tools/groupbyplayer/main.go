package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
)

func main() {
	// Analyze all three maps
	files := []struct {
		path string
		name string
	}{
		{"samplefiles/R01_dump.bin", "Chalet"},
		{"samplefiles/nighthaven_R01_dump.bin", "Nighthaven"},
		{"samplefiles/border_R01_dump.bin", "Border"},
	}

	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		fmt.Printf("\n=== %s ===\n", f.name)
		analyzeByPlayer(data)
	}
}

func analyzeByPlayer(data []byte) {
	// Pattern: 83 00 00 00 62 73 85 fe [seq] 5e...
	// But let's look at what comes BEFORE the 83
	// Full pattern in context might be: [player?] 83 00 00 00 62 73 85 fe [seq] 5e...

	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}
	suffix := []byte{0x5e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	type packet struct {
		offset    int
		seq       uint32
		x, y, z   float32
		preMarker []byte // Bytes before the 83
	}

	var packets []packet

	for i := 32; i <= len(data)-44; i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}

		suffixOff := i + 8 + 4
		for j, b := range suffix {
			if data[suffixOff+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}

		seq := binary.LittleEndian.Uint32(data[i+8:])
		floatOff := i + 20
		x := readFloat(data[floatOff:])
		y := readFloat(data[floatOff+4:])
		z := readFloat(data[floatOff+8:])

		if isValidCoord(x) && isValidCoord(y) && isValidCoord(z) {
			pre := make([]byte, 32)
			copy(pre, data[i-32:i])
			packets = append(packets, packet{i, seq, x, y, z, pre})
		}
	}

	fmt.Printf("Found %d packets\n", len(packets))

	// Group by bytes at offset -4 from marker (4 bytes before 83)
	// And also try other offsets
	
	offsets := []int{4, 8, 12, 16, 20, 24, 28}
	
	for _, off := range offsets {
		groups := make(map[string][]packet)
		for _, p := range packets {
			key := hex.EncodeToString(p.preMarker[32-off : 32-off+4])
			groups[key] = append(groups[key], p)
		}
		
		if len(groups) >= 2 && len(groups) <= 20 {
			fmt.Printf("\n--- Grouping by 4 bytes at offset -%d ---\n", off)
			fmt.Printf("Found %d groups\n", len(groups))
			
			// Sort by count
			type groupInfo struct {
				key   string
				pkts  []packet
			}
			var sorted []groupInfo
			for k, v := range groups {
				sorted = append(sorted, groupInfo{k, v})
			}
			sort.Slice(sorted, func(i, j int) bool {
				return len(sorted[i].pkts) > len(sorted[j].pkts)
			})
			
			for _, g := range sorted {
				// Calculate coordinate ranges
				var xs, ys, zs []float32
				minSeq, maxSeq := g.pkts[0].seq, g.pkts[0].seq
				for _, p := range g.pkts {
					xs = append(xs, p.x)
					ys = append(ys, p.y)
					zs = append(zs, p.z)
					if p.seq < minSeq { minSeq = p.seq }
					if p.seq > maxSeq { maxSeq = p.seq }
				}
				
				fmt.Printf("\n  Group '%s': %d positions\n", g.key, len(g.pkts))
				fmt.Printf("    X: %.1f to %.1f, Y: %.1f to %.1f, Z: %.1f to %.1f\n",
					minF(xs), maxF(xs), minF(ys), maxF(ys), minF(zs), maxF(zs))
				fmt.Printf("    Seq: 0x%08X to 0x%08X (span: %d)\n", minSeq, maxSeq, maxSeq-minSeq)
			}
		}
	}
	
	// Also check if there's a pattern in how positions alternate
	fmt.Println("\n--- Analyzing position clustering ---")
	
	// Sort by sequence
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].seq < packets[j].seq
	})
	
	// Check for clusters of similar positions (same player standing still)
	clusters := 0
	for i := 1; i < len(packets); i++ {
		dx := packets[i].x - packets[i-1].x
		dy := packets[i].y - packets[i-1].y
		dz := packets[i].z - packets[i-1].z
		dist := math.Sqrt(float64(dx*dx + dy*dy + dz*dz))
		
		if dist < 0.5 { // Very close positions
			clusters++
		}
	}
	fmt.Printf("Adjacent positions within 0.5 units: %d (%.1f%%)\n", 
		clusters, float64(clusters)/float64(len(packets))*100)
	
	// Check position variance
	seqRange := packets[len(packets)-1].seq - packets[0].seq
	fmt.Printf("Sequence range: %d ticks\n", seqRange)
	fmt.Printf("Average positions per 1000 ticks: %.1f\n", float64(len(packets))*1000/float64(seqRange))
}

func readFloat(data []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(data))
}

func isValidCoord(f float32) bool {
	if f != f {
		return false
	}
	if math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -200 && f <= 200
}

func minF(fs []float32) float32 {
	m := fs[0]
	for _, f := range fs {
		if f < m {
			m = f
		}
	}
	return m
}

func maxF(fs []float32) float32 {
	m := fs[0]
	for _, f := range fs {
		if f > m {
			m = f
		}
	}
	return m
}

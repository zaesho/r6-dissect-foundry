package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

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
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: packetsurvey <replay.rec>")
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

	fmt.Printf("Captured %d position packets total\n\n", len(allPackets))

	// Count by type combination
	typeCounts := make(map[string]int)
	typeExamples := make(map[string][]PacketRecord)
	
	for _, p := range allPackets {
		key := fmt.Sprintf("%02X%02X", p.Type1, p.Type2)
		typeCounts[key]++
		if len(typeExamples[key]) < 5 {
			typeExamples[key] = append(typeExamples[key], p)
		}
	}

	// Sort by count
	type typeCount struct {
		key   string
		count int
	}
	var sorted []typeCount
	for k, v := range typeCounts {
		sorted = append(sorted, typeCount{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	fmt.Println("=== PACKET TYPE DISTRIBUTION ===")
	fmt.Printf("%-10s %-10s\n", "Type", "Count")
	fmt.Println("---------------------")
	for _, tc := range sorted {
		fmt.Printf("%-10s %-10d\n", tc.key, tc.count)
	}

	// For each type, analyze the data structure
	fmt.Println("\n\n=== DETAILED TYPE ANALYSIS ===")
	
	for _, tc := range sorted[:min(5, len(sorted))] {
		fmt.Printf("\n--- Type %s (%d packets) ---\n", tc.key, tc.count)
		
		examples := typeExamples[tc.key]
		if len(examples) == 0 {
			continue
		}
		
		// Analyze byte patterns at each offset
		fmt.Println("Sample positions:")
		for i, p := range examples[:min(3, len(examples))] {
			fmt.Printf("  %d: (%.1f, %.1f, %.1f)\n", i, p.X, p.Y, p.Z)
		}
		
		// Check which offsets contain float-like values
		fmt.Println("\nFloat values at various offsets (averaged across samples):")
		for offset := 0; offset < 40; offset += 4 {
			var values []float64
			allValid := true
			
			for _, p := range examples {
				if offset+4 <= len(p.PostBytes) {
					v := readFloat32(p.PostBytes[offset : offset+4])
					if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) || math.Abs(float64(v)) > 1e10 {
						allValid = false
						break
					}
					values = append(values, float64(v))
				}
			}
			
			if allValid && len(values) > 0 {
				minV, maxV, sumV := values[0], values[0], 0.0
				for _, v := range values {
					if v < minV { minV = v }
					if v > maxV { maxV = v }
					sumV += v
				}
				avgV := sumV / float64(len(values))
				rangeV := maxV - minV
				
				// Only show if there's meaningful variation or the values are in quaternion range
				if rangeV > 0.001 || (math.Abs(avgV) < 2 && math.Abs(avgV) > 0.001) {
					fmt.Printf("  off%02d: min=%.4f, max=%.4f, avg=%.4f, range=%.4f\n",
						offset, minV, maxV, avgV, rangeV)
				}
			}
		}
		
		// Look for quaternion-like patterns (4 consecutive floats that form unit quaternion)
		fmt.Println("\nChecking for quaternion patterns:")
		for startOff := 0; startOff+16 <= 40; startOff += 4 {
			unitCount := 0
			for _, p := range examples {
				if startOff+16 <= len(p.PostBytes) {
					q0 := float64(readFloat32(p.PostBytes[startOff:startOff+4]))
					q1 := float64(readFloat32(p.PostBytes[startOff+4:startOff+8]))
					q2 := float64(readFloat32(p.PostBytes[startOff+8:startOff+12]))
					q3 := float64(readFloat32(p.PostBytes[startOff+12:startOff+16]))
					
					mag := q0*q0 + q1*q1 + q2*q2 + q3*q3
					if math.Abs(mag-1.0) < 0.1 {
						unitCount++
					}
				}
			}
			
			if unitCount > 0 {
				pct := float64(unitCount) * 100.0 / float64(len(examples))
				fmt.Printf("  Quaternion at off%02d-%02d: %.0f%% unit quaternions\n",
					startOff, startOff+16, pct)
			}
		}
	}
	
	// Special analysis: look at ALL different packet types and see if any
	// have rotation-like data that isn't quaternion
	fmt.Println("\n\n=== SEARCHING FOR EULER ANGLE PATTERNS ===")
	fmt.Println("Looking for direct angle values (degrees or radians)")
	
	for _, tc := range sorted[:min(8, len(sorted))] {
		examples := typeExamples[tc.key]
		if len(examples) < 3 {
			continue
		}
		
		// Check for values in degree range (-360 to 360) or radian range (-2π to 2π)
		fmt.Printf("\nType %s:\n", tc.key)
		
		for offset := 0; offset < 40; offset += 4 {
			degreeCount := 0
			radianCount := 0
			
			for _, p := range examples {
				if offset+4 <= len(p.PostBytes) {
					v := float64(readFloat32(p.PostBytes[offset : offset+4]))
					
					// Check if value looks like degrees
					if !math.IsNaN(v) && !math.IsInf(v, 0) {
						if math.Abs(v) > 0.1 && math.Abs(v) < 360 {
							degreeCount++
						}
						// Check if value looks like radians
						if math.Abs(v) > 0.01 && math.Abs(v) < 6.3 {
							radianCount++
						}
					}
				}
			}
			
			total := len(examples)
			if degreeCount == total && radianCount < total {
				v := readFloat32(examples[0].PostBytes[offset:offset+4])
				fmt.Printf("  off%02d: Looks like degrees (sample: %.2f°)\n", offset, v)
			} else if radianCount == total && degreeCount < total {
				v := readFloat32(examples[0].PostBytes[offset:offset+4])
				fmt.Printf("  off%02d: Looks like radians (sample: %.4f = %.2f°)\n", 
					offset, v, v*180/math.Pi)
			}
		}
	}
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

func readFloat32(b []byte) float32 {
	if len(b) < 4 {
		return 0
	}
	bits := binary.LittleEndian.Uint32(b)
	return math.Float32frombits(bits)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

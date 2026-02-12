package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

type PacketRecord struct {
	PacketNum int
	Type1     byte
	Type2     byte
	X, Y, Z   float32
	RawPost   []byte // Everything after X,Y,Z coords
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: deeppacket <replay.rec>")
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

	fmt.Printf("Captured %d type 0x03 packets\n\n", len(allPackets))

	// ============================================
	// TEST 1: Raw hex dump of first 10 packets
	// ============================================
	fmt.Println("=== RAW HEX DUMP (first 10 type 0x03 packets) ===")
	for i := 0; i < min(10, len(allPackets)); i++ {
		p := allPackets[i]
		fmt.Printf("Pkt %d: pos=(%.2f, %.2f, %.2f)\n", i, p.X, p.Y, p.Z)
		fmt.Printf("  Raw post-coord bytes (%d bytes):\n", len(p.RawPost))
		for off := 0; off < min(64, len(p.RawPost)); off += 16 {
			end := min(off+16, len(p.RawPost))
			fmt.Printf("    +%02d: %s\n", off, hex.EncodeToString(p.RawPost[off:end]))
		}
		fmt.Println()
	}

	// ============================================
	// TEST 2: Find ALL possible unit quaternions at ANY offset
	// ============================================
	fmt.Println("\n=== SEARCHING FOR UNIT QUATERNIONS AT ALL OFFSETS ===")
	for startOff := 0; startOff+16 <= 64; startOff++ {
		unitCount := 0
		totalChecked := 0
		
		for _, p := range allPackets[:min(1000, len(allPackets))] {
			if startOff+16 <= len(p.RawPost) {
				totalChecked++
				q0 := float64(readFloat32(p.RawPost[startOff : startOff+4]))
				q1 := float64(readFloat32(p.RawPost[startOff+4 : startOff+8]))
				q2 := float64(readFloat32(p.RawPost[startOff+8 : startOff+12]))
				q3 := float64(readFloat32(p.RawPost[startOff+12 : startOff+16]))

				mag := q0*q0 + q1*q1 + q2*q2 + q3*q3
				if mag > 0.9 && mag < 1.1 {
					unitCount++
				}
			}
		}

		if totalChecked > 0 {
			pct := float64(unitCount) * 100 / float64(totalChecked)
			if pct > 50 {
				fmt.Printf("  Offset %02d-%02d: %.1f%% unit quaternions (%d/%d)\n",
					startOff, startOff+16, pct, unitCount, totalChecked)
			}
		}
	}

	// ============================================
	// TEST 3: Look for direct angle values (degrees -360 to 360, or radians -2π to 2π)
	// ============================================
	fmt.Println("\n=== SEARCHING FOR DIRECT ANGLE VALUES AT ALL OFFSETS ===")
	for off := 0; off+4 <= 64; off += 2 { // Check every 2 bytes
		degreeCount := 0
		radianCount := 0
		totalChecked := 0
		var sampleValues []float32

		for _, p := range allPackets[:min(1000, len(allPackets))] {
			if off+4 <= len(p.RawPost) {
				totalChecked++
				v := readFloat32(p.RawPost[off : off+4])

				if !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0) {
					// Check if it looks like degrees
					if math.Abs(float64(v)) >= 1 && math.Abs(float64(v)) <= 360 {
						degreeCount++
					}
					// Check if it looks like radians
					if math.Abs(float64(v)) >= 0.01 && math.Abs(float64(v)) <= 6.3 {
						radianCount++
					}
					if len(sampleValues) < 20 {
						sampleValues = append(sampleValues, v)
					}
				}
			}
		}

		if totalChecked > 0 {
			degPct := float64(degreeCount) * 100 / float64(totalChecked)
			radPct := float64(radianCount) * 100 / float64(totalChecked)
			
			if degPct > 80 || radPct > 80 {
				fmt.Printf("  Offset %02d: deg=%.0f%%, rad=%.0f%%\n", off, degPct, radPct)
				fmt.Printf("    Samples: ")
				for i, v := range sampleValues[:min(8, len(sampleValues))] {
					if i > 0 {
						fmt.Print(", ")
					}
					fmt.Printf("%.2f", v)
				}
				fmt.Println()
			}
		}
	}

	// ============================================
	// TEST 4: Check int16 scaled angles (common in games)
	// ============================================
	fmt.Println("\n=== SEARCHING FOR INT16 SCALED ANGLES ===")
	for off := 0; off+2 <= 64; off += 2 {
		validCount := 0
		totalChecked := 0
		var sampleAngles []float64

		for _, p := range allPackets[:min(1000, len(allPackets))] {
			if off+2 <= len(p.RawPost) {
				totalChecked++
				i16 := int16(binary.LittleEndian.Uint16(p.RawPost[off : off+2]))
				// Common scaling: 32767 = 180° or 65535 = 360°
				angle1 := float64(i16) * 180.0 / 32767.0
				
				if math.Abs(angle1) <= 180 {
					validCount++
					if len(sampleAngles) < 20 {
						sampleAngles = append(sampleAngles, angle1)
					}
				}
			}
		}

		if totalChecked > 0 && validCount == totalChecked {
			// Check if there's meaningful variation
			if len(sampleAngles) > 5 {
				minA, maxA := sampleAngles[0], sampleAngles[0]
				for _, a := range sampleAngles {
					if a < minA { minA = a }
					if a > maxA { maxA = a }
				}
				rangeA := maxA - minA
				
				if rangeA > 10 && rangeA < 360 { // Has variation but not too crazy
					fmt.Printf("  Offset %02d: range=%.1f° (min=%.1f°, max=%.1f°)\n", off, rangeA, minA, maxA)
				}
			}
		}
	}

	// ============================================
	// TEST 5: Build a track and check if ANY field correlates with movement direction
	// ============================================
	fmt.Println("\n=== CORRELATION TEST: FIND FIELDS THAT MATCH MOVEMENT DIRECTION ===")
	
	// Build simple track from first 500 packets (players moving from spawn)
	type trackPt struct {
		p     PacketRecord
		moveDir float64 // Direction of movement from this point
	}
	var track []trackPt
	var lastX, lastY float32
	threshold := float32(1.5)
	
	for _, p := range allPackets {
		if len(track) == 0 {
			lastX, lastY = p.X, p.Y
			track = append(track, trackPt{p: p})
			continue
		}
		
		dx := p.X - lastX
		dy := p.Y - lastY
		dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
		
		if dist <= threshold && dist > 0.1 {
			moveDir := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
			track = append(track, trackPt{p: p, moveDir: moveDir})
			lastX, lastY = p.X, p.Y
			
			if len(track) >= 200 {
				break
			}
		}
	}

	fmt.Printf("Built track with %d moving points\n", len(track))

	// For each possible float32 offset, check correlation with movement direction
	fmt.Println("\nChecking float32 offsets for correlation with movement direction:")
	for off := 0; off+4 <= 40; off += 4 {
		var diffs []float64
		for _, pt := range track[1:] {
			if off+4 <= len(pt.p.RawPost) {
				fieldVal := float64(readFloat32(pt.p.RawPost[off : off+4]))
				
				// Try interpreting as angle directly
				diff := pt.moveDir - fieldVal
				for diff > 180 { diff -= 360 }
				for diff < -180 { diff += 360 }
				diffs = append(diffs, math.Abs(diff))
			}
		}
		
		if len(diffs) > 10 {
			// Calculate average difference
			sum := 0.0
			for _, d := range diffs {
				sum += d
			}
			avg := sum / float64(len(diffs))
			
			// Calculate how many are within 45° of average
			nearAvg := 0
			for _, d := range diffs {
				if math.Abs(d-avg) < 45 || math.Abs(d-(360-avg)) < 45 {
					nearAvg++
				}
			}
			consistency := float64(nearAvg) * 100 / float64(len(diffs))
			
			if consistency > 40 {
				fmt.Printf("  Offset %02d: avg diff = %.1f°, consistency = %.0f%%\n", off, avg, consistency)
			}
		}
	}

	// Try quaternion-derived yaw at different offsets
	fmt.Println("\nChecking quaternion-derived yaw at different offsets:")
	for qStart := 0; qStart+16 <= 40; qStart += 4 {
		var diffs []float64
		for _, pt := range track[1:] {
			if qStart+16 <= len(pt.p.RawPost) {
				qx := float64(readFloat32(pt.p.RawPost[qStart : qStart+4]))
				qy := float64(readFloat32(pt.p.RawPost[qStart+4 : qStart+8]))
				qz := float64(readFloat32(pt.p.RawPost[qStart+8 : qStart+12]))
				qw := float64(readFloat32(pt.p.RawPost[qStart+12 : qStart+16]))
				
				mag := qx*qx + qy*qy + qz*qz + qw*qw
				if mag < 0.9 || mag > 1.1 {
					continue
				}
				
				// Try different yaw extraction methods
				yaw1 := math.Atan2(2*(qw*qz+qx*qy), 1-2*(qy*qy+qz*qz)) * 180 / math.Pi
				
				diff := pt.moveDir - yaw1
				for diff > 180 { diff -= 360 }
				for diff < -180 { diff += 360 }
				diffs = append(diffs, diff)
			}
		}
		
		if len(diffs) > 10 {
			// Find median offset
			sorted := make([]float64, len(diffs))
			copy(sorted, diffs)
			for i := 0; i < len(sorted); i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[i] > sorted[j] {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			median := sorted[len(sorted)/2]
			
			// Check consistency
			nearMedian := 0
			for _, d := range diffs {
				diff := math.Abs(d - median)
				if diff > 180 { diff = 360 - diff }
				if diff < 45 {
					nearMedian++
				}
			}
			consistency := float64(nearMedian) * 100 / float64(len(diffs))
			
			fmt.Printf("  Quat at offset %02d-%02d: median offset = %.1f°, consistency = %.0f%%\n",
				qStart, qStart+16, median, consistency)
		}
	}

	// ============================================
	// TEST 6: Look for patterns in byte 0-3 (the mystery zeros)
	// ============================================
	fmt.Println("\n=== ANALYZING MYSTERY BYTES 0-3 ===")
	patterns := make(map[string]int)
	for _, p := range allPackets[:min(1000, len(allPackets))] {
		if len(p.RawPost) >= 4 {
			key := hex.EncodeToString(p.RawPost[0:4])
			patterns[key]++
		}
	}
	fmt.Printf("Found %d unique patterns in bytes 0-3\n", len(patterns))
	for k, v := range patterns {
		if v > 100 {
			fmt.Printf("  %s: %d packets\n", k, v)
		}
	}

	// ============================================  
	// TEST 7: Check if we're reading the quaternion BACKWARDS (WXYZ vs XYZW)
	// ============================================
	fmt.Println("\n=== TESTING QUATERNION COMPONENT ORDER ===")
	orders := []struct {
		name string
		w, x, y, z int // Offsets within the 16-byte block
	}{
		{"XYZW", 0, 4, 8, 12},
		{"WXYZ", 12, 0, 4, 8},
		{"YZWX", 8, 12, 0, 4},
		{"ZWXY", 4, 8, 12, 0},
	}
	
	qStart := 4 // Try offset 4 which showed unit quaternions
	for _, order := range orders {
		var diffs []float64
		for _, pt := range track[1:min(100, len(track))] {
			if qStart+16 <= len(pt.p.RawPost) {
				qx := float64(readFloat32(pt.p.RawPost[qStart+order.x : qStart+order.x+4]))
				qy := float64(readFloat32(pt.p.RawPost[qStart+order.y : qStart+order.y+4]))
				qz := float64(readFloat32(pt.p.RawPost[qStart+order.z : qStart+order.z+4]))
				qw := float64(readFloat32(pt.p.RawPost[qStart+order.w : qStart+order.w+4]))
				
				yaw := math.Atan2(2*(qw*qz+qx*qy), 1-2*(qy*qy+qz*qz)) * 180 / math.Pi
				
				diff := pt.moveDir - yaw
				for diff > 180 { diff -= 360 }
				for diff < -180 { diff += 360 }
				diffs = append(diffs, diff)
			}
		}
		
		if len(diffs) > 5 {
			sorted := make([]float64, len(diffs))
			copy(sorted, diffs)
			for i := range sorted {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[i] > sorted[j] {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			median := sorted[len(sorted)/2]
			fmt.Printf("  Order %s: median offset = %.1f°\n", order.name, median)
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

	if type1 < 0xB0 || type2 != 0x03 {
		return nil
	}

	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	rawPost, _ := r.Bytes(80) // Read extra bytes

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		RawPost:   rawPost,
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

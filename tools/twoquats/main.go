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
	X, Y, Z     float32
	Quat1       [4]float32 // Quaternion at offset 4-20 (bytes 4,8,12,16)
	Quat2       [4]float32 // Quaternion at offset 46-62
	Yaw1, Yaw2  float32
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: twoquats <replay.rec>")
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

	// Show first 20 packets comparing both quaternions
	fmt.Println("=== COMPARING TWO QUATERNIONS IN EACH PACKET ===")
	fmt.Println("Quat1 at offset 4-20 (currently used)")
	fmt.Println("Quat2 at offset 46-62 (new discovery)")
	fmt.Println()
	
	for i := 0; i < min(20, len(allPackets)); i++ {
		p := allPackets[i]
		fmt.Printf("Pkt %2d: pos=(%.1f, %.1f)\n", i, p.X, p.Y)
		fmt.Printf("  Quat1: [%.3f, %.3f, %.3f, %.3f] → Yaw1=%.1f°\n",
			p.Quat1[0], p.Quat1[1], p.Quat1[2], p.Quat1[3], p.Yaw1)
		fmt.Printf("  Quat2: [%.3f, %.3f, %.3f, %.3f] → Yaw2=%.1f°\n",
			p.Quat2[0], p.Quat2[1], p.Quat2[2], p.Quat2[3], p.Yaw2)
		fmt.Printf("  Yaw difference: %.1f°\n", p.Yaw2-p.Yaw1)
		fmt.Println()
	}

	// Build tracks and compare which quaternion correlates better with movement
	fmt.Println("\n=== TESTING WHICH QUATERNION MATCHES MOVEMENT DIRECTION ===")
	
	tracks := buildTracks(allPackets, 1.5)
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i]) > len(tracks[j])
	})

	for trackIdx := 0; trackIdx < min(5, len(tracks)); trackIdx++ {
		track := tracks[trackIdx]
		if len(track) < 50 {
			continue
		}

		var offsets1, offsets2 []float64
		
		for i := 5; i < len(track)-1 && len(offsets1) < 100; i++ {
			p := track[i]
			pNext := track[i+1]
			
			dx := pNext.X - p.X
			dy := pNext.Y - p.Y
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			
			if dist > 0.2 {
				moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
				
				// Compare with Quat1 yaw
				off1 := moveAngle - float64(p.Yaw1)
				for off1 > 180 { off1 -= 360 }
				for off1 < -180 { off1 += 360 }
				offsets1 = append(offsets1, off1)
				
				// Compare with Quat2 yaw
				off2 := moveAngle - float64(p.Yaw2)
				for off2 > 180 { off2 -= 360 }
				for off2 < -180 { off2 += 360 }
				offsets2 = append(offsets2, off2)
			}
		}

		if len(offsets1) < 10 {
			continue
		}

		// Calculate medians
		sort.Float64s(offsets1)
		sort.Float64s(offsets2)
		median1 := offsets1[len(offsets1)/2]
		median2 := offsets2[len(offsets2)/2]

		// Calculate consistency (how many are within 45° of median)
		near1, near2 := 0, 0
		for _, o := range offsets1 {
			diff := math.Abs(o - median1)
			if diff > 180 { diff = 360 - diff }
			if diff < 45 { near1++ }
		}
		for _, o := range offsets2 {
			diff := math.Abs(o - median2)
			if diff > 180 { diff = 360 - diff }
			if diff < 45 { near2++ }
		}
		
		cons1 := float64(near1) * 100 / float64(len(offsets1))
		cons2 := float64(near2) * 100 / float64(len(offsets2))

		fmt.Printf("Track %d (%d pts, %d samples):\n", trackIdx, len(track), len(offsets1))
		fmt.Printf("  Quat1: median offset = %.0f°, consistency = %.0f%%\n", median1, cons1)
		fmt.Printf("  Quat2: median offset = %.0f°, consistency = %.0f%%\n", median2, cons2)
		
		if cons2 > cons1 {
			fmt.Printf("  → Quat2 is BETTER!\n")
		} else if cons1 > cons2 {
			fmt.Printf("  → Quat1 is better\n")
		}
		fmt.Println()
	}

	// Statistical comparison
	fmt.Println("\n=== OVERALL YAW DIFFERENCE STATISTICS ===")
	var diffs []float64
	for _, p := range allPackets {
		diff := float64(p.Yaw2 - p.Yaw1)
		for diff > 180 { diff -= 360 }
		for diff < -180 { diff += 360 }
		diffs = append(diffs, diff)
	}
	
	sort.Float64s(diffs)
	fmt.Printf("Yaw2 - Yaw1 difference:\n")
	fmt.Printf("  Min: %.1f°\n", diffs[0])
	fmt.Printf("  25th: %.1f°\n", diffs[len(diffs)/4])
	fmt.Printf("  Median: %.1f°\n", diffs[len(diffs)/2])
	fmt.Printf("  75th: %.1f°\n", diffs[3*len(diffs)/4])
	fmt.Printf("  Max: %.1f°\n", diffs[len(diffs)-1])
}

func buildTracks(packets []PacketRecord, threshold float32) [][]PacketRecord {
	type trackState struct {
		packets      []PacketRecord
		lastX, lastY float32
	}
	
	states := make([]*trackState, 0, 12)
	
	for _, p := range packets {
		bestTrack := -1
		bestDist := float32(math.MaxFloat32)
		
		for i, t := range states {
			dx := p.X - t.lastX
			dy := p.Y - t.lastY
			dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
			if dist < bestDist {
				bestDist = dist
				bestTrack = i
			}
		}
		
		if bestTrack >= 0 && bestDist <= threshold {
			states[bestTrack].packets = append(states[bestTrack].packets, p)
			states[bestTrack].lastX = p.X
			states[bestTrack].lastY = p.Y
		} else {
			states = append(states, &trackState{
				packets: []PacketRecord{p},
				lastX:   p.X,
				lastY:   p.Y,
			})
		}
	}
	
	result := make([][]PacketRecord, len(states))
	for i, s := range states {
		result[i] = s.packets
	}
	return result
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

	rawPost, _ := r.Bytes(80)
	if len(rawPost) < 62 {
		return nil
	}

	// Quaternion 1: offset 4-20 (we've been reading this)
	// Based on hex dump: bytes 4-7 and 8-11 are 00000080 (very small/zero)
	// bytes 12-15 and 16-19 contain the actual qz/qw values
	q1x := readFloat32(rawPost[4:8])
	q1y := readFloat32(rawPost[8:12])
	q1z := readFloat32(rawPost[12:16])
	q1w := readFloat32(rawPost[16:20])

	// Quaternion 2: offset 46-62
	q2x := readFloat32(rawPost[46:50])
	q2y := readFloat32(rawPost[50:54])
	q2z := readFloat32(rawPost[54:58])
	q2w := readFloat32(rawPost[58:62])

	// Calculate yaw from each quaternion
	yaw1 := quaternionToYaw(q1x, q1y, q1z, q1w)
	yaw2 := quaternionToYaw(q2x, q2y, q2z, q2w)

	allPackets = append(allPackets, PacketRecord{
		X:     x,
		Y:     y,
		Z:     z,
		Quat1: [4]float32{q1x, q1y, q1z, q1w},
		Quat2: [4]float32{q2x, q2y, q2z, q2w},
		Yaw1:  yaw1,
		Yaw2:  yaw2,
	})

	return nil
}

func quaternionToYaw(x, y, z, w float32) float32 {
	sinyCosp := 2 * (float64(w)*float64(z) + float64(x)*float64(y))
	cosyCosp := 1 - 2*(float64(y)*float64(y)+float64(z)*float64(z))
	yaw := math.Atan2(sinyCosp, cosyCosp) * 180 / math.Pi
	return float32(yaw)
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

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
		fmt.Println("Usage: quatdebug <replay.rec>")
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

	fmt.Printf("Captured %d position packets\n\n", len(allPackets))

	// Build spatial tracks first
	type track struct {
		positions []PacketRecord
		lastX, lastY float32
	}
	
	tracks := make([]*track, 0, 12)
	threshold := float32(2.0)
	
	for _, p := range allPackets {
		if p.Type2 != 0x03 || len(p.PostBytes) < 20 {
			continue
		}
		
		// Find nearest track
		bestTrack := -1
		bestDist := float32(math.MaxFloat32)
		
		for i, t := range tracks {
			dx := p.X - t.lastX
			dy := p.Y - t.lastY
			dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
			if dist < bestDist {
				bestDist = dist
				bestTrack = i
			}
		}
		
		if bestTrack >= 0 && bestDist <= threshold {
			tracks[bestTrack].positions = append(tracks[bestTrack].positions, p)
			tracks[bestTrack].lastX = p.X
			tracks[bestTrack].lastY = p.Y
		} else {
			newTrack := &track{
				positions: []PacketRecord{p},
				lastX:     p.X,
				lastY:     p.Y,
			}
			tracks = append(tracks, newTrack)
		}
	}
	
	// Sort tracks by size
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})
	
	fmt.Println("=== TOP 5 TRACKS ===")
	for i := 0; i < min(5, len(tracks)); i++ {
		fmt.Printf("Track %d: %d positions\n", i, len(tracks[i].positions))
	}
	
	// Analyze the largest track in detail
	if len(tracks) > 0 && len(tracks[0].positions) > 20 {
		fmt.Println("\n\n=== DETAILED ANALYSIS OF LARGEST TRACK ===")
		largestTrack := tracks[0].positions
		
		totalTime := 240.0
		timePerPacket := totalTime / float64(len(allPackets))
		
		fmt.Println("\nPosition + Quaternion components over time:")
		fmt.Printf("%-8s %-8s %-14s %-10s %-10s %-10s %-10s %-12s\n",
			"Pkt", "Time", "Position", "Q0", "Q1", "Q2", "Q3", "ComputedYaw")
		fmt.Println("----------------------------------------------------------------------------------------")
		
		// Show first 40 packets of this track
		for i := 0; i < min(40, len(largestTrack)); i++ {
			p := largestTrack[i]
			t := float64(p.PacketNum) * timePerPacket
			
			q0 := readFloat32(p.PostBytes[4:8])
			q1 := readFloat32(p.PostBytes[8:12])
			q2 := readFloat32(p.PostBytes[12:16])
			q3 := readFloat32(p.PostBytes[16:20])
			
			// Standard yaw calculation
			yaw := 2 * math.Atan2(float64(q2), float64(q3)) * 180 / math.Pi
			
			fmt.Printf("%-8d %-8.1fs (%.1f,%.1f,%.1f) %-10.4f %-10.4f %-10.4f %-10.4f %-12.1f\n",
				p.PacketNum, t, p.X, p.Y, p.Z, q0, q1, q2, q3, yaw)
		}
		
		// Analyze if quaternion changes correlate with movement direction
		fmt.Println("\n\n=== MOVEMENT DIRECTION vs QUATERNION ANALYSIS ===")
		fmt.Println("Comparing computed yaw change to actual movement direction change")
		fmt.Printf("%-8s %-14s %-14s %-12s %-12s %-10s\n",
			"Idx", "Movement(dx,dy)", "MoveAngle", "QuatYaw", "YawChange", "Match?")
		fmt.Println("---------------------------------------------------------------------------------")
		
		prevYaw := float64(0)
		for i := 1; i < min(30, len(largestTrack)); i++ {
			p := largestTrack[i]
			pPrev := largestTrack[i-1]
			
			dx := p.X - pPrev.X
			dy := p.Y - pPrev.Y
			
			moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
			
			q2 := float64(readFloat32(p.PostBytes[12:16]))
			q3 := float64(readFloat32(p.PostBytes[16:20]))
			quatYaw := 2 * math.Atan2(q2, q3) * 180 / math.Pi
			
			yawChange := quatYaw - prevYaw
			if yawChange > 180 { yawChange -= 360 }
			if yawChange < -180 { yawChange += 360 }
			
			// Check if yaw roughly matches movement (within 45 degrees)
			diff := math.Abs(quatYaw - moveAngle)
			if diff > 180 { diff = 360 - diff }
			match := "NO"
			if diff < 45 || math.Abs(diff-180) < 45 {
				match = "~yes"
			}
			if math.Abs(float64(dx)) < 0.01 && math.Abs(float64(dy)) < 0.01 {
				match = "static"
			}
			
			fmt.Printf("%-8d (%.2f,%.2f)      %-14.1f %-12.1f %-12.1f %-10s\n",
				i, dx, dy, moveAngle, quatYaw, yawChange, match)
			
			prevYaw = quatYaw
		}
		
		// Look at ALL the quaternion values to understand their distribution
		fmt.Println("\n\n=== QUATERNION VALUE DISTRIBUTION ===")
		var q0Vals, q1Vals, q2Vals, q3Vals []float64
		
		for _, p := range largestTrack {
			q0Vals = append(q0Vals, float64(readFloat32(p.PostBytes[4:8])))
			q1Vals = append(q1Vals, float64(readFloat32(p.PostBytes[8:12])))
			q2Vals = append(q2Vals, float64(readFloat32(p.PostBytes[12:16])))
			q3Vals = append(q3Vals, float64(readFloat32(p.PostBytes[16:20])))
		}
		
		printStats := func(name string, vals []float64) {
			minV, maxV := vals[0], vals[0]
			sum := 0.0
			for _, v := range vals {
				if v < minV { minV = v }
				if v > maxV { maxV = v }
				sum += v
			}
			avg := sum / float64(len(vals))
			fmt.Printf("%s: min=%.4f, max=%.4f, avg=%.4f, range=%.4f\n", 
				name, minV, maxV, avg, maxV-minV)
		}
		
		printStats("Q0 (assumed qx)", q0Vals)
		printStats("Q1 (assumed qy)", q1Vals)
		printStats("Q2 (assumed qz)", q2Vals)
		printStats("Q3 (assumed qw)", q3Vals)
		
		// Check if there are other float patterns in the post bytes
		fmt.Println("\n\n=== EXPLORING OTHER OFFSETS IN POST-BYTES ===")
		fmt.Println("Looking for other float32 values that might be rotation")
		
		// Check various offsets for float patterns
		offsets := []int{0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40}
		
		fmt.Printf("%-8s", "Pkt")
		for _, off := range offsets {
			fmt.Printf("off%-6d", off)
		}
		fmt.Println()
		fmt.Println("-----------------------------------------------------------------------------------------")
		
		for i := 0; i < min(15, len(largestTrack)); i++ {
			p := largestTrack[i]
			fmt.Printf("%-8d", p.PacketNum)
			for _, off := range offsets {
				if off+4 <= len(p.PostBytes) {
					val := readFloat32(p.PostBytes[off:off+4])
					// Only print if it looks like a reasonable float (not huge/tiny/nan)
					if !math.IsNaN(float64(val)) && !math.IsInf(float64(val), 0) && 
					   math.Abs(float64(val)) < 1000 && math.Abs(float64(val)) > 0.0001 {
						fmt.Printf("%-9.3f", val)
					} else if math.Abs(float64(val)) <= 0.0001 {
						fmt.Printf("%-9.4f", val)
					} else {
						fmt.Printf("%-9s", "-")
					}
				} else {
					fmt.Printf("%-9s", "N/A")
				}
			}
			fmt.Println()
		}
		
		// Let's also check for angles stored as raw degrees or radians
		fmt.Println("\n\n=== CHECKING IF VALUES ARE DIRECT ANGLES ===")
		fmt.Println("Interpreting values at various offsets as potential direct angles")
		
		for i := 0; i < min(10, len(largestTrack)); i++ {
			p := largestTrack[i]
			fmt.Printf("Pkt %d: ", p.PacketNum)
			
			// Check bytes 0-3 as potential angle
			if len(p.PostBytes) >= 4 {
				v := readFloat32(p.PostBytes[0:4])
				if math.Abs(float64(v)) < 400 {
					fmt.Printf("off0=%.1f° ", v)
				}
			}
			
			// Check bytes 20-23 (after the quat)
			if len(p.PostBytes) >= 24 {
				v := readFloat32(p.PostBytes[20:24])
				if math.Abs(float64(v)) < 400 {
					fmt.Printf("off20=%.1f° ", v)
				}
			}
			
			fmt.Println()
		}
	}
	
	// Also look at type 0x01 packets which might have different rotation data
	fmt.Println("\n\n=== TYPE 0x01 PACKETS ANALYSIS ===")
	fmt.Println("Type 0x01 might have rotation in a different format")
	
	count := 0
	for _, p := range allPackets {
		if p.Type2 == 0x01 && len(p.PostBytes) >= 30 && count < 15 {
			fmt.Printf("Pkt %d: ", p.PacketNum)
			
			// Print all float values from post bytes
			for off := 0; off+4 <= min(40, len(p.PostBytes)); off += 4 {
				v := readFloat32(p.PostBytes[off:off+4])
				if !math.IsNaN(float64(v)) && math.Abs(float64(v)) < 10 && math.Abs(float64(v)) > 0.001 {
					fmt.Printf("[%d]=%.3f ", off, v)
				}
			}
			fmt.Println()
			count++
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

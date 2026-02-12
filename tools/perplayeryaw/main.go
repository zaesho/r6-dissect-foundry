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
	X, Y, Z   float32
	Qz, Qw    float32
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: perplayeryaw <replay.rec>")
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

	fmt.Printf("Captured %d type 0x03 position packets\n\n", len(allPackets))

	// Build tracks using spatial continuity
	tracks := buildTracks(allPackets, 1.5)
	
	// Sort by size, take top 10
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i]) > len(tracks[j])
	})
	
	if len(tracks) > 10 {
		tracks = tracks[:10]
	}

	fmt.Printf("Built %d player tracks\n\n", len(tracks))

	// For each track, analyze the relationship between quaternion yaw and movement direction
	fmt.Println("=== PER-PLAYER YAW ANALYSIS ===")
	fmt.Println("Comparing quaternion yaw to movement direction for each track\n")

	for trackIdx, track := range tracks {
		if len(track) < 50 {
			continue
		}

		// Calculate average start position (for team identification)
		var sumX, sumY float32
		numStart := min(20, len(track))
		for i := 0; i < numStart; i++ {
			sumX += track[i].X
			sumY += track[i].Y
		}
		avgStartX := sumX / float32(numStart)
		avgStartY := sumY / float32(numStart)

		// Collect offset samples where player is clearly moving
		var offsets []float64
		
		for i := 10; i < len(track)-1; i++ {
			p := track[i]
			pNext := track[i+1]
			
			dx := pNext.X - p.X
			dy := pNext.Y - p.Y
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			
			// Only consider when player is moving significantly
			if dist > 0.3 {
				// Movement direction
				moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
				
				// Quaternion yaw
				quatYaw := 2 * math.Atan2(float64(p.Qz), float64(p.Qw)) * 180 / math.Pi
				
				// Calculate offset needed to align yaw with movement
				offset := moveAngle - quatYaw
				// Normalize to -180 to 180
				for offset > 180 { offset -= 360 }
				for offset < -180 { offset += 360 }
				
				offsets = append(offsets, offset)
			}
		}

		if len(offsets) < 10 {
			fmt.Printf("Track %d: Not enough movement samples (%d)\n\n", trackIdx, len(offsets))
			continue
		}

		// Calculate statistics
		sort.Float64s(offsets)
		median := offsets[len(offsets)/2]
		
		// Count how many offsets are near the median (within 30 degrees)
		nearMedian := 0
		for _, o := range offsets {
			diff := math.Abs(o - median)
			if diff > 180 { diff = 360 - diff }
			if diff < 30 {
				nearMedian++
			}
		}
		consistency := float64(nearMedian) * 100 / float64(len(offsets))

		// Calculate what the corrected yaw offset should be
		// Round to nearest 45 degrees for cleaner values
		roundedOffset := math.Round(median/45) * 45

		fmt.Printf("Track %d: %d positions, start=(%.1f,%.1f)\n", 
			trackIdx, len(track), avgStartX, avgStartY)
		fmt.Printf("  Samples: %d moving moments\n", len(offsets))
		fmt.Printf("  Median offset: %.1f° (%.0f%% consistent)\n", median, consistency)
		fmt.Printf("  Suggested correction: %.0f°\n", roundedOffset)
		
		// Show sample comparisons
		fmt.Println("  Sample comparisons (move_dir vs quat_yaw):")
		sampleCount := 0
		for i := 10; i < len(track)-1 && sampleCount < 5; i++ {
			p := track[i]
			pNext := track[i+1]
			
			dx := pNext.X - p.X
			dy := pNext.Y - p.Y
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			
			if dist > 0.3 {
				moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
				quatYaw := 2 * math.Atan2(float64(p.Qz), float64(p.Qw)) * 180 / math.Pi
				correctedYaw := quatYaw + roundedOffset
				for correctedYaw > 180 { correctedYaw -= 360 }
				for correctedYaw < -180 { correctedYaw += 360 }
				
				match := "✗"
				diff := math.Abs(moveAngle - correctedYaw)
				if diff > 180 { diff = 360 - diff }
				if diff < 45 {
					match = "✓"
				}
				
				fmt.Printf("    move=%.0f° quat=%.0f° corrected=%.0f° %s\n",
					moveAngle, quatYaw, correctedYaw, match)
				sampleCount++
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("\n=== SUMMARY ===")
	fmt.Println("If all tracks need similar offsets, we can apply a global correction.")
	fmt.Println("If tracks need different offsets, we may need per-player calibration")
	fmt.Println("based on team, spawn location, or packet metadata.")
}

func buildTracks(packets []PacketRecord, threshold float32) [][]PacketRecord {
	type trackState struct {
		packets      []PacketRecord
		lastX, lastY float32
	}
	
	states := make([]*trackState, 0, 12)
	
	for _, p := range packets {
		// Find nearest track
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
			newState := &trackState{
				packets: []PacketRecord{p},
				lastX:   p.X,
				lastY:   p.Y,
			}
			states = append(states, newState)
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

	// Only type 0x03
	if type1 < 0xB0 || type2 != 0x03 {
		return nil
	}

	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	// Read post bytes to get quaternion
	postBytes, _ := r.Bytes(20)
	if len(postBytes) < 20 {
		return nil
	}

	qz := readFloat32(postBytes[12:16])
	qw := readFloat32(postBytes[16:20])

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		X:         x,
		Y:         y,
		Z:         z,
		Qz:        qz,
		Qw:        qw,
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

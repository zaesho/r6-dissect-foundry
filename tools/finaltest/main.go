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
	X, Y, Z float32
	Yaw     float32 // From Quat1 (offset 12-20)
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: finaltest <replay.rec>")
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

	fmt.Printf("Captured %d packets\n\n", len(allPackets))

	// Build tracks
	tracks := buildTracks(allPackets, 1.5)
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i]) > len(tracks[j])
	})

	// Test different offsets
	offsets := []float64{0, 45, 90, -90, 180}
	
	fmt.Println("=== TESTING DIFFERENT YAW OFFSETS ===")
	fmt.Println("Looking for which offset gives best match between yaw and movement direction\n")
	
	for _, offset := range offsets {
		fmt.Printf("Testing offset: %.0f°\n", offset)
		
		totalSamples := 0
		totalNearMatch := 0
		
		for trackIdx := 0; trackIdx < min(10, len(tracks)); trackIdx++ {
			track := tracks[trackIdx]
			if len(track) < 50 {
				continue
			}
			
			for i := 5; i < len(track)-1; i++ {
				p := track[i]
				pNext := track[i+1]
				
				dx := pNext.X - p.X
				dy := pNext.Y - p.Y
				dist := math.Sqrt(float64(dx*dx + dy*dy))
				
				if dist > 0.3 { // Only when moving
					moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
					correctedYaw := float64(p.Yaw) + offset
					
					diff := moveAngle - correctedYaw
					for diff > 180 { diff -= 360 }
					for diff < -180 { diff += 360 }
					
					totalSamples++
					if math.Abs(diff) < 45 {
						totalNearMatch++
					}
				}
			}
		}
		
		if totalSamples > 0 {
			matchPct := float64(totalNearMatch) * 100 / float64(totalSamples)
			fmt.Printf("  %d/%d samples (%.1f%%) within 45° of movement direction\n\n",
				totalNearMatch, totalSamples, matchPct)
		}
	}

	// Show sample timeline with best offset (90°)
	fmt.Println("\n=== SAMPLE TIMELINE WITH +90° OFFSET ===")
	fmt.Println("Showing first 30 movement samples from Track 0:")
	fmt.Println("  Time | Position       | RawYaw | +90°Yaw | MoveDir | Match?")
	fmt.Println("  -----|----------------|--------|---------|---------|-------")
	
	track := tracks[0]
	sampleCount := 0
	for i := 5; i < len(track)-1 && sampleCount < 30; i++ {
		p := track[i]
		pNext := track[i+1]
		
		dx := pNext.X - p.X
		dy := pNext.Y - p.Y
		dist := math.Sqrt(float64(dx*dx + dy*dy))
		
		if dist > 0.3 {
			moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
			correctedYaw := float64(p.Yaw) + 90
			for correctedYaw > 180 { correctedYaw -= 360 }
			
			diff := moveAngle - correctedYaw
			for diff > 180 { diff -= 360 }
			for diff < -180 { diff += 360 }
			
			match := "✗"
			if math.Abs(diff) < 45 {
				match = "✓"
			}
			
			time := float64(i) * 240 / float64(len(track))
			fmt.Printf("  %4.1fs | (%5.1f, %5.1f) | %6.1f° | %6.1f° | %6.1f° | %s\n",
				time, p.X, p.Y, p.Yaw, correctedYaw, moveAngle, match)
			sampleCount++
		}
	}
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

	rawPost, _ := r.Bytes(20)
	if len(rawPost) < 20 {
		return nil
	}

	// Quaternion at offset 12-20 (qz, qw)
	qz := readFloat32(rawPost[12:16])
	qw := readFloat32(rawPost[16:20])
	
	// Simple Z-rotation yaw: 2 * atan2(qz, qw)
	yaw := float32(2 * math.Atan2(float64(qz), float64(qw)) * 180 / math.Pi)

	allPackets = append(allPackets, PacketRecord{
		X:   x,
		Y:   y,
		Z:   z,
		Yaw: yaw,
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

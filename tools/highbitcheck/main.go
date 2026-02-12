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
	HighBit   bool // Is the high bit set in bytes 4-7?
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: highbitcheck <replay.rec>")
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

	// Separate by high bit
	var noBit, hasBit []PacketRecord
	for _, p := range allPackets {
		if p.HighBit {
			hasBit = append(hasBit, p)
		} else {
			noBit = append(noBit, p)
		}
	}

	fmt.Printf("Total packets: %d\n", len(allPackets))
	fmt.Printf("  High bit NOT set (0x00000000): %d packets\n", len(noBit))
	fmt.Printf("  High bit SET (0x80000000): %d packets\n\n", len(hasBit))

	// Build tracks for each group separately
	fmt.Println("=== TRACKS WITHOUT HIGH BIT (likely team A) ===")
	tracksNoBit := buildTracks(noBit, 1.5)
	analyzeTracks(tracksNoBit, "NoBit")

	fmt.Println("\n=== TRACKS WITH HIGH BIT (likely team B) ===")
	tracksHasBit := buildTracks(hasBit, 1.5)
	analyzeTracks(tracksHasBit, "HasBit")

	// Check spawn positions
	fmt.Println("\n=== SPAWN POSITION ANALYSIS ===")
	fmt.Println("First positions for each track:")
	
	fmt.Println("\nNo-bit tracks:")
	for i, track := range tracksNoBit {
		if len(track) >= 50 && i < 6 {
			fmt.Printf("  Track %d: first=(%.1f, %.1f), %d positions\n", i, track[0].X, track[0].Y, len(track))
		}
	}
	
	fmt.Println("\nHas-bit tracks:")
	for i, track := range tracksHasBit {
		if len(track) >= 50 && i < 6 {
			fmt.Printf("  Track %d: first=(%.1f, %.1f), %d positions\n", i, track[0].X, track[0].Y, len(track))
		}
	}
}

func analyzeTracks(tracks [][]PacketRecord, label string) {
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i]) > len(tracks[j])
	})

	fmt.Printf("Built %d tracks\n", len(tracks))
	
	// For top tracks, analyze yaw vs movement
	for idx, track := range tracks {
		if len(track) < 50 || idx >= 6 {
			continue
		}

		var offsets []float64
		for i := 5; i < len(track)-1 && len(offsets) < 100; i++ {
			p := track[i]
			pNext := track[i+1]
			
			dx := pNext.X - p.X
			dy := pNext.Y - p.Y
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			
			if dist > 0.2 {
				moveAngle := math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
				quatYaw := 2 * math.Atan2(float64(p.Qz), float64(p.Qw)) * 180 / math.Pi
				
				offset := moveAngle - quatYaw
				for offset > 180 { offset -= 360 }
				for offset < -180 { offset += 360 }
				offsets = append(offsets, offset)
			}
		}

		if len(offsets) >= 5 {
			sort.Float64s(offsets)
			median := offsets[len(offsets)/2]
			
			// Calculate consistency
			nearMedian := 0
			for _, o := range offsets {
				diff := math.Abs(o - median)
				if diff > 180 { diff = 360 - diff }
				if diff < 45 {
					nearMedian++
				}
			}
			consistency := float64(nearMedian) * 100 / float64(len(offsets))
			
			fmt.Printf("  Track %d (%d pts): median offset = %.0f° (%.0f%% consistent)\n",
				idx, len(track), median, consistency)
		} else {
			fmt.Printf("  Track %d (%d pts): not enough movement\n", idx, len(track))
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

	postBytes, _ := r.Bytes(20)
	if len(postBytes) < 20 {
		return nil
	}

	// Check bytes 4-7 for high bit
	entityField := binary.LittleEndian.Uint32(postBytes[4:8])
	highBit := (entityField & 0x80000000) != 0

	qz := readFloat32(postBytes[12:16])
	qw := readFloat32(postBytes[16:20])

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		X:         x,
		Y:         y,
		Z:         z,
		Qz:        qz,
		Qw:        qw,
		HighBit:   highBit,
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

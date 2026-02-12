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
	Yaw       float32
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: yawsmooth <replay.rec>")
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

	fmt.Println("=== YAW SMOOTHNESS ANALYSIS ===")
	fmt.Println("Checking if yaw changes are smooth (small deltas) vs erratic (large jumps)")
	fmt.Println()

	for idx, track := range tracks {
		if len(track) < 100 || idx >= 10 {
			continue
		}

		var deltas []float64
		var largeJumps int
		
		for i := 1; i < len(track); i++ {
			delta := float64(track[i].Yaw - track[i-1].Yaw)
			// Normalize to -180 to 180
			for delta > 180 { delta -= 360 }
			for delta < -180 { delta += 360 }
			delta = math.Abs(delta)
			
			deltas = append(deltas, delta)
			if delta > 30 {
				largeJumps++
			}
		}

		if len(deltas) == 0 {
			continue
		}

		sort.Float64s(deltas)
		median := deltas[len(deltas)/2]
		p90 := deltas[int(float64(len(deltas))*0.9)]
		maxDelta := deltas[len(deltas)-1]
		
		smoothPct := 100.0 * float64(len(deltas)-largeJumps) / float64(len(deltas))

		fmt.Printf("Track %d (%d pts):\n", idx, len(track))
		fmt.Printf("  Yaw delta: median=%.1f°, 90th=%.1f°, max=%.1f°\n", median, p90, maxDelta)
		fmt.Printf("  Smooth transitions (<30°): %.1f%%\n", smoothPct)
		
		// Show yaw progression for first 20 positions
		fmt.Print("  First 20 yaw values: ")
		for i := 0; i < min(20, len(track)); i++ {
			fmt.Printf("%.0f ", track[i].Yaw)
		}
		fmt.Println()
		fmt.Println()
	}

	// Overall statistics
	fmt.Println("=== OVERALL ===")
	fmt.Println("If yaw is smooth (small median delta, high smooth %), the quaternion data is valid.")
	fmt.Println("Players just don't always face their movement direction.")
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

	qz := readFloat32(postBytes[12:16])
	qw := readFloat32(postBytes[16:20])
	
	// Convert to yaw
	yaw := float32(2 * math.Atan2(float64(qz), float64(qw)) * 180 / math.Pi)

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		X:         x,
		Y:         y,
		Z:         z,
		Yaw:       yaw,
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

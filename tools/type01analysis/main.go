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
		fmt.Println("Usage: type01analysis <replay.rec>")
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

	// Separate packets by type
	var type01, type03 []PacketRecord
	
	for _, p := range allPackets {
		if p.Type2 == 0x01 {
			type01 = append(type01, p)
		} else if p.Type2 == 0x03 {
			type03 = append(type03, p)
		}
	}

	fmt.Printf("Type 0x01 packets: %d\n", len(type01))
	fmt.Printf("Type 0x03 packets: %d\n\n", len(type03))

	// Build spatial tracks for type 0x01
	fmt.Println("=== BUILDING TRACKS FROM TYPE 0x01 PACKETS ===\n")
	
	tracks01 := buildTracks(type01)
	
	sort.Slice(tracks01, func(i, j int) bool {
		return len(tracks01[i]) > len(tracks01[j])
	})
	
	fmt.Printf("Found %d tracks from type 0x01\n", len(tracks01))
	for i := 0; i < min(5, len(tracks01)); i++ {
		fmt.Printf("  Track %d: %d packets\n", i, len(tracks01[i]))
	}

	// Analyze the largest type 0x01 track
	if len(tracks01) > 0 && len(tracks01[0]) > 20 {
		fmt.Println("\n=== ANALYZING LARGEST TYPE 0x01 TRACK ===")
		track := tracks01[0]
		
		fmt.Println("\nPosition and potential rotation values:")
		fmt.Printf("%-8s %-14s %-12s %-12s %-12s %-12s %-12s\n",
			"Pkt", "Position", "off00", "off04", "off08", "off12", "off16")
		fmt.Println("------------------------------------------------------------------------------------------")
		
		for i := 0; i < min(30, len(track)); i++ {
			p := track[i]
			
			var vals [5]string
			offsets := []int{0, 4, 8, 12, 16}
			for j, off := range offsets {
				if off+4 <= len(p.PostBytes) {
					v := readFloat32(p.PostBytes[off:off+4])
					if math.Abs(float64(v)) < 1000 && !math.IsNaN(float64(v)) {
						vals[j] = fmt.Sprintf("%.3f", v)
					} else {
						vals[j] = "-"
					}
				}
			}
			
			fmt.Printf("%-8d (%.1f,%.1f,%.1f) %-12s %-12s %-12s %-12s %-12s\n",
				p.PacketNum, p.X, p.Y, p.Z, vals[0], vals[1], vals[2], vals[3], vals[4])
		}
		
		// Compare with corresponding type 0x03 packets for the same track
		fmt.Println("\n\n=== COMPARING TYPE 0x01 vs TYPE 0x03 FOR SAME POSITIONS ===")
		fmt.Println("Looking for packets at similar positions to compare rotation data\n")
		
		// Build position index for type 0x03
		type03ByPos := make(map[string][]PacketRecord)
		for _, p := range type03 {
			key := fmt.Sprintf("%.0f,%.0f", p.X, p.Y)
			type03ByPos[key] = append(type03ByPos[key], p)
		}
		
		fmt.Printf("%-8s %-14s %-10s %-10s %-10s %-10s\n",
			"Pkt", "Position", "01:off16", "03:qz", "03:qw", "03:yaw")
		fmt.Println("-----------------------------------------------------------------------")
		
		matchCount := 0
		for i := 0; i < min(20, len(track)); i++ {
			p01 := track[i]
			key := fmt.Sprintf("%.0f,%.0f", p01.X, p01.Y)
			
			matching03 := type03ByPos[key]
			if len(matching03) > 0 {
				p03 := matching03[0] // Take first matching
				
				off16_01 := "-"
				if len(p01.PostBytes) >= 20 {
					v := readFloat32(p01.PostBytes[16:20])
					if math.Abs(float64(v)) < 1000 {
						off16_01 = fmt.Sprintf("%.3f", v)
					}
				}
				
				qz, qw, yaw := float32(0), float32(0), float64(0)
				if len(p03.PostBytes) >= 20 {
					qz = readFloat32(p03.PostBytes[12:16])
					qw = readFloat32(p03.PostBytes[16:20])
					yaw = 2 * math.Atan2(float64(qz), float64(qw)) * 180 / math.Pi
				}
				
				fmt.Printf("%-8d (%.1f,%.1f)     %-10s %-10.4f %-10.4f %-10.1f\n",
					p01.PacketNum, p01.X, p01.Y, off16_01, qz, qw, yaw)
				matchCount++
			}
		}
		fmt.Printf("\nFound %d position matches between type 0x01 and 0x03\n", matchCount)
	}

	// Also check B801 specifically (0xB8 prefix with 0x01 suffix)
	fmt.Println("\n\n=== B801 SPECIFIC ANALYSIS ===")
	var b801Packets []PacketRecord
	for _, p := range allPackets {
		if p.Type1 == 0xB8 && p.Type2 == 0x01 {
			b801Packets = append(b801Packets, p)
		}
	}
	
	fmt.Printf("B801 packets: %d\n\n", len(b801Packets))
	
	if len(b801Packets) > 0 {
		fmt.Println("Analyzing off16 values (suspected angle):")
		fmt.Printf("%-8s %-14s %-12s %-12s\n",
			"Pkt", "Position", "off16", "Interpretation")
		fmt.Println("--------------------------------------------------")
		
		for i := 0; i < min(30, len(b801Packets)); i++ {
			p := b801Packets[i]
			
			off16Val := "-"
			interp := ""
			if len(p.PostBytes) >= 20 {
				v := readFloat32(p.PostBytes[16:20])
				if !math.IsNaN(float64(v)) && math.Abs(float64(v)) < 1000 {
					off16Val = fmt.Sprintf("%.3f", v)
					// Try to interpret
					if v >= 0 && v <= 180 {
						interp = "degrees?"
					} else if v >= -3.15 && v <= 3.15 {
						interp = fmt.Sprintf("radians = %.1f°", v*180/math.Pi)
					}
				}
			}
			
			fmt.Printf("%-8d (%.1f,%.1f,%.1f) %-12s %s\n",
				p.PacketNum, p.X, p.Y, p.Z, off16Val, interp)
		}
		
		// Statistics
		var off16Values []float64
		for _, p := range b801Packets {
			if len(p.PostBytes) >= 20 {
				v := float64(readFloat32(p.PostBytes[16:20]))
				if !math.IsNaN(v) && math.Abs(v) < 1000 {
					off16Values = append(off16Values, v)
				}
			}
		}
		
		if len(off16Values) > 0 {
			sort.Float64s(off16Values)
			minV := off16Values[0]
			maxV := off16Values[len(off16Values)-1]
			sum := 0.0
			for _, v := range off16Values {
				sum += v
			}
			avgV := sum / float64(len(off16Values))
			
			fmt.Printf("\nStatistics for off16: min=%.2f, max=%.2f, avg=%.2f\n", minV, maxV, avgV)
		}
	}
}

func buildTracks(packets []PacketRecord) [][]PacketRecord {
	tracks := make([][]PacketRecord, 0, 12)
	threshold := float32(2.0)
	
	type trackState struct {
		packets []PacketRecord
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
	
	for _, s := range states {
		tracks = append(tracks, s.packets)
	}
	
	return tracks
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

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
	RawBytes  []byte // Full raw bytes including type and coords
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: rawdump <replay.rec>")
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

	// Filter to type 0x03 only and show detailed hex dump
	fmt.Println("=== RAW HEX DUMP OF TYPE 0x03 PACKETS ===")
	fmt.Println("Looking for patterns in the raw bytes\n")

	count := 0
	for _, p := range allPackets {
		if p.Type2 == 0x03 && count < 20 {
			fmt.Printf("Pkt %d: Type=%02X%02X Pos=(%.1f,%.1f,%.1f)\n", 
				p.PacketNum, p.Type1, p.Type2, p.X, p.Y, p.Z)
			fmt.Printf("  Bytes after coords:\n")
			
			// Skip first 14 bytes (2 type + 12 coord)
			if len(p.RawBytes) >= 14 {
				afterCoords := p.RawBytes[14:]
				// Hex dump in 8-byte rows
				for i := 0; i < min(48, len(afterCoords)); i += 8 {
					end := min(i+8, len(afterCoords))
					hexStr := hex.EncodeToString(afterCoords[i:end])
					
					// Try to interpret as floats
					floatStr := ""
					for j := i; j+4 <= end && j+4 <= len(afterCoords); j += 4 {
						f := readFloat32(afterCoords[j:j+4])
						if !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) && 
						   math.Abs(float64(f)) < 1000 {
							floatStr += fmt.Sprintf("%.3f ", f)
						} else {
							floatStr += "- "
						}
					}
					
					fmt.Printf("    +%02d: %-24s | floats: %s\n", i, hexStr, floatStr)
				}
			}
			fmt.Println()
			count++
		}
	}

	// Now look at 5 packets from the same track to see field consistency
	fmt.Println("\n=== TRACKING FIELD CHANGES ACROSS CONSECUTIVE PACKETS ===")
	fmt.Println("Following one player's packets to see which fields change\n")

	// Build a simple track
	type trackPkt struct {
		p PacketRecord
		t float64
	}
	var track []trackPkt
	var lastX, lastY float32
	threshold := float32(2.0)
	
	for i, p := range allPackets {
		if p.Type2 != 0x03 || len(p.RawBytes) < 34 {
			continue
		}
		
		if len(track) == 0 {
			lastX, lastY = p.X, p.Y
			track = append(track, trackPkt{p, 0})
			continue
		}
		
		dx := p.X - lastX
		dy := p.Y - lastY
		dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
		
		if dist <= threshold {
			t := float64(i) * 240.0 / float64(len(allPackets))
			track = append(track, trackPkt{p, t})
			lastX, lastY = p.X, p.Y
			
			if len(track) >= 30 {
				break
			}
		}
	}

	fmt.Printf("Built track with %d packets\n\n", len(track))
	
	// Compare consecutive packets
	if len(track) >= 2 {
		fmt.Println("Comparing fields that CHANGE between consecutive packets:\n")
		
		for i := 1; i < min(15, len(track)); i++ {
			prev := track[i-1].p.RawBytes
			curr := track[i].p.RawBytes
			
			fmt.Printf("Pkt %d → %d (%.1f,%.1f) → (%.1f,%.1f):\n",
				track[i-1].p.PacketNum, track[i].p.PacketNum,
				track[i-1].p.X, track[i-1].p.Y,
				track[i].p.X, track[i].p.Y)
			
			// Skip coords (bytes 2-14), compare the rest
			startOffset := 14
			maxLen := min(len(prev), len(curr))
			
			changes := []string{}
			for j := startOffset; j+4 <= min(50, maxLen); j += 4 {
				f1 := readFloat32(prev[j:j+4])
				f2 := readFloat32(curr[j:j+4])
				
				if math.Abs(float64(f2-f1)) > 0.0001 {
					changes = append(changes, fmt.Sprintf("off%d: %.4f→%.4f (Δ=%.4f)", 
						j-14, f1, f2, f2-f1))
				}
			}
			
			if len(changes) == 0 {
				fmt.Println("  No float changes detected in post-coord data")
			} else {
				for _, c := range changes {
					fmt.Printf("  %s\n", c)
				}
			}
			fmt.Println()
		}
	}

	// Try interpreting bytes as different data types
	fmt.Println("\n=== INTERPRETING BYTES AS DIFFERENT TYPES ===")
	fmt.Println("Checking if rotation might be stored as int16 or other format\n")

	for i := 0; i < min(10, len(track)); i++ {
		p := track[i].p
		afterCoords := p.RawBytes[14:]
		
		fmt.Printf("Pkt %d:\n", p.PacketNum)
		
		// Try int16 at various offsets
		for off := 0; off+2 <= min(20, len(afterCoords)); off += 2 {
			i16 := int16(binary.LittleEndian.Uint16(afterCoords[off:off+2]))
			// If it's an angle, might be stored as int16 scaled (e.g., 32767 = 180°)
			asAngle := float64(i16) * 180.0 / 32767.0
			
			if i16 != 0 && math.Abs(asAngle) < 400 {
				fmt.Printf("  i16@%d: %d (%.1f° if scaled)\n", off, i16, asAngle)
			}
		}
		fmt.Println()
	}
}

func capturePacket(r *dissect.Reader) error {
	// Read type bytes first
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	type1 := typeBytes[0]
	type2 := typeBytes[1]

	if type1 < 0xB0 {
		return nil
	}

	// Read coords
	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	// Read more raw bytes after coords
	postBytes, _ := r.Bytes(64)

	// Reconstruct raw bytes
	rawBytes := make([]byte, 2+12+len(postBytes))
	copy(rawBytes[0:2], typeBytes)
	binary.LittleEndian.PutUint32(rawBytes[2:6], math.Float32bits(x))
	binary.LittleEndian.PutUint32(rawBytes[6:10], math.Float32bits(y))
	binary.LittleEndian.PutUint32(rawBytes[10:14], math.Float32bits(z))
	copy(rawBytes[14:], postBytes)

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		RawBytes:  rawBytes,
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

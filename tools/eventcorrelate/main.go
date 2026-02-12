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
	PostBytes []byte
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: eventcorrelate <replay.rec>")
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

	// Calculate time per packet (assuming ~240s total)
	totalTime := 240.0
	timePerPacket := totalTime / float64(len(allPackets))

	// Print kill events and look for nearby packets
	fmt.Println("=== KILL EVENT CORRELATION ===\n")
	
	kills := []struct {
		time   float64
		killer string
		victim string
	}{
		{84, "Repuhrz", "SpiffNP"},
		{73, "Franklin.ALX", "VicBands"},
		{72, "BjL-", "Inryo.ALX"},
		{58, "Kiru.UNITY", "Solo.FF"},
		{51, "Ewzy4KT", "hattttttttt"},
		{50, "Repuhrz", "Ewzy4KT"},
		{44, "Repuhrz", "Franklin.ALX"},
	}

	for _, kill := range kills {
		// Estimate packet number at kill time
		estPacketNum := int(kill.time / timePerPacket)
		
		fmt.Printf("Kill at %.0fs: %s -> %s (est packet #%d)\n", 
			kill.time, kill.killer, kill.victim, estPacketNum)
		
		// Look for type 0x08 packets near this time
		searchRange := 500 // packets
		for _, p := range allPackets {
			if p.Type2 == 0x08 && abs(p.PacketNum-estPacketNum) < searchRange {
				estTime := float64(p.PacketNum) * timePerPacket
				fmt.Printf("  Type 0x08 at #%d (est %.1fs): post=%s\n", 
					p.PacketNum, estTime, hex.EncodeToString(p.PostBytes[:min(32, len(p.PostBytes))]))
			}
		}
		fmt.Println()
	}

	// Analyze type 0x08 packets in detail
	fmt.Println("\n=== TYPE 0x08 PACKET PATTERNS ===")
	var type08 []PacketRecord
	for _, p := range allPackets {
		if p.Type2 == 0x08 {
			type08 = append(type08, p)
		}
	}

	// Group by post-byte prefix
	prefixGroups := make(map[string][]PacketRecord)
	for _, p := range type08 {
		if len(p.PostBytes) >= 4 {
			prefix := hex.EncodeToString(p.PostBytes[0:4])
			prefixGroups[prefix] = append(prefixGroups[prefix], p)
		}
	}

	fmt.Printf("Found %d type 0x08 packets with %d unique 4-byte prefixes\n\n", len(type08), len(prefixGroups))

	for prefix, packets := range prefixGroups {
		fmt.Printf("Prefix %s: %d packets\n", prefix, len(packets))
		for i, p := range packets {
			if i >= 3 {
				fmt.Printf("  ... and %d more\n", len(packets)-3)
				break
			}
			estTime := float64(p.PacketNum) * timePerPacket
			fmt.Printf("  #%d (%.1fs): %s\n", p.PacketNum, estTime, hex.EncodeToString(p.PostBytes[:min(40, len(p.PostBytes))]))
		}
	}

	// Look for any packet type that appears near kill times
	fmt.Println("\n=== RARE PACKET TYPES NEAR KILLS ===")
	rareTypes := []byte{0x04, 0x05, 0x06, 0x08, 0x14, 0x1F}
	
	for _, kill := range kills {
		estPacketNum := int(kill.time / timePerPacket)
		fmt.Printf("\nKill at %.0fs (est #%d):\n", kill.time, estPacketNum)
		
		for _, p := range allPackets {
			if abs(p.PacketNum-estPacketNum) < 200 {
				for _, rareType := range rareTypes {
					if p.Type2 == rareType {
						estTime := float64(p.PacketNum) * timePerPacket
						fmt.Printf("  Type 0x%02X at #%d (%.1fs): %s\n", 
							p.Type2, p.PacketNum, estTime, hex.EncodeToString(p.PostBytes[:min(24, len(p.PostBytes))]))
					}
				}
			}
		}
	}

	// Analyze byte patterns in type 0x08 that might indicate event type
	fmt.Println("\n=== TYPE 0x08 BYTE ANALYSIS ===")
	for pos := 0; pos < 40 && len(type08) > 0 && pos < len(type08[0].PostBytes); pos++ {
		values := make(map[byte]int)
		for _, p := range type08 {
			if pos < len(p.PostBytes) {
				values[p.PostBytes[pos]]++
			}
		}
		
		if len(values) >= 2 && len(values) <= 10 {
			fmt.Printf("Byte@%d: ", pos)
			for v, c := range values {
				if c >= 2 {
					fmt.Printf("0x%02X(%d) ", v, c)
				}
			}
			fmt.Println()
		}
	}

	// Look for uint32 values that might be player/entity IDs
	fmt.Println("\n=== TYPE 0x08 UINT32 VALUES ===")
	for offset := 0; offset <= 32 && offset+4 <= len(type08[0].PostBytes); offset += 4 {
		values := make(map[uint32]int)
		for _, p := range type08 {
			if offset+4 <= len(p.PostBytes) {
				val := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
				values[val]++
			}
		}
		
		if len(values) >= 2 && len(values) <= 20 {
			fmt.Printf("uint32@%d: %d unique values\n", offset, len(values))
			for v, c := range values {
				if c >= 5 {
					fmt.Printf("  %d (0x%08X): %d times\n", v, v, c)
				}
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

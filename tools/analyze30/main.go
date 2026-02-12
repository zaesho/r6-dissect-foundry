package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	typeCode  uint16
	packetNum int
	rawBytes  []byte
}

var packets []packet
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
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

	// Capture 0x30xx packets specifically
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capture30)
	r.Read()

	fmt.Printf("Captured %d 0x30xx packets\n\n", len(packets))

	// Analyze each major 30xx type
	typeGroups := make(map[uint16][]packet)
	for _, p := range packets {
		typeGroups[p.typeCode] = append(typeGroups[p.typeCode], p)
	}

	// Analyze 0x3006 - the most common 30xx type
	if group, ok := typeGroups[0x3006]; ok && len(group) > 0 {
		fmt.Printf("=== Analyzing 0x3006 (%d packets) ===\n", len(group))
		analyzePacketGroup(group, 20)
	}

	// Analyze 0x3004
	if group, ok := typeGroups[0x3004]; ok && len(group) > 0 {
		fmt.Printf("\n=== Analyzing 0x3004 (%d packets) ===\n", len(group))
		analyzePacketGroup(group, 20)
	}

	// Analyze 0x3008
	if group, ok := typeGroups[0x3008]; ok && len(group) > 0 {
		fmt.Printf("\n=== Analyzing 0x3008 (%d packets) ===\n", len(group))
		analyzePacketGroup(group, 20)
	}

	// Analyze 0x3005
	if group, ok := typeGroups[0x3005]; ok && len(group) > 0 {
		fmt.Printf("\n=== Analyzing 0x3005 (%d packets) ===\n", len(group))
		analyzePacketGroup(group, 10)
	}

	// Header
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d)\n", i, p.Username, p.TeamIndex)
	}
}

func analyzePacketGroup(group []packet, showCount int) {
	// Show first N packets raw
	fmt.Printf("First %d packets (raw bytes after type):\n", showCount)
	for i := 0; i < showCount && i < len(group); i++ {
		p := group[i]
		fmt.Printf("\n[%d] Type=0x%04X\n", i, p.typeCode)
		fmt.Printf("    Raw: %02X\n", p.rawBytes)
		
		// Try to interpret as floats
		if len(p.rawBytes) >= 12 {
			f1 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawBytes[0:4]))
			f2 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawBytes[4:8]))
			f3 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawBytes[8:12]))
			
			fmt.Printf("    Floats 0-11: %.3f, %.3f, %.3f\n", f1, f2, f3)
			
			// Check if they look like coordinates
			if isCoord(f1) && isCoord(f2) && isCoord(f3) {
				fmt.Printf("    ^ Possible coordinates!\n")
			}
		}
		
		// Try to find player IDs
		for offset := 0; offset+4 <= len(p.rawBytes); offset += 4 {
			val := binary.LittleEndian.Uint32(p.rawBytes[offset : offset+4])
			if val >= 5 && val <= 14 {
				fmt.Printf("    Possible player ID %d at offset %d\n", val, offset)
			}
		}
	}

	// Look for patterns in player IDs across all packets
	fmt.Printf("\nPlayer ID candidates at each offset:\n")
	offsetCounts := make(map[int]map[uint32]int)
	
	for _, p := range group {
		for offset := 0; offset+4 <= len(p.rawBytes); offset += 4 {
			val := binary.LittleEndian.Uint32(p.rawBytes[offset : offset+4])
			if val >= 5 && val <= 14 {
				if offsetCounts[offset] == nil {
					offsetCounts[offset] = make(map[uint32]int)
				}
				offsetCounts[offset][val]++
			}
		}
	}
	
	for offset := 0; offset < 40; offset += 4 {
		if counts, ok := offsetCounts[offset]; ok && len(counts) > 0 {
			total := 0
			for _, c := range counts {
				total += c
			}
			fmt.Printf("  Offset %2d: %d packets with player IDs 5-14\n", offset, total)
		}
	}
}

func capture30(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	// Only capture 0x30xx packets
	if typeBytes[0] != 0x30 {
		return nil
	}

	// Read up to 40 bytes of data
	rawBytes, err := r.Bytes(40)
	if err != nil {
		rawBytes = make([]byte, 0)
	}

	packets = append(packets, packet{
		typeCode:  typeCode,
		packetNum: packetNum,
		rawBytes:  rawBytes,
	})

	return nil
}

func isCoord(f float32) bool {
	return !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) && f >= -100 && f <= 100
}

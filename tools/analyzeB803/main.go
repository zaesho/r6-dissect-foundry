package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/klauspost/compress/zstd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	decompressed := decompress(data)
	fmt.Printf("Decompressed size: %d bytes\n\n", len(decompressed))

	// Look for player position marker: 00 00 60 73 85 fe
	marker := []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

	// Analyze B803 packets specifically - look for additional identifiers
	type packetInfo struct {
		offset     int
		x, y, z    float32
		extraBytes []byte // bytes after type but before coords
	}

	// Group by different potential sub-identifiers
	byByte14 := make(map[byte]int)     // byte at offset +14 from marker
	byByte16 := make(map[uint16]int)   // 2 bytes at offset +16
	byByte20 := make(map[uint32]int)   // 4 bytes at offset +20

	var b803Packets []packetInfo
	
	for i := 0; i <= len(decompressed)-len(marker)-30; i++ {
		if !bytes.Equal(decompressed[i:i+len(marker)], marker) {
			continue
		}

		typeBytes := decompressed[i+6 : i+8]
		if typeBytes[0] != 0xB8 || typeBytes[1] != 0x03 {
			continue
		}

		// Read coordinates at offset +8 from marker
		pos := i + 8
		if pos+12 > len(decompressed) {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(decompressed[pos : pos+4]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(decompressed[pos+4 : pos+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(decompressed[pos+8 : pos+12]))

		// Skip invalid coords
		if x < -100 || x > 100 || y < -100 || y > 100 || z < -5 || z > 15 {
			continue
		}

		// Track various bytes that might be sub-identifiers
		if i+14 < len(decompressed) {
			byByte14[decompressed[i+14]]++
		}
		if i+16 < len(decompressed) {
			byByte16[binary.LittleEndian.Uint16(decompressed[i+16:i+18])]++
		}
		if i+20 < len(decompressed) {
			byByte20[binary.LittleEndian.Uint32(decompressed[i+20:i+24])]++
		}

		// Store packet info
		extraBytes := make([]byte, 20)
		if i+28 <= len(decompressed) {
			copy(extraBytes, decompressed[i+8:i+28])
		}
		b803Packets = append(b803Packets, packetInfo{i, x, y, z, extraBytes})
	}

	fmt.Printf("Total B803 packets with valid coords: %d\n\n", len(b803Packets))

	// Analyze bytes after coordinates (offset +20 from marker, +12 from coords start)
	fmt.Printf("Analyzing bytes AFTER coordinates (offset +20-24 from marker):\n")
	fmt.Printf("Top values at offset +20 (4 bytes):\n")
	type kv struct {
		k uint32
		v int
	}
	var sorted []kv
	for k, v := range byByte20 {
		sorted = append(sorted, kv{k, v})
	}
	// Sort by count descending
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for i := 0; i < 20 && i < len(sorted); i++ {
		fmt.Printf("  0x%08X: %d packets\n", sorted[i].k, sorted[i].v)
	}

	// Now look at bytes BEFORE the type (offset -4 to -1 from marker)
	fmt.Printf("\nAnalyzing bytes BEFORE marker (potential entity ID):\n")
	byPre4 := make(map[uint32]int)
	for i := 0; i <= len(decompressed)-len(marker)-30; i++ {
		if !bytes.Equal(decompressed[i:i+len(marker)], marker) {
			continue
		}
		typeBytes := decompressed[i+6 : i+8]
		if typeBytes[0] != 0xB8 || typeBytes[1] != 0x03 {
			continue
		}
		if i >= 4 {
			pre4 := binary.LittleEndian.Uint32(decompressed[i-4 : i])
			byPre4[pre4]++
		}
	}
	
	fmt.Printf("Top values at offset -4 (4 bytes before marker):\n")
	sorted = nil
	for k, v := range byPre4 {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for i := 0; i < 20 && i < len(sorted); i++ {
		fmt.Printf("  0x%08X: %d packets\n", sorted[i].k, sorted[i].v)
	}

	// Print first 10 raw packets
	fmt.Printf("\nFirst 10 B803 packets (raw hex dump):\n")
	for i := 0; i < 10 && i < len(b803Packets); i++ {
		p := b803Packets[i]
		fmt.Printf("  [%d] offset=0x%X coords=(%.2f, %.2f, %.2f)\n", i, p.offset, p.x, p.y, p.z)
		fmt.Printf("       extra bytes: %02X\n", p.extraBytes)
	}

	// Group by the 4 bytes after coordinates (bytes 12-15 of extra)
	fmt.Printf("\nGrouping by bytes AFTER coordinates (potential player ID):\n")
	byAfterCoords := make(map[uint32]int)
	for _, p := range b803Packets {
		if len(p.extraBytes) >= 16 {
			afterCoords := binary.LittleEndian.Uint32(p.extraBytes[12:16])
			byAfterCoords[afterCoords]++
		}
	}
	
	var sortedAfter []kv
	for k, v := range byAfterCoords {
		sortedAfter = append(sortedAfter, kv{k, v})
	}
	for i := 0; i < len(sortedAfter)-1; i++ {
		for j := i + 1; j < len(sortedAfter); j++ {
			if sortedAfter[j].v > sortedAfter[i].v {
				sortedAfter[i], sortedAfter[j] = sortedAfter[j], sortedAfter[i]
			}
		}
	}
	for i := 0; i < 15 && i < len(sortedAfter); i++ {
		fmt.Printf("  0x%08X: %d packets\n", sortedAfter[i].k, sortedAfter[i].v)
	}

	// Also check bytes 16-19
	fmt.Printf("\nGrouping by bytes 16-19 of extra:\n")
	byBytes16 := make(map[uint32]int)
	for _, p := range b803Packets {
		if len(p.extraBytes) >= 20 {
			val := binary.LittleEndian.Uint32(p.extraBytes[16:20])
			byBytes16[val]++
		}
	}
	
	var sortedBytes16 []kv
	for k, v := range byBytes16 {
		sortedBytes16 = append(sortedBytes16, kv{k, v})
	}
	for i := 0; i < len(sortedBytes16)-1; i++ {
		for j := i + 1; j < len(sortedBytes16); j++ {
			if sortedBytes16[j].v > sortedBytes16[i].v {
				sortedBytes16[i], sortedBytes16[j] = sortedBytes16[j], sortedBytes16[i]
			}
		}
	}
	for i := 0; i < 15 && i < len(sortedBytes16); i++ {
		fmt.Printf("  0x%08X: %d packets\n", sortedBytes16[i].k, sortedBytes16[i].v)
	}
}

func decompress(data []byte) []byte {
	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	zstdReader, _ := zstd.NewReader(nil)
	result := make([]byte, 0)

	i := 0
	for i < len(data) {
		found := -1
		for j := i; j <= len(data)-4; j++ {
			if bytes.Equal(data[j:j+4], zstdMagic) {
				found = j
				break
			}
		}
		if found < 0 {
			break
		}

		reader := bytes.NewReader(data[found:])
		if err := zstdReader.Reset(reader); err != nil {
			i = found + 1
			continue
		}
		chunk, err := io.ReadAll(zstdReader)
		if err != nil && len(chunk) == 0 {
			i = found + 1
			continue
		}
		result = append(result, chunk...)
		i = found + len(data) - reader.Len()
	}

	return result
}

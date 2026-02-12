package main

import (
	"bytes"
	"fmt"
	"io"
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

	// Count exact patterns
	patterns := map[string][]byte{
		"607385fe (base marker)":     {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe},
		"607385fe + B803":            {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xB8, 0x03},
		"607385fe + B801":            {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xB8, 0x01},
		"607385fe + B001":            {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xB0, 0x01},
		"607385fe + B003":            {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xB0, 0x03},
		"607385fe + BC01":            {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xBC, 0x01},
		"607385fe + BC03":            {0x00, 0x00, 0x60, 0x73, 0x85, 0xfe, 0xBC, 0x03},
		"627385fe (spectator cam)":   {0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe},
	}

	for name, pattern := range patterns {
		count := countPattern(decompressed, pattern)
		fmt.Printf("%s: %d occurrences\n", name, count)
	}

	// Now count all 607385fe + XX YY patterns where YY is 01 or 03
	fmt.Printf("\nAll 607385fe + type patterns (YY=01 or 03):\n")
	baseMarker := []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	typeCounts := make(map[uint16]int)
	
	for i := 0; i <= len(decompressed)-8; i++ {
		if bytes.Equal(decompressed[i:i+6], baseMarker) {
			typeFirst := decompressed[i+6]
			typeSecond := decompressed[i+7]
			if typeSecond == 0x01 || typeSecond == 0x03 {
				typeCode := uint16(typeFirst)<<8 | uint16(typeSecond)
				typeCounts[typeCode]++
			}
		}
	}

	// Sort and print
	type kv struct {
		k uint16
		v int
	}
	var sorted []kv
	for k, v := range typeCounts {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	
	total := 0
	for _, s := range sorted {
		fmt.Printf("  Type 0x%04X: %d\n", s.k, s.v)
		total += s.v
	}
	fmt.Printf("  TOTAL: %d\n", total)
}

func countPattern(data []byte, pattern []byte) int {
	count := 0
	for i := 0; i <= len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			count++
		}
	}
	return count
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

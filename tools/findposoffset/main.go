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

	// Read and decompress
	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	decompressed := decompress(data)
	fmt.Printf("Decompressed size: %d bytes\n", len(decompressed))

	// Look for player position marker: 00 00 60 73 85 fe
	marker := []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

	// Find first few occurrences and analyze
	count := 0
	for i := 0; i <= len(decompressed)-len(marker)-50 && count < 30; i++ {
		if bytes.Equal(decompressed[i:i+len(marker)], marker) {
			count++

			// Read type bytes
			typeBytes := decompressed[i+6 : i+8]
			playerType := int(typeBytes[0])<<8 | int(typeBytes[1])

			// Only look at types ending in 01 or 03 (position types)
			if typeBytes[1] != 0x01 && typeBytes[1] != 0x03 {
				count-- // Don't count rotation types
				continue
			}

			fmt.Printf("\n=== Match #%d at offset 0x%X ===\n", count, i)
			fmt.Printf("Type: 0x%04X (bytes: %02X %02X)\n", playerType, typeBytes[0], typeBytes[1])

			// Dump next 60 bytes as hex
			end := i + 60
			if end > len(decompressed) {
				end = len(decompressed)
			}
			fmt.Printf("Raw bytes after marker:\n")
			for j := i + 6; j < end; j += 16 {
				lineEnd := j + 16
				if lineEnd > end {
					lineEnd = end
				}
				fmt.Printf("  +%02d: ", j-i-6)
				for k := j; k < lineEnd; k++ {
					fmt.Printf("%02X ", decompressed[k])
				}
				fmt.Println()
			}

			// Try different offsets to find coordinates
			fmt.Printf("\nTrying different offsets for floats:\n")
			for offset := 8; offset <= 40; offset += 4 {
				pos := i + offset
				if pos+12 > len(decompressed) {
					continue
				}
				x := math.Float32frombits(binary.LittleEndian.Uint32(decompressed[pos : pos+4]))
				y := math.Float32frombits(binary.LittleEndian.Uint32(decompressed[pos+4 : pos+8]))
				z := math.Float32frombits(binary.LittleEndian.Uint32(decompressed[pos+8 : pos+12]))

				// Check if these look like world coordinates
				isWorld := isWorldCoord(x) && isWorldCoord(y) && isWorldCoord(z)
				marker := ""
				if isWorld && hasValidZ(z) && hasSignificantXY(x, y) {
					marker = " <-- LIKELY WORLD COORDS"
				}
				fmt.Printf("  Offset +%d: X=%.2f Y=%.2f Z=%.2f%s\n", offset, x, y, z, marker)
			}
		}
	}
	fmt.Printf("\nTotal position-type packets found: %d\n", count)
}

func isWorldCoord(f float32) bool {
	if f != f { // NaN
		return false
	}
	return f >= -100 && f <= 100
}

func hasValidZ(z float32) bool {
	return z >= -5 && z <= 15
}

func hasSignificantXY(x, y float32) bool {
	ax := x
	ay := y
	if ax < 0 {
		ax = -ax
	}
	if ay < 0 {
		ay = -ay
	}
	return ax > 1 || ay > 1
}

func decompress(data []byte) []byte {
	// Find header end and decompress chunks
	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	zstdReader, _ := zstd.NewReader(nil)
	result := make([]byte, 0)

	i := 0
	for i < len(data) {
		// Find next zstd magic
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

		// Try to decompress from this point
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

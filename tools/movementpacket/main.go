package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/klauspost/compress/zstd"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: movementpacket <replay.rec> [num_packets]")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	// Decompress
	data, err := decompressReplay(f)
	if err != nil {
		fmt.Println("Error decompressing:", err)
		os.Exit(1)
	}

	fmt.Printf("Decompressed size: %d bytes\n\n", len(data))

	// Find movement packets
	numToShow := 20
	if len(os.Args) >= 3 {
		fmt.Sscanf(os.Args[2], "%d", &numToShow)
	}

	shown := 0
	uniqueTypes := make(map[string]int)

	// Also look at what comes BEFORE the marker
	for i := 0; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6 // After marker

		// Read type bytes
		if pos+2 > len(data) {
			continue
		}
		typeFirst := data[pos]
		typeSecond := data[pos+1]
		pos += 2

		// Only process B0xx, B8xx etc with 01 or 03 suffix
		if typeSecond != 0x01 && typeSecond != 0x03 {
			continue
		}
		if typeFirst < 0xB0 {
			continue
		}

		typeKey := fmt.Sprintf("%02x%02x", typeFirst, typeSecond)
		uniqueTypes[typeKey]++

		if shown >= numToShow {
			continue
		}

		// Read coordinates
		if pos+12 > len(data) {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+8 : pos+12]))
		pos += 12

		// Check valid coords
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		shown++
		fmt.Printf("=== MOVEMENT PACKET #%d (offset %d) ===\n", shown, i)

		// Show bytes BEFORE the marker
		preStart := i - 20
		if preStart < 0 {
			preStart = 0
		}
		fmt.Printf("Pre-marker bytes (20 before):\n")
		fmt.Printf("  %x\n", data[preStart:i])

		// Interpret pre-marker bytes as potential IDs
		if i >= 4 {
			preID := binary.LittleEndian.Uint32(data[i-4 : i])
			fmt.Printf("  Last 4 bytes as uint32: %d (0x%08x)\n", preID, preID)
		}

		fmt.Printf("Type: 0x%02x 0x%02x\n", typeFirst, typeSecond)
		fmt.Printf("Position: (%.2f, %.2f, %.2f)\n", x, y, z)

		// Read more bytes after coordinates
		if pos+80 > len(data) {
			continue
		}
		postBytes := data[pos : pos+80]
		fmt.Printf("Post-coord bytes (80 bytes):\n")

		// Show in rows of 16
		for j := 0; j < len(postBytes); j += 16 {
			end := j + 16
			if end > len(postBytes) {
				end = len(postBytes)
			}
			fmt.Printf("  %02d-%02d: %x\n", j, end-1, postBytes[j:end])
		}

		// Try to identify any ID-like values
		fmt.Printf("Potential IDs in post-coord:\n")
		for j := 0; j+4 <= 40; j++ {
			val := binary.LittleEndian.Uint32(postBytes[j : j+4])
			if val > 0 && val < 1000 {
				fmt.Printf("  Offset %d: uint32=%d\n", j, val)
			}
		}

		fmt.Println()
	}

	fmt.Printf("=== UNIQUE PACKET TYPES ===\n")
	for t, count := range uniqueTypes {
		fmt.Printf("  %s: %d packets\n", t, count)
	}
}

func decompressReplay(f *os.File) ([]byte, error) {
	br := bufio.NewReader(f)
	temp, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}

	// Check for chunked compression
	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	isChunked := false
	for i := 0; i < len(temp)-4; i++ {
		if bytes.Equal(temp[i:i+4], zstdMagic) {
			for j := i + 100; j < len(temp)-4; j++ {
				if bytes.Equal(temp[j:j+4], zstdMagic) {
					isChunked = true
					break
				}
			}
			break
		}
	}

	if isChunked {
		zstdReader, _ := zstd.NewReader(nil)
		var result []byte
		offset := 0
		for {
			found := false
			for ; offset < len(temp)-4; offset++ {
				if bytes.Equal(temp[offset:offset+4], zstdMagic) {
					found = true
					break
				}
			}
			if !found {
				break
			}

			chunkReader := bytes.NewReader(temp[offset:])
			if err := zstdReader.Reset(chunkReader); err != nil {
				offset++
				continue
			}
			chunk, err := io.ReadAll(zstdReader)
			if err != nil && !errors.Is(err, zstd.ErrMagicMismatch) {
				if len(chunk) == 0 {
					offset++
					continue
				}
			}
			result = append(result, chunk...)
			offset += 4
		}
		return result, nil
	} else {
		f.Seek(0, 0)
		zstdReader, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(zstdReader)
	}
}

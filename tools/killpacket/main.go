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

var matchFeedbackPattern = []byte{0x59, 0x34, 0xE5, 0x8B, 0x04}
var killIndicator = []byte{0x22, 0xd9, 0x13, 0x3c, 0xba}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: killpacket <replay.rec>")
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

	// Find all match feedback patterns
	offsets := findPatternOffsets(data, matchFeedbackPattern)
	fmt.Printf("Found %d match feedback patterns\n\n", len(offsets))

	for i, offset := range offsets {
		// Read the data after the pattern
		pos := offset + len(matchFeedbackPattern)

		// Version-dependent skip (simplified - assuming Y9S1+)
		pos += 38

		// Read size
		if pos >= len(data) {
			continue
		}
		size := int(data[pos])
		pos++

		if size != 0 {
			// Not a kill packet
			continue
		}

		// Read kill trace (5 bytes)
		if pos+5 > len(data) {
			continue
		}
		killTrace := data[pos : pos+5]
		if !bytes.Equal(killTrace, killIndicator) {
			continue
		}
		pos += 5

		fmt.Printf("=== KILL PACKET #%d (offset %d) ===\n", i+1, offset)

		// Read killer username
		if pos >= len(data) {
			continue
		}
		usernameLen := int(data[pos])
		pos++
		if pos+usernameLen > len(data) {
			continue
		}
		killer := string(data[pos : pos+usernameLen])
		pos += usernameLen

		fmt.Printf("Killer: %s\n", killer)

		// Read the 15 unknown bytes
		if pos+15 > len(data) {
			continue
		}
		unknown15 := data[pos : pos+15]
		pos += 15

		fmt.Printf("15 unknown bytes: %v\n", unknown15)
		fmt.Printf("  As hex: %x\n", unknown15)

		// Try interpreting as floats
		if len(unknown15) >= 12 {
			f1 := math.Float32frombits(binary.LittleEndian.Uint32(unknown15[0:4]))
			f2 := math.Float32frombits(binary.LittleEndian.Uint32(unknown15[4:8]))
			f3 := math.Float32frombits(binary.LittleEndian.Uint32(unknown15[8:12]))
			fmt.Printf("  As 3 floats: %.2f, %.2f, %.2f\n", f1, f2, f3)
		}

		// Read target username
		if pos >= len(data) {
			continue
		}
		targetLen := int(data[pos])
		pos++
		if pos+targetLen > len(data) {
			continue
		}
		target := string(data[pos : pos+targetLen])
		pos += targetLen

		fmt.Printf("Target: %s\n", target)

		// Read the 56 unknown bytes
		if pos+56 > len(data) {
			continue
		}
		unknown56 := data[pos : pos+56]
		pos += 56

		fmt.Printf("56 unknown bytes:\n")
		fmt.Printf("  Raw: %v\n", unknown56)
		fmt.Printf("  Hex: %x\n", unknown56)

		// Try interpreting as floats (could be positions, etc.)
		fmt.Printf("  As floats:\n")
		for j := 0; j+4 <= len(unknown56); j += 4 {
			f := math.Float32frombits(binary.LittleEndian.Uint32(unknown56[j : j+4]))
			if !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) && f >= -1000 && f <= 1000 {
				fmt.Printf("    [%d-%d]: %.3f\n", j, j+3, f)
			}
		}

		// Read headshot
		if pos >= len(data) {
			continue
		}
		headshot := data[pos]
		fmt.Printf("Headshot: %d\n", headshot)

		fmt.Println()
	}
}

func findPatternOffsets(data []byte, pattern []byte) []int {
	var offsets []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		if bytes.Equal(data[i:i+len(pattern)], pattern) {
			offsets = append(offsets, i)
		}
	}
	return offsets
}

func decompressReplay(f *os.File) ([]byte, error) {
	br := bufio.NewReader(f)
	temp, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}

	// Check for chunked compression (Y8S4+)
	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	isChunked := false
	for i := 0; i < len(temp)-4; i++ {
		if bytes.Equal(temp[i:i+4], zstdMagic) {
			// Check if there's another zstd magic after this
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
		// Chunked decompression
		zstdReader, _ := zstd.NewReader(nil)
		var result []byte
		offset := 0
		for {
			// Find next zstd magic
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

			// Decompress this chunk
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
			offset += 4 // Move past magic
		}
		return result, nil
	} else {
		// Single block decompression
		f.Seek(0, 0)
		zstdReader, err := zstd.NewReader(f)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(zstdReader)
	}
}

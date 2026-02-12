package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dumpreplay <replay.rec> <output.bin>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Read all file data
	fileData, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File size: %d bytes\n", len(fileData))

	// Find and decompress zstd sections (same logic as dissect reader)
	zstdMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	zstdReader, _ := zstd.NewReader(nil)
	
	var decompressed []byte
	offset := 0
	sections := 0

	for offset < len(fileData) {
		// Find next zstd magic
		idx := bytes.Index(fileData[offset:], zstdMagic)
		if idx == -1 {
			break
		}
		
		offset += idx
		sections++
		
		// Try to decompress from this point
		memReader := bytes.NewReader(fileData[offset:])
		if err := zstdReader.Reset(memReader); err != nil {
			offset += 4
			continue
		}
		
		chunk, err := io.ReadAll(zstdReader)
		if err != nil && !(len(chunk) > 0 && errors.Is(err, zstd.ErrMagicMismatch)) {
			offset += 4
			continue
		}
		
		decompressed = append(decompressed, chunk...)
		
		// Move past this section (approximate - read position from memReader)
		remaining := memReader.Len()
		offset = len(fileData) - remaining
	}

	fmt.Printf("Found %d zstd sections\n", sections)
	fmt.Printf("Decompressed size: %d bytes\n", len(decompressed))

	// Write to output file
	if err := os.WriteFile(os.Args[2], decompressed, 0644); err != nil {
		fmt.Printf("Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Written to %s\n", os.Args[2])
}

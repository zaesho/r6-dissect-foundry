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
	"sort"

	"github.com/klauspost/compress/zstd"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

type packetInfo struct {
	offset   int
	preBytes []byte // 16 bytes before marker
	x, y, z  float32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: movementid <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	data, err := decompressReplay(f)
	if err != nil {
		fmt.Println("Error decompressing:", err)
		os.Exit(1)
	}

	fmt.Printf("Decompressed size: %d bytes\n\n", len(data))

	// Collect packets grouped by pre-marker ID pattern
	idCounts := make(map[string][]packetInfo)

	for i := 16; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6

		// Read type bytes
		if pos+2 > len(data) {
			continue
		}
		typeFirst := data[pos]
		typeSecond := data[pos+1]
		pos += 2

		if typeSecond != 0x01 && typeSecond != 0x03 {
			continue
		}
		if typeFirst < 0xB0 {
			continue
		}

		// Read coordinates
		if pos+12 > len(data) {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+8 : pos+12]))

		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		// Get 16 bytes before marker
		preBytes := data[i-16 : i]
		
		// Use the last 8 bytes before marker as ID
		idKey := fmt.Sprintf("%x", data[i-8:i])
		
		idCounts[idKey] = append(idCounts[idKey], packetInfo{i, preBytes, x, y, z})
	}

	// Sort by count
	type idEntry struct {
		id     string
		count  int
		first  packetInfo
		last   packetInfo
	}
	var entries []idEntry
	for id, packets := range idCounts {
		entries = append(entries, idEntry{id, len(packets), packets[0], packets[len(packets)-1]})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	fmt.Println("=== TOP 15 PRE-MARKER IDs (8 bytes before marker) ===")
	fmt.Printf("%-20s %8s %30s %30s\n", "ID (hex)", "Count", "First Position", "Last Position")
	fmt.Println(strings.Repeat("-", 100))

	for i, e := range entries {
		if i >= 15 {
			break
		}
		firstPos := fmt.Sprintf("(%.1f, %.1f, %.1f)", e.first.x, e.first.y, e.first.z)
		lastPos := fmt.Sprintf("(%.1f, %.1f, %.1f)", e.last.x, e.last.y, e.last.z)
		fmt.Printf("%-20s %8d %30s %30s\n", e.id, e.count, firstPos, lastPos)
	}

	// Now let's try different offsets to find the player ID
	fmt.Println("\n=== TRYING DIFFERENT ID OFFSETS ===")
	
	for offset := -4; offset >= -20; offset -= 4 {
		idCounts2 := make(map[uint32]int)
		
		for i := 20; i < len(data)-100; i++ {
			if !bytes.Equal(data[i:i+6], movementMarker) {
				continue
			}

			pos := i + 6
			if pos+2 > len(data) {
				continue
			}
			typeFirst := data[pos]
			typeSecond := data[pos+1]
			if typeSecond != 0x01 && typeSecond != 0x03 {
				continue
			}
			if typeFirst < 0xB0 {
				continue
			}
			pos += 2

			if pos+12 > len(data) {
				continue
			}
			x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if math.IsNaN(float64(x)) || x < -100 || x > 100 {
				continue
			}

			if i+offset < 0 {
				continue
			}
			id := binary.LittleEndian.Uint32(data[i+offset : i+offset+4])
			idCounts2[id]++
		}

		// Count unique IDs with significant packets
		var significant int
		for _, count := range idCounts2 {
			if count > 100 {
				significant++
			}
		}
		
		fmt.Printf("Offset %d: %d unique IDs with >100 packets\n", offset, significant)
	}

	// Look specifically at offsets in post-coordinates for player ID
	fmt.Println("\n=== CHECKING POST-COORDINATE BYTES FOR PLAYER ID ===")
	
	postIDCounts := make(map[int]map[uint32]int)
	for testOffset := 0; testOffset < 40; testOffset += 4 {
		postIDCounts[testOffset] = make(map[uint32]int)
	}

	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if pos+2 > len(data) {
			continue
		}
		typeFirst := data[pos]
		typeSecond := data[pos+1]
		if typeSecond != 0x01 && typeSecond != 0x03 {
			continue
		}
		if typeFirst < 0xB0 {
			continue
		}
		pos += 2

		if pos+12 > len(data) {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}
		pos += 12 // Skip coordinates

		if pos+40 > len(data) {
			continue
		}

		for testOffset := 0; testOffset < 40; testOffset += 4 {
			id := binary.LittleEndian.Uint32(data[pos+testOffset : pos+testOffset+4])
			postIDCounts[testOffset][id]++
		}
	}

	for testOffset := 0; testOffset < 40; testOffset += 4 {
		var significant int
		for _, count := range postIDCounts[testOffset] {
			if count > 100 {
				significant++
			}
		}
		if significant >= 5 && significant <= 15 {
			fmt.Printf("Post-coord offset %d: %d unique IDs with >100 packets (could be player ID!)\n", testOffset, significant)
		}
	}
}

var strings = struct{ Repeat func(string, int) string }{
	Repeat: func(s string, n int) string {
		result := ""
		for i := 0; i < n; i++ {
			result += s
		}
		return result
	},
}

func decompressReplay(f *os.File) ([]byte, error) {
	br := bufio.NewReader(f)
	temp, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}

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

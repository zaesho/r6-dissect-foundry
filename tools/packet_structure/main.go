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
	"github.com/redraskal/r6-dissect/dissect"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: packet_structure <replay.rec>")
		os.Exit(1)
	}

	// Get player info
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	r, _ := dissect.NewReader(f)
	r.Read()
	f.Close()

	fmt.Println("=== PLAYERS ===")
	players := make([]string, len(r.Header.Players))
	for i, p := range r.Header.Players {
		players[i] = p.Username
		fmt.Printf("  [%d] -> PlayerID %d: %s\n", i, i+5, p.Username)
	}

	// Scan raw data
	f, _ = os.Open(os.Args[1])
	defer f.Close()
	data, _ := decompressReplay(f)

	fmt.Println("\n=== TYPE 0x03 PACKET STRUCTURE ===")
	fmt.Println("Examining first 10 type 0x03 packets in detail...\n")

	count := 0
	for i := 20; i < len(data)-100 && count < 10; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if data[pos+1] != 0x03 || data[pos] < 0xB0 {
			continue
		}

		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		count++
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		fmt.Printf("Packet %d at offset %d:\n", count, i)
		fmt.Printf("  Entity ID (before marker): 0x%08x\n", entityID)
		fmt.Printf("  Type bytes: %02x %02x\n", data[pos], data[pos+1])
		
		// Coordinates
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+6 : pos+10]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+10 : pos+14]))
		fmt.Printf("  Coords (offset +2): X=%.2f Y=%.2f Z=%.2f\n", x, y, z)

		// Show bytes after coordinates
		postStart := pos + 14
		fmt.Printf("  Post-coordinate bytes (offset +14):\n")
		
		// Try different offsets for player ID
		for offset := 0; offset <= 24; offset += 4 {
			if postStart+offset+4 <= len(data) {
				val := binary.LittleEndian.Uint32(data[postStart+offset : postStart+offset+4])
				playerGuess := "?"
				if val >= 5 && val <= 14 && int(val-5) < len(players) {
					playerGuess = players[val-5]
				}
				fmt.Printf("    [+%d]: 0x%08x (%d) %s\n", offset, val, val, playerGuess)
			}
		}
		fmt.Println()
	}

	// Also check type 0x01 packets
	fmt.Println("\n=== TYPE 0x01 PACKET STRUCTURE ===")
	fmt.Println("Examining first 10 type 0x01 packets in detail...\n")

	count = 0
	for i := 20; i < len(data)-100 && count < 10; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}

		pos := i + 6
		if data[pos+1] != 0x01 || data[pos] < 0xB0 {
			continue
		}

		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		count++
		entityID := binary.LittleEndian.Uint32(data[i-4 : i])

		fmt.Printf("Packet %d at offset %d:\n", count, i)
		fmt.Printf("  Entity ID (before marker): 0x%08x\n", entityID)
		fmt.Printf("  Type bytes: %02x %02x\n", data[pos], data[pos+1])

		// Coordinates
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+6 : pos+10]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+10 : pos+14]))
		fmt.Printf("  Coords (offset +2): X=%.2f Y=%.2f Z=%.2f\n", x, y, z)

		// Show bytes after coordinates
		postStart := pos + 14
		fmt.Printf("  Post-coordinate bytes (offset +14):\n")

		for offset := 0; offset <= 24; offset += 4 {
			if postStart+offset+4 <= len(data) {
				val := binary.LittleEndian.Uint32(data[postStart+offset : postStart+offset+4])
				playerGuess := "?"
				if val >= 5 && val <= 14 && int(val-5) < len(players) {
					playerGuess = players[val-5]
				}
				fmt.Printf("    [+%d]: 0x%08x (%d) %s\n", offset, val, val, playerGuess)
			}
		}
		fmt.Println()
	}

	// Summary: count player IDs at offset +20 for type 0x03
	fmt.Println("\n=== VERIFICATION: Player ID at offset +20 in type 0x03 ===")
	playerCounts := make(map[uint32]int)
	
	for i := 20; i < len(data)-100; i++ {
		if !bytes.Equal(data[i:i+6], movementMarker) {
			continue
		}
		pos := i + 6
		if data[pos+1] != 0x03 || data[pos] < 0xB0 {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+2 : pos+6]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}
		
		// Player ID at post-coord offset +20
		playerIDOffset := pos + 14 + 20
		if playerIDOffset+4 <= len(data) {
			playerID := binary.LittleEndian.Uint32(data[playerIDOffset : playerIDOffset+4])
			playerCounts[playerID]++
		}
	}

	fmt.Printf("%-12s %8s %-20s\n", "PlayerID", "Count", "Mapped Player")
	for id, count := range playerCounts {
		if count < 50 {
			continue
		}
		player := "?"
		if id >= 5 && int(id-5) < len(players) {
			player = players[id-5]
		}
		fmt.Printf("%-12d %8d %-20s\n", id, count, player)
	}
}

func decompressReplay(f *os.File) ([]byte, error) {
	br := bufio.NewReader(f)
	temp, _ := io.ReadAll(br)

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
		zstdReader, _ := zstd.NewReader(f)
		return io.ReadAll(zstdReader)
	}
}

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
	"github.com/redraskal/r6-dissect/dissect"
)

var movementMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: movementid2 <replay.rec>")
		os.Exit(1)
	}

	// First, read the replay with dissect to get player info
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	if err := r.Read(); err != nil && err.Error() != "EOF" {
		fmt.Println("Error reading:", err)
	}
	f.Close()

	fmt.Println("=== PLAYER IDS FROM HEADER ===")
	for i, p := range r.Header.Players {
		teamRole := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "ATK"
			} else {
				teamRole = "DEF"
			}
		}
		fmt.Printf("[%d] %s (%s) - DissectID: %x, ID: %d, uiID: %d\n", 
			i, p.Username, teamRole, p.DissectID, p.ID, 0) // Note: uiID is private
	}

	// Now manually analyze the raw data
	f, err = os.Open(os.Args[1])
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

	// Analyze post-coord offset 8 (the 5 unique IDs)
	fmt.Println("\n=== ANALYZING POST-COORD OFFSET 8 ===")
	
	type idInfo struct {
		id     uint32
		count  int
		firstX float32
		firstY float32
		firstZ float32
		lastX  float32
		lastY  float32
		lastZ  float32
	}
	
	idData := make(map[uint32]*idInfo)

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
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+8 : pos+12]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}
		pos += 12

		if pos+12 > len(data) {
			continue
		}

		// Read ID at offset 8 from post-coordinates
		id := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
		
		if idData[id] == nil {
			idData[id] = &idInfo{id: id, firstX: x, firstY: y, firstZ: z}
		}
		idData[id].count++
		idData[id].lastX = x
		idData[id].lastY = y
		idData[id].lastZ = z
	}

	var entries []*idInfo
	for _, info := range idData {
		entries = append(entries, info)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	fmt.Printf("\n%-12s %8s %25s %25s\n", "ID", "Count", "First Pos", "Last Pos")
	for _, e := range entries {
		if e.count > 50 {
			fmt.Printf("0x%08x %8d  (%6.1f,%6.1f,%6.1f)  (%6.1f,%6.1f,%6.1f)\n", 
				e.id, e.count, e.firstX, e.firstY, e.firstZ, e.lastX, e.lastY, e.lastZ)
		}
	}

	// Also look at the last 4 bytes before the marker
	fmt.Println("\n=== ANALYZING LAST 4 BYTES BEFORE MARKER ===")
	
	preIdData := make(map[uint32]*idInfo)

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
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[pos+8 : pos+12]))
		if math.IsNaN(float64(x)) || x < -100 || x > 100 {
			continue
		}

		// Read last 4 bytes before marker
		id := binary.LittleEndian.Uint32(data[i-4 : i])
		
		if preIdData[id] == nil {
			preIdData[id] = &idInfo{id: id, firstX: x, firstY: y, firstZ: z}
		}
		preIdData[id].count++
		preIdData[id].lastX = x
		preIdData[id].lastY = y
		preIdData[id].lastZ = z
	}

	var preEntries []*idInfo
	for _, info := range preIdData {
		preEntries = append(preEntries, info)
	}
	sort.Slice(preEntries, func(i, j int) bool {
		return preEntries[i].count > preEntries[j].count
	})

	fmt.Printf("\n%-12s %8s %25s %25s\n", "ID", "Count", "First Pos", "Last Pos")
	count := 0
	for _, e := range preEntries {
		if e.count > 100 {
			fmt.Printf("0x%08x %8d  (%6.1f,%6.1f,%6.1f)  (%6.1f,%6.1f,%6.1f)\n", 
				e.id, e.count, e.firstX, e.firstY, e.firstZ, e.lastX, e.lastY, e.lastZ)
			count++
			if count >= 15 {
				break
			}
		}
	}
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

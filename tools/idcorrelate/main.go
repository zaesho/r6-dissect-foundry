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

type trackData struct {
	id        uint32
	positions []pos
}

type pos struct {
	x, y, z float32
	time    int // packet sequence
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: idcorrelate <replay.rec>")
		os.Exit(1)
	}

	// First, read with dissect
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

	// Print player info
	fmt.Println("=== PLAYERS ===")
	playersByTeam := map[string][]dissect.Player{
		"Defense": {},
		"Attack":  {},
	}
	for _, p := range r.Header.Players {
		teamRole := "Unknown"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				teamRole = "Attack"
			} else {
				teamRole = "Defense"
			}
		}
		playersByTeam[teamRole] = append(playersByTeam[teamRole], p)
		// Extract the first byte of DissectID as potential match
		if len(p.DissectID) >= 1 {
			fmt.Printf("%s (%s): DissectID=%x, first byte=%02x\n", 
				p.Username, teamRole, p.DissectID, p.DissectID[0])
		}
	}

	// Get death times
	deathTimes := make(map[string]float64)
	for _, event := range r.MatchFeedback {
		if event.Type == dissect.Kill && event.Target != "" {
			deathTimes[event.Target] = 45.0 + (180.0 - event.TimeInSeconds)
		}
	}

	fmt.Println("\n=== DEATH TIMES ===")
	for name, t := range deathTimes {
		fmt.Printf("%s died at %.0fs\n", name, t)
	}

	// Now analyze raw data
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

	// Build tracks by pre-marker ID
	tracks := make(map[uint32]*trackData)
	packetNum := 0

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

		// Read ID from last 4 bytes before marker
		id := binary.LittleEndian.Uint32(data[i-4 : i])
		packetNum++

		if tracks[id] == nil {
			tracks[id] = &trackData{id: id}
		}
		tracks[id].positions = append(tracks[id].positions, struct{ x, y, z float32; time int }{x, y, z, packetNum})
	}

	// Find total packet range for time normalization
	totalPackets := packetNum
	
	// Calculate last significant movement time for each track
	type trackInfo struct {
		id              uint32
		count           int
		lastSigMoveTime float64
		endTime         float64
		lastPos         pos
	}
	var infos []trackInfo

	for id, track := range tracks {
		if len(track.positions) < 100 {
			continue
		}

		var lastSigX, lastSigY, lastSigZ float32
		var lastSigMoveTime float64 = 0

		for i, p := range track.positions {
			posTime := float64(p.time) / float64(totalPackets) * 180.0 // rough estimate
			
			if i == 0 {
				lastSigX, lastSigY, lastSigZ = p.x, p.y, p.z
				lastSigMoveTime = posTime
			} else {
				dx := p.x - lastSigX
				dy := p.y - lastSigY
				dz := p.z - lastSigZ
				dist := float32(math.Sqrt(float64(dx*dx + dy*dy + dz*dz)))
				if dist > 0.5 {
					lastSigX, lastSigY, lastSigZ = p.x, p.y, p.z
					lastSigMoveTime = posTime
				}
			}
		}

		endTime := float64(track.positions[len(track.positions)-1].time) / float64(totalPackets) * 180.0
		lastP := track.positions[len(track.positions)-1]

		infos = append(infos, trackInfo{
			id:              id,
			count:           len(track.positions),
			lastSigMoveTime: lastSigMoveTime,
			endTime:         endTime,
			lastPos:         struct{ x, y, z float32; time int }{lastP.x, lastP.y, lastP.z, lastP.time},
		})
	}

	// Sort by packet count
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].count > infos[j].count
	})

	fmt.Println("\n=== TOP TRACKS BY PACKET COUNT ===")
	fmt.Printf("%-12s %8s %12s %12s %30s\n", "ID", "Count", "LastSigMove", "EndTime", "Last Position")
	for i, info := range infos {
		if i >= 15 {
			break
		}
		posStr := fmt.Sprintf("(%.1f, %.1f, %.1f)", info.lastPos.x, info.lastPos.y, info.lastPos.z)
		fmt.Printf("0x%08x %8d %12.1f %12.1f %30s\n", 
			info.id, info.count, info.lastSigMoveTime, info.endTime, posStr)
	}

	// Now try to match by correlating death time with lastSigMoveTime
	fmt.Println("\n=== DEATH TIME CORRELATION ===")
	for name, deathT := range deathTimes {
		fmt.Printf("\n%s died at %.0fs:\n", name, deathT)
		// Find tracks whose lastSigMoveTime is close to deathT
		type match struct {
			id   uint32
			diff float64
		}
		var matches []match
		for _, info := range infos {
			// Scale death time from 45-225 to 0-180 for comparison
			scaledDeathT := (deathT - 45) / 180 * 180
			diff := math.Abs(info.lastSigMoveTime - scaledDeathT)
			if diff < 15 {
				matches = append(matches, match{info.id, diff})
			}
		}
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].diff < matches[j].diff
		})
		for i, m := range matches {
			if i >= 3 {
				break
			}
			fmt.Printf("  ID 0x%08x: lastSigMove diff = %.1fs\n", m.id, m.diff)
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

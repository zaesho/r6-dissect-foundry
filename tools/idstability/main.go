package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type PacketRecord struct {
	PacketNum int
	Type2     byte
	X, Y, Z   float32
	ID4       uint32
	ID20      uint32
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: idstability <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	r.Listen(positionMarker, capturePacket)
	r.Read()

	fmt.Printf("Captured %d packets\n\n", len(allPackets))

	// Build tracks by position continuity
	tracks := buildTracks(allPackets, 1.5)
	fmt.Printf("Built %d tracks\n\n", len(tracks))

	// Analyze ID stability within each track
	fmt.Println("=== ID STABILITY ANALYSIS PER TRACK ===\n")
	
	for i, track := range tracks {
		if len(track) < 100 {
			continue
		}
		
		// Count IDs within this track
		id4Counts := make(map[uint32]int)
		id20Counts := make(map[uint32]int)
		
		for _, p := range track {
			if p.ID4 >= 1 && p.ID4 <= 20 {
				id4Counts[p.ID4]++
			}
			if p.ID20 >= 1 && p.ID20 <= 20 {
				id20Counts[p.ID20]++
			}
		}
		
		// Get first and last position
		first := track[0]
		last := track[len(track)-1]
		
		fmt.Printf("Track %d: %d packets, pos (%.1f,%.1f) -> (%.1f,%.1f)\n", 
			i+1, len(track), first.X, first.Y, last.X, last.Y)
		
		// Print ID distribution
		fmt.Printf("  ID@4 distribution: ")
		printIDDist(id4Counts, len(track))
		
		fmt.Printf("  ID@20 distribution: ")
		printIDDist(id20Counts, len(track))
		
		// Check if there's a dominant ID
		dom4, pct4 := getDominantID(id4Counts, len(track))
		dom20, pct20 := getDominantID(id20Counts, len(track))
		
		fmt.Printf("  Dominant ID@4: %d (%.1f%%), ID@20: %d (%.1f%%)\n", 
			dom4, pct4, dom20, pct20)
		fmt.Println()
	}

	// Cross-track analysis: which IDs appear in multiple tracks?
	fmt.Println("\n=== CROSS-TRACK ID ANALYSIS ===")
	analyzeIDsAcrossTracks(tracks)
}

func capturePacket(r *dissect.Reader) error {
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	type1 := typeBytes[0]
	type2 := typeBytes[1]

	if type1 < 0xB0 {
		return nil
	}

	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	postBytes, _ := r.Bytes(64)

	var id4, id20 uint32
	if len(postBytes) >= 8 {
		id4 = binary.LittleEndian.Uint32(postBytes[4:8])
	}
	if len(postBytes) >= 24 {
		id20 = binary.LittleEndian.Uint32(postBytes[20:24])
	}

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		ID4:       id4,
		ID20:      id20,
	})

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func buildTracks(packets []PacketRecord, threshold float32) [][]PacketRecord {
	type track struct {
		packets []PacketRecord
		lastX   float32
		lastY   float32
	}
	
	var tracks []*track
	
	for _, p := range packets {
		// Find nearest track
		var bestTrack *track
		var bestDist float32 = threshold + 1
		
		for _, t := range tracks {
			dx := p.X - t.lastX
			dy := p.Y - t.lastY
			dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
			if dist < bestDist {
				bestDist = dist
				bestTrack = t
			}
		}
		
		if bestTrack != nil && bestDist <= threshold {
			bestTrack.packets = append(bestTrack.packets, p)
			bestTrack.lastX = p.X
			bestTrack.lastY = p.Y
		} else {
			tracks = append(tracks, &track{
				packets: []PacketRecord{p},
				lastX:   p.X,
				lastY:   p.Y,
			})
		}
	}
	
	// Convert to result
	var result [][]PacketRecord
	for _, t := range tracks {
		result = append(result, t.packets)
	}
	
	// Sort by size
	sort.Slice(result, func(i, j int) bool {
		return len(result[i]) > len(result[j])
	})
	
	return result
}

func printIDDist(counts map[uint32]int, total int) {
	if len(counts) == 0 {
		fmt.Println("none")
		return
	}
	
	// Sort by count
	type idCount struct {
		id    uint32
		count int
	}
	var sorted []idCount
	for id, c := range counts {
		sorted = append(sorted, idCount{id, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	
	for i, ic := range sorted {
		if i >= 5 {
			fmt.Printf("...")
			break
		}
		pct := float64(ic.count) * 100 / float64(total)
		fmt.Printf("%d(%.0f%%) ", ic.id, pct)
	}
	fmt.Println()
}

func getDominantID(counts map[uint32]int, total int) (uint32, float64) {
	var maxID uint32
	var maxCount int
	
	for id, c := range counts {
		if c > maxCount {
			maxCount = c
			maxID = id
		}
	}
	
	if total == 0 {
		return 0, 0
	}
	return maxID, float64(maxCount) * 100 / float64(total)
}

func analyzeIDsAcrossTracks(tracks [][]PacketRecord) {
	// For each ID, count how many tracks it appears in
	id4TrackCounts := make(map[uint32]int)
	id20TrackCounts := make(map[uint32]int)
	
	for _, track := range tracks {
		if len(track) < 50 {
			continue
		}
		
		// Get unique IDs in this track
		id4Seen := make(map[uint32]bool)
		id20Seen := make(map[uint32]bool)
		
		for _, p := range track {
			if p.ID4 >= 1 && p.ID4 <= 20 {
				id4Seen[p.ID4] = true
			}
			if p.ID20 >= 1 && p.ID20 <= 20 {
				id20Seen[p.ID20] = true
			}
		}
		
		for id := range id4Seen {
			id4TrackCounts[id]++
		}
		for id := range id20Seen {
			id20TrackCounts[id]++
		}
	}
	
	fmt.Println("\nID@4 appearing in multiple tracks:")
	printTrackCounts(id4TrackCounts)
	
	fmt.Println("\nID@20 appearing in multiple tracks:")
	printTrackCounts(id20TrackCounts)
}

func printTrackCounts(counts map[uint32]int) {
	// Sort by ID
	var ids []uint32
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	
	for _, id := range ids {
		fmt.Printf("  ID %2d: appears in %d tracks\n", id, counts[id])
	}
}

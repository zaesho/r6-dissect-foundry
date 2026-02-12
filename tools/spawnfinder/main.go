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
	Type1     byte
	Type2     byte
	X, Y, Z   float32
	PostBytes []byte
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
	packetCounter  int
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: spawnfinder <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating reader: %v\n", err)
		os.Exit(1)
	}

	r.Listen(positionMarker, captureAllPackets)

	err = r.Read()
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("Captured %d total position packets\n\n", len(allPackets))

	// Find packets at spawn locations (Y > 40 or |X| > 40)
	fmt.Println("=== PACKETS AT SPAWN LOCATIONS ===")
	fmt.Println("Looking for packets with Y > 40 or |X| > 40 (attacker spawn areas)")
	
	spawnPackets := make([]PacketRecord, 0)
	for _, p := range allPackets {
		if p.Y > 40 || p.Y < -15 || p.X > 40 || p.X < -40 {
			spawnPackets = append(spawnPackets, p)
		}
	}
	
	fmt.Printf("Found %d packets in spawn areas\n\n", len(spawnPackets))

	if len(spawnPackets) > 0 {
		// Group by approximate position
		clusters := clusterByPosition(spawnPackets)
		
		fmt.Printf("Found %d spawn location clusters:\n\n", len(clusters))
		
		for i, cluster := range clusters {
			fmt.Printf("Cluster %d: %d packets\n", i+1, len(cluster))
			
			// Calculate average position
			var avgX, avgY float64
			for _, p := range cluster {
				avgX += float64(p.X)
				avgY += float64(p.Y)
			}
			avgX /= float64(len(cluster))
			avgY /= float64(len(cluster))
			
			fmt.Printf("  Average position: (%.1f, %.1f)\n", avgX, avgY)
			
			// Analyze IDs in this cluster
			analyzeClusterIDs(cluster)
			fmt.Println()
		}
	}

	// Look at the very first packets to understand initial state
	fmt.Println("\n=== FIRST 100 PACKETS (chronological) ===")
	n := min(100, len(allPackets))
	
	// Group by packet type
	typeGroups := make(map[string][]PacketRecord)
	for i := 0; i < n; i++ {
		p := allPackets[i]
		key := fmt.Sprintf("%02X_%02X", p.Type1, p.Type2)
		typeGroups[key] = append(typeGroups[key], p)
	}
	
	for typ, packets := range typeGroups {
		fmt.Printf("\nType %s: %d packets\n", typ, len(packets))
		for i, p := range packets {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(packets)-5)
				break
			}
			// Extract potential ID based on type
			var id1, id2 uint32
			if len(p.PostBytes) >= 8 {
				id1 = binary.LittleEndian.Uint32(p.PostBytes[4:8])
			}
			if len(p.PostBytes) >= 24 {
				id2 = binary.LittleEndian.Uint32(p.PostBytes[20:24])
			}
			fmt.Printf("  #%d: pos=(%.1f, %.1f, %.1f) id@4=%d id@20=%d\n", 
				p.PacketNum, p.X, p.Y, p.Z, id1, id2)
		}
	}

	// Look specifically at type 0x03 packets which have the most data
	fmt.Println("\n\n=== TYPE 0x03 PACKET DEEP ANALYSIS ===")
	analyzeType03Packets()
}

func captureAllPackets(r *dissect.Reader) error {
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

	allPackets = append(allPackets, PacketRecord{
		PacketNum: packetCounter,
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		PostBytes: postBytes,
	})
	packetCounter++

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func clusterByPosition(packets []PacketRecord) [][]PacketRecord {
	if len(packets) == 0 {
		return nil
	}

	// Simple clustering by rounding to nearest 10 units
	clusters := make(map[string][]PacketRecord)
	
	for _, p := range packets {
		key := fmt.Sprintf("%.0f_%.0f", math.Round(float64(p.X)/10)*10, math.Round(float64(p.Y)/10)*10)
		clusters[key] = append(clusters[key], p)
	}

	var result [][]PacketRecord
	for _, c := range clusters {
		result = append(result, c)
	}

	// Sort by size
	sort.Slice(result, func(i, j int) bool {
		return len(result[i]) > len(result[j])
	})

	return result
}

func analyzeClusterIDs(packets []PacketRecord) {
	// For each potential ID offset, see what IDs appear
	offsets := []int{4, 20}
	
	for _, offset := range offsets {
		idCounts := make(map[uint32]int)
		
		for _, p := range packets {
			if offset+4 <= len(p.PostBytes) {
				id := binary.LittleEndian.Uint32(p.PostBytes[offset : offset+4])
				if id >= 1 && id <= 50 {
					idCounts[id]++
				}
			}
		}

		if len(idCounts) > 0 && len(idCounts) <= 10 {
			fmt.Printf("  IDs at offset %d: ", offset)
			
			// Sort by count
			type idFreq struct {
				id   uint32
				freq int
			}
			var sorted []idFreq
			for id, c := range idCounts {
				sorted = append(sorted, idFreq{id, c})
			}
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].freq > sorted[j].freq
			})
			
			for _, v := range sorted {
				fmt.Printf("%d(%d) ", v.id, v.freq)
			}
			fmt.Println()
		}
	}
}

func analyzeType03Packets() {
	type03 := make([]PacketRecord, 0)
	for _, p := range allPackets {
		if p.Type2 == 0x03 {
			type03 = append(type03, p)
		}
	}

	fmt.Printf("Total type 0x03 packets: %d\n\n", len(type03))

	// Group by ID at offset 20
	idGroups := make(map[uint32][]PacketRecord)
	for _, p := range type03 {
		if len(p.PostBytes) >= 24 {
			id := binary.LittleEndian.Uint32(p.PostBytes[20:24])
			if id >= 1 && id <= 20 {
				idGroups[id] = append(idGroups[id], p)
			}
		}
	}

	fmt.Println("Position statistics per ID (from type 0x03 packets):")
	fmt.Printf("%-6s %-8s %-12s %-12s %-12s %-12s %-12s\n", 
		"ID", "Count", "MinX", "MaxX", "MinY", "MaxY", "AvgZ")
	fmt.Println("------------------------------------------------------------------------")

	// Sort IDs
	var ids []uint32
	for id := range idGroups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		packets := idGroups[id]
		if len(packets) < 10 {
			continue
		}

		var minX, maxX, minY, maxY float32 = 999, -999, 999, -999
		var sumZ float64

		for _, p := range packets {
			if p.X < minX { minX = p.X }
			if p.X > maxX { maxX = p.X }
			if p.Y < minY { minY = p.Y }
			if p.Y > maxY { maxY = p.Y }
			sumZ += float64(p.Z)
		}

		avgZ := sumZ / float64(len(packets))
		fmt.Printf("%-6d %-8d %-12.1f %-12.1f %-12.1f %-12.1f %-12.1f\n",
			id, len(packets), minX, maxX, minY, maxY, avgZ)
	}

	// Check if any ID has packets at spawn locations
	fmt.Println("\n\nIDs with packets at spawn locations (Y > 40 or |X| > 40):")
	for _, id := range ids {
		packets := idGroups[id]
		spawnCount := 0
		for _, p := range packets {
			if p.Y > 40 || p.Y < -15 || p.X > 40 || p.X < -40 {
				spawnCount++
			}
		}
		if spawnCount > 0 {
			fmt.Printf("  ID %d: %d spawn packets out of %d total\n", id, spawnCount, len(packets))
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

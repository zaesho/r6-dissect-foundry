package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

// Verify that positions for each player ID form coherent paths
// (not jumping all over the map randomly)

type packet struct {
	packetNum int
	playerID  int
	x, y, z   float32
}

var packets []packet
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
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

	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, capturePacket)
	r.Read()

	// Group by player
	playerPackets := make(map[int][]packet)
	for _, p := range packets {
		if p.playerID >= 5 && p.playerID <= 14 {
			playerPackets[p.playerID] = append(playerPackets[p.playerID], p)
		}
	}

	fmt.Printf("=== Path coherence check per player ===\n\n")

	var ids []int
	for id := range playerPackets {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	for _, id := range ids {
		pkts := playerPackets[id]
		if len(pkts) < 10 {
			fmt.Printf("Player %d: Only %d packets (not enough to analyze)\n", id, len(pkts))
			continue
		}

		// Calculate average distance between consecutive positions
		totalDist := float64(0)
		jumpCount := 0
		for i := 1; i < len(pkts); i++ {
			dx := pkts[i].x - pkts[i-1].x
			dy := pkts[i].y - pkts[i-1].y
			dz := pkts[i].z - pkts[i-1].z
			dist := math.Sqrt(float64(dx*dx + dy*dy + dz*dz))
			totalDist += dist
			if dist > 5.0 { // >5 units is a "jump"
				jumpCount++
			}
		}
		avgDist := totalDist / float64(len(pkts)-1)
		jumpPct := float64(jumpCount) / float64(len(pkts)-1) * 100

		// Calculate position variance
		var sumX, sumY float64
		for _, p := range pkts {
			sumX += float64(p.x)
			sumY += float64(p.y)
		}
		meanX := sumX / float64(len(pkts))
		meanY := sumY / float64(len(pkts))

		var varX, varY float64
		for _, p := range pkts {
			varX += (float64(p.x) - meanX) * (float64(p.x) - meanX)
			varY += (float64(p.y) - meanY) * (float64(p.y) - meanY)
		}
		stdX := math.Sqrt(varX / float64(len(pkts)))
		stdY := math.Sqrt(varY / float64(len(pkts)))

		fmt.Printf("Player %d (%d packets):\n", id, len(pkts))
		fmt.Printf("  Avg step distance: %.3f units\n", avgDist)
		fmt.Printf("  Jump count (>5 units): %d (%.1f%%)\n", jumpCount, jumpPct)
		fmt.Printf("  Position spread (std): X=%.1f, Y=%.1f\n", stdX, stdY)
		
		// Show first and last few positions
		fmt.Printf("  First 5 positions: ")
		for i := 0; i < 5 && i < len(pkts); i++ {
			fmt.Printf("(%.1f,%.1f) ", pkts[i].x, pkts[i].y)
		}
		fmt.Println()
		fmt.Printf("  Last 5 positions:  ")
		for i := len(pkts) - 5; i < len(pkts); i++ {
			if i >= 0 {
				fmt.Printf("(%.1f,%.1f) ", pkts[i].x, pkts[i].y)
			}
		}
		fmt.Println()
		fmt.Println()
	}

	// Header
	fmt.Printf("=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d) -> ID %d\n", i, p.Username, p.TeamIndex, i+5)
	}
}

func capturePacket(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	suffix := typeBytes[1]
	prefix := typeBytes[0]

	if (suffix != 0x01 && suffix != 0x03) || prefix < 0xB0 {
		return nil
	}

	x, err := r.Float32()
	if err != nil {
		return nil
	}
	y, err := r.Float32()
	if err != nil {
		return nil
	}
	z, err := r.Float32()
	if err != nil {
		return nil
	}

	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) {
		return nil
	}

	postBytes, err := r.Bytes(36)
	if err != nil {
		return nil
	}

	var playerID int
	if suffix == 0x01 {
		playerID = int(binary.LittleEndian.Uint32(postBytes[4:8]))
	} else {
		playerID = int(binary.LittleEndian.Uint32(postBytes[20:24]))
	}

	packets = append(packets, packet{
		packetNum: packetNum,
		playerID:  playerID,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

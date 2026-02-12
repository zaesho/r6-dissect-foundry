package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	packetNum int
	playerID  int
	suffix    byte
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

	// Separate by suffix type
	var type01, type03 []packet
	for _, p := range packets {
		if p.playerID >= 5 && p.playerID <= 14 {
			if p.suffix == 0x01 {
				type01 = append(type01, p)
			} else if p.suffix == 0x03 {
				type03 = append(type03, p)
			}
		}
	}

	fmt.Printf("=== 01-type path analysis ===\n\n")
	analyzeByPlayer(type01)

	fmt.Printf("\n=== 03-type path analysis ===\n\n")
	analyzeByPlayer(type03)

	// Header
	fmt.Printf("\n=== Header Players ===\n")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %s (Team %d) -> ID %d\n", i, p.Username, p.TeamIndex, i+5)
	}
}

func analyzeByPlayer(pkts []packet) {
	playerPackets := make(map[int][]packet)
	for _, p := range pkts {
		playerPackets[p.playerID] = append(playerPackets[p.playerID], p)
	}

	var ids []int
	for id := range playerPackets {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	for _, id := range ids {
		pktList := playerPackets[id]
		if len(pktList) < 10 {
			fmt.Printf("Player %d: %d packets (too few)\n", id, len(pktList))
			continue
		}

		totalDist := float64(0)
		jumpCount := 0
		for i := 1; i < len(pktList); i++ {
			dx := pktList[i].x - pktList[i-1].x
			dy := pktList[i].y - pktList[i-1].y
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			totalDist += dist
			if dist > 5.0 {
				jumpCount++
			}
		}
		avgDist := totalDist / float64(len(pktList)-1)
		jumpPct := float64(jumpCount) / float64(len(pktList)-1) * 100

		fmt.Printf("Player %d: %5d packets, avg step=%.2f, jumps=%.1f%%\n",
			id, len(pktList), avgDist, jumpPct)
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
		suffix:    suffix,
		x:         x,
		y:         y,
		z:         z,
	})

	return nil
}

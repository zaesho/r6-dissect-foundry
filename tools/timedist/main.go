package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

type packet struct {
	playerID  int
	packetNum int
}

var packets []packet
var packetNum int
var totalPackets int

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

	fmt.Printf("Total marker matches: %d\n", totalPackets)
	fmt.Printf("Valid position packets with player IDs: %d\n\n", len(packets))

	// Group by player
	playerPackets := make(map[int][]int) // playerID -> packet numbers
	for _, p := range packets {
		playerPackets[p.playerID] = append(playerPackets[p.playerID], p.packetNum)
	}

	// Divide into time segments (10 segments)
	maxPkt := 0
	for _, p := range packets {
		if p.packetNum > maxPkt {
			maxPkt = p.packetNum
		}
	}
	
	segmentSize := maxPkt / 10
	if segmentSize == 0 {
		segmentSize = 1
	}

	fmt.Printf("=== Temporal distribution (10 segments of ~%d packets each) ===\n", segmentSize)
	fmt.Printf("%-15s", "Player")
	for i := 0; i < 10; i++ {
		fmt.Printf(" Seg%d ", i+1)
	}
	fmt.Println(" Total")
	fmt.Println("-----------------------------------------------------------------------")

	var playerIDs []int
	for id := range playerPackets {
		playerIDs = append(playerIDs, id)
	}
	sort.Ints(playerIDs)

	// Header mapping
	playerNames := map[int]string{
		5: "Ewzy4KT", 6: "Inryo.ALX", 7: "Franklin.ALX", 8: "Solo.FF", 9: "SpiffNP",
		10: "Kiru.UNITY", 11: "VicBands", 12: "hattttttttt", 13: "Repuhrz", 14: "BjL-",
	}

	for _, id := range playerIDs {
		if id < 5 || id > 14 {
			continue
		}
		
		pktNums := playerPackets[id]
		
		// Count packets in each segment
		segCounts := make([]int, 10)
		for _, pktNum := range pktNums {
			seg := pktNum / segmentSize
			if seg >= 10 {
				seg = 9
			}
			segCounts[seg]++
		}
		
		name := playerNames[id]
		if name == "" {
			name = fmt.Sprintf("Player %d", id)
		}
		
		fmt.Printf("%-15s", name)
		for _, count := range segCounts {
			fmt.Printf(" %4d ", count)
		}
		fmt.Printf(" %5d\n", len(pktNums))
	}

	// Also show total per segment
	fmt.Println("-----------------------------------------------------------------------")
	fmt.Printf("%-15s", "TOTAL")
	segTotals := make([]int, 10)
	for _, id := range playerIDs {
		if id < 5 || id > 14 {
			continue
		}
		pktNums := playerPackets[id]
		for _, pktNum := range pktNums {
			seg := pktNum / segmentSize
			if seg >= 10 {
				seg = 9
			}
			segTotals[seg]++
		}
	}
	total := 0
	for _, count := range segTotals {
		fmt.Printf(" %4d ", count)
		total += count
	}
	fmt.Printf(" %5d\n", total)
}

func capturePacket(r *dissect.Reader) error {
	packetNum++
	totalPackets++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	suffix := typeBytes[1]
	prefix := typeBytes[0]

	// Only 01 and 03 types with B0+ prefix (known position packets)
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

	if x < -100 || x > 100 || y < -100 || y > 100 || z < -5 || z > 15 {
		return nil
	}

	postBytes, err := r.Bytes(24)
	if err != nil {
		return nil
	}

	var playerID int
	if suffix == 0x01 {
		playerID = int(binary.LittleEndian.Uint32(postBytes[4:8]))
	} else {
		playerID = int(binary.LittleEndian.Uint32(postBytes[20:24]))
	}

	if playerID >= 5 && playerID <= 14 {
		packets = append(packets, packet{
			playerID:  playerID,
			packetNum: packetNum,
		})
	}

	return nil
}

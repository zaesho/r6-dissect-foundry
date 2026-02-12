package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entitycheck <replay.rec>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	r.EnableMovementTracking(1)

	if err := r.Read(); err != nil && err.Error() != "EOF" {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	// Get raw positions and count by entity ID
	rawPos := r.GetRawPositions()
	fmt.Printf("Total raw positions: %d\n\n", len(rawPos))

	idCounts := make(map[uint32]int)
	for _, p := range rawPos {
		idCounts[p.EntityID]++
	}

	// Sort by count
	type idInfo struct {
		id    uint32
		count int
	}
	var idList []idInfo
	for id, count := range idCounts {
		idList = append(idList, idInfo{id, count})
	}
	sort.Slice(idList, func(i, j int) bool {
		return idList[i].count > idList[j].count
	})

	fmt.Println("=== ENTITY IDs BY PACKET COUNT ===")
	for i, info := range idList {
		if i >= 15 {
			break
		}
		fmt.Printf("  0x%08x: %d packets\n", info.id, info.count)
	}

	// Get movements and count positions per track
	movements := r.GetMovementData()
	fmt.Printf("\nTotal movement tracks: %d\n\n", len(movements))

	fmt.Println("=== MOVEMENT TRACKS (by position count) ===")
	type trackInfo struct {
		username string
		team     string
		count    int
	}
	var tracks []trackInfo
	for _, m := range movements {
		tracks = append(tracks, trackInfo{m.Username, m.Team, len(m.Positions)})
	}
	sort.Slice(tracks, func(i, j int) bool {
		return tracks[i].count > tracks[j].count
	})
	for _, t := range tracks {
		fmt.Printf("  %s (%s): %d positions\n", t.username, t.team, t.count)
	}
}

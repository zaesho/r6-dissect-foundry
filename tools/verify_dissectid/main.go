// verify_dissectid: Tests whether bytes near the movement marker match player DissectIDs.
// Works by enabling movement tracking, reading the full replay, then post-processing
// the raw binary data to check various offsets before the marker.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/verify_dissectid <replay.rec>")
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

	r.EnableMovementTracking(1)
	r.Read()

	// Build DissectID lookup
	dissectIDMap := make(map[string]int) // hex DissectID -> player index
	fmt.Println("Players and DissectIDs:")
	for i, p := range r.Header.Players {
		hexID := hex.EncodeToString(p.DissectID)
		dissectIDMap[hexID] = i
		team := "?"
		if p.TeamIndex < len(r.Header.Teams) {
			team = string(r.Header.Teams[p.TeamIndex].Role)
		}
		fmt.Printf("  [%d] %-18s %-8s DissectID: %s (uint32 LE: %d)\n",
			i, p.Username, team, hexID, binary.LittleEndian.Uint32(p.DissectID))
	}

	// Get raw positions - these have entityID but we need to also check
	// other nearby bytes. The raw position has the entityID from offset -4.
	// We need the raw binary to check offset -8.
	raw := r.GetRawPositions()
	fmt.Printf("\nTotal raw positions: %d\n", len(raw))

	// Check: does the entityID (at offset -4) match any DissectID?
	entityMatchCount := 0
	entityMatchByPlayer := make(map[int]int)
	for _, pos := range raw {
		// Convert entityID to 4-byte hex
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, pos.EntityID)
		hexID := hex.EncodeToString(buf)
		if idx, ok := dissectIDMap[hexID]; ok {
			entityMatchCount++
			entityMatchByPlayer[idx]++
		}
	}

	fmt.Printf("\n=== Entity ID (offset -4) vs DissectID ===\n")
	fmt.Printf("Matched: %d / %d (%.1f%%)\n", entityMatchCount, len(raw), pct(entityMatchCount, len(raw)))
	for idx, count := range entityMatchByPlayer {
		p := r.Header.Players[idx]
		fmt.Printf("  %s: %d\n", p.Username, count)
	}

	// Check: does the playerID (5-14) field work?
	pidMatchCount := 0
	pidByPlayer := make(map[uint32]int)
	for _, pos := range raw {
		if pos.PlayerID >= 5 && pos.PlayerID <= 14 {
			pidMatchCount++
			pidByPlayer[pos.PlayerID]++
		}
	}
	fmt.Printf("\n=== Player ID field (5-14) ===\n")
	fmt.Printf("Valid: %d / %d (%.1f%%)\n", pidMatchCount, len(raw), pct(pidMatchCount, len(raw)))
	for pid := uint32(5); pid <= 14; pid++ {
		if pidByPlayer[pid] > 0 {
			idx := int(pid - 5)
			name := "?"
			if idx < len(r.Header.Players) {
				name = r.Header.Players[idx].Username
			}
			fmt.Printf("  ID %d (%s): %d\n", pid, name, pidByPlayer[pid])
		}
	}

	// Now let's check: do valid-coordinate positions have consistent
	// playerID assignment? Group by (rounded X,Y) and see if playerID is stable
	fmt.Printf("\n=== Position-to-PlayerID Stability Check ===\n")
	type gridKey struct{ x, y int }
	gridIDs := make(map[gridKey]map[uint32]int) // grid cell -> playerID -> count

	for _, pos := range raw {
		if pos.PlayerID < 5 || pos.PlayerID > 14 {
			continue
		}
		if math.IsNaN(float64(pos.X)) || math.IsNaN(float64(pos.Y)) {
			continue
		}
		if pos.X < -100 || pos.X > 100 || pos.Y < -100 || pos.Y > 100 {
			continue
		}
		key := gridKey{int(math.Round(float64(pos.X))), int(math.Round(float64(pos.Y)))}
		if gridIDs[key] == nil {
			gridIDs[key] = make(map[uint32]int)
		}
		gridIDs[key][pos.PlayerID]++
	}

	// Count cells with multiple player IDs (cross-contamination)
	singleID := 0
	multiID := 0
	for _, ids := range gridIDs {
		if len(ids) == 1 {
			singleID++
		} else {
			multiID++
		}
	}
	fmt.Printf("Grid cells with single player ID: %d\n", singleID)
	fmt.Printf("Grid cells with MULTIPLE player IDs: %d (%.1f%% contaminated)\n",
		multiID, pct(multiID, singleID+multiID))
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

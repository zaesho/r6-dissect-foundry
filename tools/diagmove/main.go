// diagmove: Diagnose where movement data is being lost in the pipeline.
// Shows raw position counts per player ID, per entity, and after filtering.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/diagmove <replay.rec>")
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

	r.EnableMovementTracking(1) // capture all
	r.Read()

	fmt.Printf("Season: %s (code: %d)\n", r.Header.GameVersion, r.Header.CodeVersion)
	fmt.Printf("Map: %s\n\n", r.Header.Map.String())

	// Show players
	fmt.Println("Players:")
	for i, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex < len(r.Header.Teams) {
			team = string(r.Header.Teams[p.TeamIndex].Role)
		}
		fmt.Printf("  [%d] %-18s Team %d (%s) -> Player ID %d\n", i, p.Username, p.TeamIndex, team, i+5)
	}

	// Get raw positions
	raw := r.GetRawPositions()
	fmt.Printf("\nTotal raw positions: %d\n\n", len(raw))

	// Group by player ID
	byPlayerID := make(map[uint32][]dissect.RawPosition)
	noPlayerID := 0
	for _, p := range raw {
		if p.PlayerID >= 5 && p.PlayerID <= 14 {
			byPlayerID[p.PlayerID] = append(byPlayerID[p.PlayerID], p)
		} else {
			noPlayerID++
		}
	}

	fmt.Printf("Positions with valid player ID (5-14): %d\n", len(raw)-noPlayerID)
	fmt.Printf("Positions without valid player ID: %d\n\n", noPlayerID)

	// For each player ID, show entity breakdown
	fmt.Println("=== RAW POSITIONS BY PLAYER ID + ENTITY ID ===")
	for playerID := uint32(5); playerID <= 14; playerID++ {
		positions := byPlayerID[playerID]
		headerIdx := int(playerID - 5)
		username := "?"
		if headerIdx < len(r.Header.Players) {
			username = r.Header.Players[headerIdx].Username
		}

		// Group by entity ID
		byEntity := make(map[uint32]int)
		for _, p := range positions {
			byEntity[p.EntityID]++
		}

		// Sort entities by count
		type eidCount struct {
			id    uint32
			count int
		}
		var entities []eidCount
		for id, c := range byEntity {
			entities = append(entities, eidCount{id, c})
		}
		sort.Slice(entities, func(i, j int) bool { return entities[i].count > entities[j].count })

		fmt.Printf("\nPlayer ID %d (%s): %d total positions, %d entities\n", playerID, username, len(positions), len(entities))
		for i, e := range entities {
			dominant := ""
			if i == 0 {
				dominant = " <-- DOMINANT (selected)"
			}
			fmt.Printf("  Entity 0x%08X: %d positions%s\n", e.id, e.count, dominant)
			if i >= 9 {
				fmt.Printf("  ... and %d more entities\n", len(entities)-10)
				break
			}
		}
	}

	// Now show final output
	fmt.Println("\n=== FINAL OUTPUT (after entity selection + continuity filter) ===")
	movements := r.GetMovementData()
	totalFinal := 0
	for _, m := range movements {
		totalFinal += len(m.Positions)
		fmt.Printf("  %-18s: %d positions\n", m.Username, len(m.Positions))
	}
	fmt.Printf("\nTotal: %d players, %d positions\n", len(movements), totalFinal)
}

package main

import (
	"fmt"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_mapping <replay.rec>")
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
	r.Read()

	fmt.Println("=== HEADER PLAYERS ===")
	for i, p := range r.Header.Players {
		team := "?"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
				team = "ATK"
			} else {
				team = "DEF"
			}
		}
		fmt.Printf("  [%d] %-15s (%s) %s\n", i, p.Username, team, p.Operator.String())
	}

	movements := r.GetMovementData()
	fmt.Println("\n=== MOVEMENT TRACKS ===")
	for _, m := range movements {
		fmt.Printf("  %-15s (%s) %-12s: %d positions\n", m.Username, m.Team, m.Operator, len(m.Positions))
	}

	// Also show raw position stats per entity
	rawPos := r.GetRawPositions()
	fmt.Printf("\n=== RAW POSITIONS: %d total ===\n", len(rawPos))

	// Count by entity and player ID
	entityCounts := make(map[uint32]int)
	entityPlayerIDs := make(map[uint32]map[uint32]int)

	for _, p := range rawPos {
		entityCounts[p.EntityID]++
		if entityPlayerIDs[p.EntityID] == nil {
			entityPlayerIDs[p.EntityID] = make(map[uint32]int)
		}
		entityPlayerIDs[p.EntityID][p.PlayerID]++
	}

	fmt.Println("\nTop 15 entities by packet count:")
	fmt.Printf("%-12s %6s %s\n", "EntityID", "Count", "PlayerIDs (count)")

	// Sort by count
	type entityInfo struct {
		id    uint32
		count int
	}
	var entities []entityInfo
	for id, cnt := range entityCounts {
		entities = append(entities, entityInfo{id, cnt})
	}
	for i := 0; i < len(entities)-1; i++ {
		for j := i + 1; j < len(entities); j++ {
			if entities[j].count > entities[i].count {
				entities[i], entities[j] = entities[j], entities[i]
			}
		}
	}

	for i, e := range entities {
		if i >= 15 {
			break
		}
		playerIDStr := ""
		for pid, cnt := range entityPlayerIDs[e.id] {
			if pid >= 5 && pid <= 14 {
				playerIDStr += fmt.Sprintf("%d(%d) ", pid, cnt)
			}
		}
		if playerIDStr == "" {
			playerIDStr = "(no valid IDs)"
		}
		fmt.Printf("0x%08x %6d %s\n", e.id, e.count, playerIDStr)
	}
}

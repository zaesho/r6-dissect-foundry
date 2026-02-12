package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/ammoanalysis <replay.rec>")
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
	_ = r.ReadPartial()

	fmt.Println("=== PLAYERS ===")
	for i, p := range r.Header.Players {
		fmt.Printf("  [%d] %-18s %-10s (team %d)\n", i, p.Username, p.RoleName, p.TeamIndex)
	}
	fmt.Println()

	f.Seek(0, 0)
	r2, err := dissect.NewReader(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	rawBytes, err := decompressReplay(r2)
	if err != nil {
		fmt.Println("Error decompressing:", err)
		os.Exit(1)
	}

	marker := []byte{0x77, 0xCA, 0x96, 0xDE}
	offsets := findAllOccurrences(rawBytes, marker)
	fmt.Printf("Found %d ammo markers\n\n", len(offsets))

	// Collect ALL unique entities in order of first appearance
	type entityInfo struct {
		id       uint32
		offset   int
		magAmmo  uint32
		reserve  uint32
		total    uint32
		gadget   uint32
		magCap   uint32
		isFull   bool // has all tagged fields
	}

	seenEntities := map[uint32]bool{}
	var allEntities []entityInfo

	for _, off := range offsets {
		if off < 8 {
			continue
		}

		entityID := binary.LittleEndian.Uint32(rawBytes[off-8 : off-4])
		nullOk := rawBytes[off-4] == 0 && rawBytes[off-3] == 0 && rawBytes[off-2] == 0 && rawBytes[off-1] == 0
		if !nullOk || entityID == 0 {
			continue
		}

		if seenEntities[entityID] {
			continue
		}
		seenEntities[entityID] = true

		pos := off + 4
		var magAmmo, reserve, gadget, magCap, totalAmmo uint32
		hasReserve, hasGadget, hasMagCap, hasTotal := false, false, false, false
		if pos+5 <= len(rawBytes) && rawBytes[pos] == 0x04 {
			magAmmo = binary.LittleEndian.Uint32(rawBytes[pos+1 : pos+5])
			pos += 5
		}
		for pos+10 <= len(rawBytes) && rawBytes[pos] == 0x22 {
			var fid [4]byte
			copy(fid[:], rawBytes[pos+1:pos+5])
			if rawBytes[pos+5] == 0x04 {
				val := binary.LittleEndian.Uint32(rawBytes[pos+6 : pos+10])
				switch fid {
				case [4]byte{0x6D, 0x5B, 0x6D, 0x3E}:
					reserve = val
					hasReserve = true
				case [4]byte{0x34, 0xBC, 0x4B, 0xAA}:
					gadget = val
					hasGadget = true
				case [4]byte{0x56, 0xF5, 0x44, 0x0A}:
					magCap = val
					hasMagCap = true
				case [4]byte{0x40, 0x0A, 0xC8, 0x29}:
					totalAmmo = val
					hasTotal = true
				}
				pos += 10
			} else if rawBytes[pos+5] == 0x08 {
				pos += 14
			} else if rawBytes[pos+5] == 0x01 {
				pos += 7
			} else {
				break
			}
		}

		isFull := hasReserve && hasGadget && hasMagCap && hasTotal

		allEntities = append(allEntities, entityInfo{
			id: entityID, offset: off,
			magAmmo: magAmmo, reserve: reserve, total: totalAmmo,
			gadget: gadget, magCap: magCap, isFull: isFull,
		})
	}

	fmt.Printf("Total unique entities: %d\n\n", len(allEntities))

	// Print all entities with gap analysis
	fmt.Println("=== ALL UNIQUE ENTITIES (first-appearance order) ===")
	for i, e := range allEntities {
		gap := 0
		gapLabel := ""
		if i > 0 {
			gap = e.offset - allEntities[i-1].offset
			if gap < 400 {
				gapLabel = "SHORT (same pair)"
			} else {
				gapLabel = "LONG (new pair)"
			}
		} else {
			gapLabel = "FIRST"
		}

		fullLabel := ""
		if e.isFull {
			fullLabel = " [FULL]"
		} else {
			fullLabel = " [partial]"
		}

		fmt.Printf("  #%2d entity=0x%08X: mag=%2d/%2d reserve=%3d total=%3d gadget=%d  gap=%4d %s%s\n",
			i, e.id, e.magAmmo, e.magCap, e.reserve, e.total, e.gadget, gap, gapLabel, fullLabel)
	}

	// Group into pairs based on gap
	fmt.Println("\n=== PAIR GROUPING ===")
	type pair struct {
		entities []entityInfo
	}
	var pairs []pair
	var currentPair pair

	for i, e := range allEntities {
		if i == 0 {
			currentPair = pair{entities: []entityInfo{e}}
		} else {
			gap := e.offset - allEntities[i-1].offset
			if gap < 400 {
				currentPair.entities = append(currentPair.entities, e)
			} else {
				pairs = append(pairs, currentPair)
				currentPair = pair{entities: []entityInfo{e}}
			}
		}
	}
	if len(currentPair.entities) > 0 {
		pairs = append(pairs, currentPair)
	}

	for i, p := range pairs {
		playerLabel := ""
		if i < len(r.Header.Players) {
			playerLabel = fmt.Sprintf(" -> Player[%d] %s (%s)", i, r.Header.Players[i].Username, r.Header.Players[i].RoleName)
		}
		fmt.Printf("  Pair %d (%d entities)%s:\n", i, len(p.entities), playerLabel)
		for j, e := range p.entities {
			label := "???"
			if j == 0 {
				label = "PRIMARY"
			} else {
				label = "SECONDARY"
			}
			fmt.Printf("    [%s] entity=0x%08X: mag=%d/%d reserve=%d total=%d gadget=%d\n",
				label, e.id, e.magAmmo, e.magCap, e.reserve, e.total, e.gadget)
		}
	}
}

func findAllOccurrences(data, pattern []byte) []int {
	var result []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			result = append(result, i)
		}
	}
	return result
}

func decompressReplay(r *dissect.Reader) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "replay-decomp-*.bin")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	_, err = r.Write(tmpFile)
	if err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()
	return os.ReadFile(tmpFile.Name())
}

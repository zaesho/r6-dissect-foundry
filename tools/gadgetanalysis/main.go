package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

// Deep analysis of ALL fields in ammo packets, focusing on gadget identification.

var knownFieldNames = map[[4]byte]string{
	{0x6D, 0x5B, 0x6D, 0x3E}: "reserve",
	{0x34, 0xBC, 0x4B, 0xAA}: "gadget",
	{0x56, 0xF5, 0x44, 0x0A}: "magCap",
	{0x40, 0x0A, 0xC8, 0x29}: "total",
}

type fieldValue struct {
	fid      [4]byte
	typeByte byte
	valU32   uint32  // if type 0x04
	valU64   uint64  // if type 0x08
	valBool  bool    // if type 0x01
}

type ammoSnapshot struct {
	entityID uint32
	offset   int
	magAmmo  uint32
	fields   []fieldValue
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./tools/gadgetanalysis <replay.rec>")
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
		fmt.Printf("  [%d] %-18s %-10s\n", i, p.Username, p.RoleName)
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
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	marker := []byte{0x77, 0xCA, 0x96, 0xDE}
	offsets := findAllOccurrences(rawBytes, marker)

	// Parse ALL snapshots
	var allSnapshots []ammoSnapshot
	for _, off := range offsets {
		snap := parseFullAmmoAt(rawBytes, off)
		if snap != nil {
			allSnapshots = append(allSnapshots, *snap)
		}
	}

	// Group by entity, preserve order
	entitySnapshots := map[uint32][]ammoSnapshot{}
	entityOrder := []uint32{}
	for _, s := range allSnapshots {
		if _, ok := entitySnapshots[s.entityID]; !ok {
			entityOrder = append(entityOrder, s.entityID)
		}
		entitySnapshots[s.entityID] = append(entitySnapshots[s.entityID], s)
	}

	// Group into player groups
	type entityGroup struct {
		entities []uint32
	}
	var groups []entityGroup
	var currentGroup entityGroup
	var lastOffset int

	for i, eid := range entityOrder {
		snaps := entitySnapshots[eid]
		firstOff := snaps[0].offset
		if i == 0 {
			currentGroup = entityGroup{entities: []uint32{eid}}
			lastOffset = firstOff
		} else {
			gap := firstOff - lastOffset
			if gap > 400 {
				groups = append(groups, currentGroup)
				currentGroup = entityGroup{entities: []uint32{eid}}
			} else {
				currentGroup.entities = append(currentGroup.entities, eid)
			}
			lastOffset = firstOff
		}
	}
	if len(currentGroup.entities) > 0 {
		groups = append(groups, currentGroup)
	}

	// For each group/player, show ALL field values from the INITIAL full packet
	fmt.Println("=== INITIAL FULL PACKET FIELD VALUES (per entity) ===")
	for gi, g := range groups {
		playerLabel := ""
		if gi < len(r.Header.Players) {
			p := r.Header.Players[gi]
			playerLabel = fmt.Sprintf("%s (%s)", p.Username, p.RoleName)
		}

		fmt.Printf("\n--- Player %d: %s ---\n", gi, playerLabel)

		for ei, eid := range g.entities {
			snaps := entitySnapshots[eid]
			first := snaps[0]
			label := "PRIMARY"
			if ei == 1 {
				label = "SECONDARY"
			} else if ei > 1 {
				label = fmt.Sprintf("GADGET_%d", ei-1)
			}

			fmt.Printf("  [%s] mag=%d, all fields:\n", label, first.magAmmo)
			for _, fv := range first.fields {
				name := knownFieldNames[fv.fid]
				if name == "" {
					name = fmt.Sprintf("%02X%02X%02X%02X", fv.fid[0], fv.fid[1], fv.fid[2], fv.fid[3])
				}
				switch fv.typeByte {
				case 0x04:
					// Check if it could be a float32
					floatVal := math.Float32frombits(fv.valU32)
					if fv.valU32 > 0 && fv.valU32 < 1000 {
						fmt.Printf("    %-12s = %d (uint32)\n", name, fv.valU32)
					} else if floatVal > 0 && floatVal < 10000 && !math.IsNaN(float64(floatVal)) && !math.IsInf(float64(floatVal), 0) {
						fmt.Printf("    %-12s = 0x%08X (uint32=%d, float=%.2f)\n", name, fv.valU32, fv.valU32, floatVal)
					} else {
						fmt.Printf("    %-12s = 0x%08X (uint32=%d)\n", name, fv.valU32, fv.valU32)
					}
				case 0x08:
					fmt.Printf("    %-12s = 0x%016X (uint64)\n", name, fv.valU64)
				case 0x01:
					fmt.Printf("    %-12s = %v (bool)\n", name, fv.valBool)
				}
			}
		}
	}

	// Track gadget-related field changes over time for interesting entities
	fmt.Println("\n\n=== FIELD VALUE CHANGES OVER TIME (operators with gadget launchers) ===")
	for gi, g := range groups {
		if gi >= len(r.Header.Players) {
			break
		}
		p := r.Header.Players[gi]

		for ei, eid := range g.entities {
			snaps := entitySnapshots[eid]
			if len(snaps) < 2 {
				continue
			}

			label := "PRIMARY"
			if ei == 1 {
				label = "SECONDARY"
			} else if ei > 1 {
				label = fmt.Sprintf("GADGET_%d", ei-1)
			}

			// Track changes to ALL fields, not just gadget
			type fieldChange struct {
				name string
				from uint32
				to   uint32
				idx  int // snapshot index where change happened
			}
			changes := []fieldChange{}

			// Compare first snapshot to subsequent ones
			first := snaps[0]
			prevByFID := map[[4]byte]uint32{}
			for _, fv := range first.fields {
				if fv.typeByte == 0x04 {
					prevByFID[fv.fid] = fv.valU32
				}
			}

			for si := 1; si < len(snaps); si++ {
				for _, fv := range snaps[si].fields {
					if fv.typeByte != 0x04 {
						continue
					}
					prev, ok := prevByFID[fv.fid]
					if !ok {
						continue
					}
					if fv.valU32 != prev {
						name := knownFieldNames[fv.fid]
						if name == "" {
							name = fmt.Sprintf("%02X%02X%02X%02X", fv.fid[0], fv.fid[1], fv.fid[2], fv.fid[3])
						}
						changes = append(changes, fieldChange{name, prev, fv.valU32, si})
						prevByFID[fv.fid] = fv.valU32
					}
				}
			}

			if len(changes) == 0 {
				continue
			}

			// Only show entities with interesting changes (beyond just mag/reserve/total)
			hasNonAmmoChanges := false
			for _, c := range changes {
				if c.name != "reserve" && c.name != "total" && c.name != "magCap" {
					hasNonAmmoChanges = true
					break
				}
			}
			if !hasNonAmmoChanges {
				continue
			}

			fmt.Printf("\n  %s [%s] (mag=%d):\n", p.Username, label, first.magAmmo)
			limit := 40
			for _, c := range changes {
				if c.name == "reserve" || c.name == "total" {
					continue // Skip ammo changes, focus on other fields
				}
				if limit <= 0 {
					fmt.Printf("    ... +%d more changes\n", len(changes)-40)
					break
				}
				fmt.Printf("    snap[%d] %s: %d -> %d\n", c.idx, c.name, c.from, c.to)
				limit--
			}
		}
	}
}

func parseFullAmmoAt(data []byte, off int) *ammoSnapshot {
	if off < 8 {
		return nil
	}

	entityID := binary.LittleEndian.Uint32(data[off-8 : off-4])
	if data[off-4] != 0 || data[off-3] != 0 || data[off-2] != 0 || data[off-1] != 0 {
		return nil
	}
	if entityID == 0 {
		return nil
	}

	pos := off + 4
	var magAmmo uint32
	var fields []fieldValue

	if pos+5 <= len(data) && data[pos] == 0x04 {
		magAmmo = binary.LittleEndian.Uint32(data[pos+1 : pos+5])
		if magAmmo > 10000 {
			return nil
		}
		pos += 5
	}

	for pos+6 <= len(data) && data[pos] == 0x22 {
		var fid [4]byte
		copy(fid[:], data[pos+1:pos+5])
		typeByte := data[pos+5]

		switch typeByte {
		case 0x04:
			if pos+10 > len(data) {
				break
			}
			val := binary.LittleEndian.Uint32(data[pos+6 : pos+10])
			fields = append(fields, fieldValue{fid: fid, typeByte: 0x04, valU32: val})
			pos += 10
		case 0x08:
			if pos+14 > len(data) {
				break
			}
			val := binary.LittleEndian.Uint64(data[pos+6 : pos+14])
			fields = append(fields, fieldValue{fid: fid, typeByte: 0x08, valU64: val})
			pos += 14
		case 0x01:
			if pos+7 > len(data) {
				break
			}
			val := data[pos+6] != 0
			fields = append(fields, fieldValue{fid: fid, typeByte: 0x01, valBool: val})
			pos += 7
		default:
			goto done
		}
	}
done:

	return &ammoSnapshot{
		entityID: entityID,
		offset:   off,
		magAmmo:  magAmmo,
		fields:   fields,
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

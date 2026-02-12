package dissect

import (
	"encoding/binary"

	"github.com/rs/zerolog/log"
)

// Known field IDs in the ammo protobuf-like packet (after 0x77CA96DE marker).
var (
	fieldIDReserveAmmo  = [4]byte{0x6D, 0x5B, 0x6D, 0x3E} // Reserve ammo pool
	fieldIDReloadsAvail = [4]byte{0x34, 0xBC, 0x4B, 0xAA} // Reloads available (reserve/magCap) - NOT gadget-related
	fieldIDMagCapacity  = [4]byte{0x56, 0xF5, 0x44, 0x0A} // Magazine capacity (without chamber)
	fieldIDTotalAmmo    = [4]byte{0x40, 0x0A, 0xC8, 0x29} // Total ammo (magazine + reserve)
)

// entityType classifies what an ammo entity represents.
type entityType int

const (
	entityTypePrimary   entityType = iota // Primary weapon
	entityTypeSecondary                   // Secondary weapon
	entityTypeAbility                     // Operator ability launcher (e.g. Hibana X-KAIROS, Ash breach rounds)
)

// AmmoUpdate represents a single ammo state snapshot for a player.
type AmmoUpdate struct {
	Username         string  `json:"username"`
	MagazineAmmo     int     `json:"magazineAmmo"`               // Current rounds loaded (magazine + 1 in chamber)
	ReserveAmmo      int     `json:"reserveAmmo,omitempty"`      // Reserve ammo pool
	TotalAmmo        int     `json:"totalAmmo,omitempty"`        // Magazine + reserve combined
	MagazineCapacity int     `json:"magazineCapacity,omitempty"` // Max rounds per magazine (without chamber)
	IsPrimary        bool    `json:"isPrimary"`                  // true=primary weapon, false=secondary weapon
	IsAbility        bool    `json:"isAbility,omitempty"`        // true=operator ability (e.g. Hibana X-KAIROS)
	Time             string  `json:"time"`
	TimeInSeconds    float64 `json:"timeInSeconds"`
}

// PlayerLoadout represents the initial loadout state for a player,
// captured from the first full ammo packets in the round.
// Each player has a primary and secondary weapon entity, and optionally
// one or more ability launcher entities.
type PlayerLoadout struct {
	// Primary weapon
	MagazineAmmo     int `json:"magazineAmmo"`     // Starting magazine ammo (capacity + 1 in chamber)
	MagazineCapacity int `json:"magazineCapacity"`  // Magazine capacity (rounds per reload)
	ReserveAmmo      int `json:"reserveAmmo"`       // Starting reserve ammo
	TotalAmmo        int `json:"totalAmmo"`         // Starting total (magazine + reserve)
	// Secondary weapon
	SecondaryMagAmmo     int `json:"secondaryMagAmmo,omitempty"`
	SecondaryMagCapacity int `json:"secondaryMagCapacity,omitempty"`
	SecondaryReserve     int `json:"secondaryReserve,omitempty"`
	SecondaryTotal       int `json:"secondaryTotal,omitempty"`
	// Operator ability (e.g. Hibana X-KAIROS, Ash breach rounds, Nomad Airjabs)
	AbilityCharges int `json:"abilityCharges,omitempty"` // Starting total ability charges
}

// ammoEntityEntry tracks first-appearance data for each unique ammo entity.
type ammoEntityEntry struct {
	firstOffset int        // byte offset of first 77CA96DE marker for this entity
	entType     entityType // primary, secondary, or ability
	playerIdx   int        // mapped player index
}

// readAmmo parses ammo state packets (marker: 0x77CA96DE).
//
// ENTITY CLASSIFICATION:
// Each player has 2-4 ammo entities in the data stream:
//   - Primary weapon (always present)
//   - Secondary weapon (always present)
//   - Ability launcher(s) (only for operators with special abilities, e.g. Hibana, Ash, Nomad, Grim)
//
// Entities for the same player appear in close proximity (<400 bytes apart).
// Ability launchers are distinguished from weapons by their small total ammo (<=20).
//
// The field previously labeled "gadget" (34BC4BAA) is actually "reloads available"
// (ceil(reserve/magCap)) and is NOT related to throwable gadgets.
func readAmmo(r *Reader) error {
	// Field 1: Always present - current magazine ammo
	magazineAmmo, err := r.Uint32()
	if err != nil {
		return err
	}
	if magazineAmmo > 10000 {
		return nil
	}

	// Parse remaining tagged fields by field ID
	var reserveAmmo, magCapacity, totalAmmo uint32
	var hasReserve, hasMagCap, hasTotal bool

	for {
		if r.offset >= len(r.b) || r.b[r.offset] != 0x22 {
			break
		}
		if r.offset+5 >= len(r.b) {
			break
		}
		var fieldID [4]byte
		copy(fieldID[:], r.b[r.offset+1:r.offset+5])
		typeByte := r.b[r.offset+5]

		if typeByte == 0x04 {
			if r.offset+10 > len(r.b) {
				break
			}
			val := binary.LittleEndian.Uint32(r.b[r.offset+6 : r.offset+10])
			if val > 10000 {
				break
			}
			switch fieldID {
			case fieldIDReserveAmmo:
				reserveAmmo = val
				hasReserve = true
			case fieldIDReloadsAvail:
				// This is reloads available (reserve/magCap), not gadget-related.
				// We parse it to advance the offset but don't use it.
			case fieldIDMagCapacity:
				magCapacity = val
				hasMagCap = true
			case fieldIDTotalAmmo:
				totalAmmo = val
				hasTotal = true
			}
			r.offset += 10
		} else if typeByte == 0x08 {
			if r.offset+14 > len(r.b) {
				break
			}
			r.offset += 14
		} else if typeByte == 0x01 {
			if r.offset+7 > len(r.b) {
				break
			}
			r.offset += 7
		} else {
			break
		}
	}

	// Extract entity ID
	entityID := r.extractAmmoEntityID()

	isFullPacket := hasReserve && hasMagCap && hasTotal

	// Map entity ID to player index and classify entity type
	playerIdx, entType := r.mapAmmoEntityToPlayer(entityID, totalAmmo, isFullPacket)

	username := ""
	if playerIdx >= 0 && playerIdx < len(r.Header.Players) {
		username = r.Header.Players[playerIdx].Username
	}

	update := AmmoUpdate{
		Username:         username,
		MagazineAmmo:     int(magazineAmmo),
		ReserveAmmo:      int(reserveAmmo),
		TotalAmmo:        int(totalAmmo),
		MagazineCapacity: int(magCapacity),
		IsPrimary:        entType == entityTypePrimary,
		IsAbility:        entType == entityTypeAbility,
		Time:             r.timeRaw,
		TimeInSeconds:    r.time,
	}

	// Build initial loadout from full packets
	if playerIdx >= 0 && isFullPacket {
		loadout, exists := r.playerLoadouts[playerIdx]
		if !exists {
			loadout = PlayerLoadout{}
		}

		switch entType {
		case entityTypePrimary:
			if loadout.MagazineAmmo == 0 { // only set once
				loadout.MagazineAmmo = int(magazineAmmo)
				loadout.MagazineCapacity = int(magCapacity)
				loadout.ReserveAmmo = int(reserveAmmo)
				loadout.TotalAmmo = int(totalAmmo)
				log.Debug().
					Str("username", username).
					Int("magazineAmmo", int(magazineAmmo)).
					Int("magazineCapacity", int(magCapacity)).
					Int("reserveAmmo", int(reserveAmmo)).
					Int("totalAmmo", int(totalAmmo)).
					Msg("primary loadout captured")
			}
		case entityTypeSecondary:
			if loadout.SecondaryMagAmmo == 0 { // only set once
				loadout.SecondaryMagAmmo = int(magazineAmmo)
				loadout.SecondaryMagCapacity = int(magCapacity)
				loadout.SecondaryReserve = int(reserveAmmo)
				loadout.SecondaryTotal = int(totalAmmo)
				log.Debug().
					Str("username", username).
					Int("secMagAmmo", int(magazineAmmo)).
					Int("secMagCap", int(magCapacity)).
					Int("secReserve", int(reserveAmmo)).
					Int("secTotal", int(totalAmmo)).
					Msg("secondary loadout captured")
			}
		case entityTypeAbility:
			if loadout.AbilityCharges == 0 { // only set once (first ability entity)
				loadout.AbilityCharges = int(totalAmmo)
				log.Debug().
					Str("username", username).
					Int("abilityCharges", int(totalAmmo)).
					Int("abilityMag", int(magazineAmmo)).
					Int("abilityReserve", int(reserveAmmo)).
					Msg("ability loadout captured")
			}
		}

		r.playerLoadouts[playerIdx] = loadout
	}

	if len(username) > 0 {
		r.AmmoUpdates = append(r.AmmoUpdates, update)
	}

	log.Debug().
		Str("username", username).
		Hex("entityID", entityID).
		Int("entityType", int(entType)).
		Uint32("magazineAmmo", magazineAmmo).
		Uint32("reserveAmmo", reserveAmmo).
		Uint32("totalAmmo", totalAmmo).
		Uint32("magCapacity", magCapacity).
		Str("time", r.timeRaw).
		Msg("ammo")

	return nil
}

// extractAmmoEntityID reads the 4-byte entity ID from before the 77CA96DE pattern.
func (r *Reader) extractAmmoEntityID() []byte {
	start := r.ammoLastPatternOffset - 12
	if start < 0 || start+4 > len(r.b) {
		return nil
	}

	id := r.b[start : start+4]

	nullPadding := r.b[start+4 : start+8]
	if nullPadding[0] != 0x00 || nullPadding[1] != 0x00 ||
		nullPadding[2] != 0x00 || nullPadding[3] != 0x00 {
		return nil
	}

	return id
}

// mapAmmoEntityToPlayer maps an ammo entity ID to a player index and
// classifies the entity type (primary weapon, secondary weapon, or ability launcher).
//
// Entity grouping:
//   - Entities for the same player appear within <400 bytes of each other.
//   - A gap >400 bytes between consecutive new entities = new player.
//
// Entity classification:
//   - Entity with totalAmmo <= 20 in its first full packet = ability launcher.
//   - Otherwise = weapon (first weapon per player = primary, second = secondary).
//
// Returns (playerIndex, entityType).
func (r *Reader) mapAmmoEntityToPlayer(entityID []byte, totalAmmo uint32, hasFullData bool) (int, entityType) {
	if entityID == nil || len(entityID) != 4 {
		return -1, entityTypePrimary
	}

	key := binary.LittleEndian.Uint32(entityID)
	if key == 0 {
		return -1, entityTypePrimary
	}

	// Check if we already have this entity mapped
	if entry, ok := r.ammoEntityEntries[key]; ok {
		return entry.playerIdx, entry.entType
	}

	// Determine if this is a new player based on gap from previous entity
	currentOffset := r.ammoLastPatternOffset
	isNewPlayer := true

	if r.ammoLastNewEntityOffset > 0 {
		gap := currentOffset - r.ammoLastNewEntityOffset
		if gap > 0 && gap < 400 {
			// Short gap = same player as previous entity
			isNewPlayer = false
		}
	}

	// Calculate player index
	playerIdx := -1
	if isNewPlayer {
		// New player - advance player counter
		playerIdx = r.ammoNextPlayerIdx
		r.ammoNextPlayerIdx++
		r.ammoCurrentPlayerEntityCount = 1
	} else {
		// Same player as previous entity
		playerIdx = r.ammoNextPlayerIdx - 1
		r.ammoCurrentPlayerEntityCount++
	}

	if playerIdx < 0 || playerIdx >= len(r.Header.Players) {
		log.Debug().
			Hex("entityID", entityID).
			Int("playerIdx", playerIdx).
			Bool("isNewPlayer", isNewPlayer).
			Msg("ammo entity exceeds player count")
		return -1, entityTypePrimary
	}

	// Classify entity type based on total ammo and position in group
	entType := classifyEntityType(r.ammoCurrentPlayerEntityCount, totalAmmo, hasFullData)

	r.ammoEntityEntries[key] = ammoEntityEntry{
		firstOffset: currentOffset,
		entType:     entType,
		playerIdx:   playerIdx,
	}
	r.ammoLastNewEntityOffset = currentOffset

	log.Debug().
		Hex("entityID", entityID).
		Int("playerIdx", playerIdx).
		Int("entityType", int(entType)).
		Int("entityCount", r.ammoCurrentPlayerEntityCount).
		Uint32("totalAmmo", totalAmmo).
		Str("username", r.Header.Players[playerIdx].Username).
		Msg("ammo entity mapped to player")

	return playerIdx, entType
}

// classifyEntityType determines whether an entity is a weapon or ability launcher.
//
// Ability launchers (Hibana X-KAIROS, Ash breach rounds, Nomad Airjabs, Grim Kawan Hive, etc.)
// have very low total ammo (typically 2-18) compared to weapons (36+).
//
// For the first entity in a group, it's always the primary weapon.
// For subsequent entities, if totalAmmo <= 20 → ability, otherwise → weapon (secondary).
func classifyEntityType(entityCountInGroup int, totalAmmo uint32, hasFullData bool) entityType {
	if entityCountInGroup == 1 {
		return entityTypePrimary
	}
	if hasFullData && totalAmmo <= 20 {
		return entityTypeAbility
	}
	return entityTypeSecondary
}

// GetPlayerLoadouts returns the initial loadout state for each player.
func (r *Reader) GetPlayerLoadouts() map[int]PlayerLoadout {
	return r.playerLoadouts
}

// populateLoadouts copies the captured loadout data onto each Player struct.
func (r *Reader) populateLoadouts() {
	for idx, loadout := range r.playerLoadouts {
		if idx >= 0 && idx < len(r.Header.Players) {
			l := loadout
			r.Header.Players[idx].Loadout = &l
		}
	}
}

// GetAmmoTimeline returns all ammo updates for a specific player username.
func (r *Reader) GetAmmoTimeline(username string) []AmmoUpdate {
	var updates []AmmoUpdate
	for _, u := range r.AmmoUpdates {
		if u.Username == username {
			updates = append(updates, u)
		}
	}
	return updates
}

// wrapAmmoReader bookmarks the pattern offset before readAmmo processes the data.
func wrapAmmoReader(r *Reader) error {
	r.ammoLastPatternOffset = r.offset
	return readAmmo(r)
}

package dissect

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

// PlayerPosition represents a player's position at a specific time.
type PlayerPosition struct {
	TimeInSeconds float64 `json:"timeInSeconds"`
	X             float32 `json:"x"`
	Y             float32 `json:"y"`
	Z             float32 `json:"z"`
	Yaw           float32 `json:"yaw,omitempty"` // Rotation in degrees (0-360)
}

// PlayerMovement tracks all positions for a single player throughout a round.
type PlayerMovement struct {
	Username  string           `json:"username"`
	Operator  string           `json:"operator"`
	Team      string           `json:"team"` // "Attack" or "Defense"
	Loadout   *PlayerLoadout   `json:"loadout,omitempty"` // Initial loadout (ammo capacities)
	Positions []PlayerPosition `json:"positions"`
}

// rawPosition stores position packets before track assignment
type rawPosition struct {
	packetNum int
	entityID  uint32  // 4-byte entity ID from before the marker
	playerID  uint32  // Player ID from packet payload (maps to header index via playerID-5)
	x, y, z   float32
	yaw       float32 // Rotation from quaternion
}

// ExperimentalPacket stores packets from non-standard types (e.g., 0x3F)
// captured when ExperimentalTypes is enabled. Used for research/analysis.
type ExperimentalPacket struct {
	PacketNum int     `json:"packetNum"`
	TypeFirst byte    `json:"typeFirst"`  // prefix byte (e.g., 0xC0)
	TypeSecond byte   `json:"typeSecond"` // suffix byte (e.g., 0x3F)
	EntityID  uint32  `json:"entityID"`
	X         float32 `json:"x,omitempty"`
	Y         float32 `json:"y,omitempty"`
	Z         float32 `json:"z,omitempty"`
	HasCoords bool    `json:"hasCoords"` // whether valid coordinates were found
	RawPost   []byte  `json:"-"`         // raw bytes after type for offline analysis
}

// positionTrack is used internally to build player movement tracks
type positionTrack struct {
	positions    []rawPosition
	lastX, lastY float32
}

// Movement packet markers identified through binary analysis.
// The 607385fe marker contains player position data for all players in spectator replays.
//
// KEY DISCOVERY: Type 0x03 packets contain a player ID at post-coord offset +20,
// and type 0x01 packets contain it at offset +4. This ID maps to the header player
// index via: playerIndex = playerID - 5 (for values 5-14 representing 10 players).
//
// This allows PROGRAMMATIC player identification without behavioral matching.
//
// EXPERIMENTAL: Type 0x3F packets (identified in PR #105 as "C0 3F") may contain
// additional movement data. When ExperimentalTypes is enabled, these are captured
// separately for analysis. Their internal structure is not yet fully understood.
var movementMarkers = [][]byte{
	// Player position marker
	{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe},
}

// readPlayerPosition captures raw position data for later track assignment.
// Each movement packet has:
//   - 4-byte entity ID in the 4 bytes BEFORE the marker
//   - Player ID in the post-coordinate bytes:
//     - Type 0x03: at offset +20 (bytes 34-37 from marker)
//     - Type 0x01/0x02: at offset +4 (bytes 18-21 from marker)
//   - Player ID maps to header index via: playerIndex = playerID - 5
func readPlayerPosition(r *Reader) error {
	if !r.TrackMovement {
		return nil
	}

	// Increment global packet counter
	r.movementCounter++
	packetNum := r.movementCounter

	// Apply sampling if configured
	if r.MovementSampleRate > 1 && packetNum%r.MovementSampleRate != 0 {
		return nil
	}

	// Extract entity ID from 4 bytes BEFORE the marker
	// The marker is 6 bytes, and r.offset is now at the byte after the marker
	// So the 4 bytes before the marker are at offset-6-4 to offset-6
	markerLen := 6
	entityID := uint32(0)
	if r.offset >= markerLen+4 {
		idBytes := r.b[r.offset-markerLen-4 : r.offset-markerLen]
		entityID = binary.LittleEndian.Uint32(idBytes)
	}

	// Read type bytes (2 bytes after marker)
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	typeSecond := typeBytes[1]
	typeFirst := typeBytes[0]

	// Accept 01, 02, and 03 suffix types (all contain player world positions)
	// 0x01 and 0x02 share the same structure (player ID at post-coord +4)
	// 0x03 is the full packet (player ID at post-coord +20, includes quaternion)
	// Experimentally capture other types when enabled
	if typeSecond != 0x01 && typeSecond != 0x02 && typeSecond != 0x03 {
		if r.ExperimentalTypes && typeFirst >= 0xB0 {
			captureExperimentalPacket(r, typeFirst, typeSecond, packetNum)
		}
		return nil
	}

	// Filter to B0xx, B8xx, BCxx, B4xx types (position packet families)
	if typeFirst < 0xB0 {
		return nil
	}

	// Read coordinates (immediately after type bytes)
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

	// Validate coordinates
	if !isValidWorldCoord(x) || !isValidWorldCoord(y) || !isValidWorldCoord(z) {
		return nil
	}

	// Z should be in reasonable floor range (-10 to 50 for most maps)
	if z < -10 || z > 50 {
		return nil
	}

	// Extract player ID and yaw based on packet type
	var playerID uint32 = 0
	var yaw float32 = 0

	if typeSecond == 0x03 {
		// Type 0x03: Player ID at post-coord offset +20, Quat2 at offset 46-62
		postBytes, err := r.Bytes(62)
		if err == nil && len(postBytes) >= 62 {
			// Player ID at offset 20-23 after coordinates
			playerID = binary.LittleEndian.Uint32(postBytes[20:24])

			// Quat2 at offset 46-62 (camera orientation)
			qx := readFloat32LE(postBytes[46:50])
			qy := readFloat32LE(postBytes[50:54])
			qz := readFloat32LE(postBytes[54:58])
			qw := readFloat32LE(postBytes[58:62])
			yaw = quaternionToYaw(qx, qy, qz, qw)
		}
	} else {
		// Type 0x01 and 0x02: Player ID at post-coord offset +4
		// Both share the same compact structure
		postBytes, err := r.Bytes(8)
		if err == nil && len(postBytes) >= 8 {
			// Player ID at offset 4-7 after coordinates
			playerID = binary.LittleEndian.Uint32(postBytes[4:8])
		}
	}

	if r.rawPositions == nil {
		r.rawPositions = make([]rawPosition, 0, 50000)
	}

	r.rawPositions = append(r.rawPositions, rawPosition{
		packetNum: packetNum,
		entityID:  entityID,
		playerID:  playerID,
		x:         x,
		y:         y,
		z:         z,
		yaw:       yaw,
	})

	return nil
}

// readFloat32LE reads a little-endian float32 from bytes
func readFloat32LE(b []byte) float32 {
	if len(b) < 4 {
		return 0
	}
	bits := binary.LittleEndian.Uint32(b)
	return math.Float32frombits(bits)
}

// quaternionToYaw converts a quaternion to yaw angle in degrees
// Uses the full 3D camera/aim quaternion (Quat2) which represents where
// the player is actually looking, not just body orientation
func quaternionToYaw(x, y, z, w float32) float32 {
	// Check for invalid quaternion components
	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) || math.IsNaN(float64(w)) {
		return 0
	}
	if math.IsInf(float64(x), 0) || math.IsInf(float64(y), 0) || math.IsInf(float64(z), 0) || math.IsInf(float64(w), 0) {
		return 0
	}
	// Convert quaternion to yaw (Z-axis rotation)
	sinyCosp := 2 * (float64(w)*float64(z) + float64(x)*float64(y))
	cosyCosp := 1 - 2*(float64(y)*float64(y)+float64(z)*float64(z))
	yaw := math.Atan2(sinyCosp, cosyCosp) * 180 / math.Pi
	if math.IsNaN(yaw) || math.IsInf(yaw, 0) {
		return 0
	}
	return float32(yaw)
}

// isValidWorldCoord checks if a coordinate is within reasonable world bounds.
func isValidWorldCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

// GetMovementData builds player movement tracks using pure spatial tracking.
//
// The player ID field in movement packets (values 5-14) is unreliable for
// per-position attribution -- 59% of map locations have positions tagged with
// multiple player IDs (cross-contamination). Entity IDs rotate every few seconds.
//
// Instead, this function:
//  1. Pools ALL raw positions regardless of player ID
//  2. Sorts by packet number (stream order)
//  3. Assigns each position to the nearest active track within threshold
//  4. Creates new tracks when no existing track is close enough
//  5. Keeps the top N tracks by size (N = number of players)
//  6. Assigns tracks to players using prep-phase movement (defenders move more)
//     and player ID majority vote as a secondary hint
func (r *Reader) GetMovementData() []PlayerMovement {
	if len(r.rawPositions) == 0 {
		return nil
	}

	numPlayers := len(r.Header.Players)
	if numPlayers == 0 {
		return nil
	}

	// --- Time estimation ---
	var minPkt, maxPkt int = -1, -1
	for _, pos := range r.rawPositions {
		if minPkt < 0 || pos.packetNum < minPkt {
			minPkt = pos.packetNum
		}
		if pos.packetNum > maxPkt {
			maxPkt = pos.packetNum
		}
	}
	pktRange := float64(maxPkt - minPkt)
	if pktRange <= 0 {
		pktRange = 1
	}

	var minCountdown float64 = 180
	for _, event := range r.MatchFeedback {
		if event.TimeInSeconds > 0 && event.TimeInSeconds < minCountdown {
			minCountdown = event.TimeInSeconds
		}
	}
	actionDuration := 180.0 - minCountdown
	if actionDuration < 10 || math.IsNaN(actionDuration) || math.IsInf(actionDuration, 0) {
		actionDuration = 180.0
	}
	totalTime := 45.0 + actionDuration
	if totalTime <= 0 || math.IsNaN(totalTime) || math.IsInf(totalTime, 0) {
		totalTime = 225.0
	}
	pktToTime := func(pkt int) float64 {
		return (float64(pkt-minPkt) / pktRange) * totalTime
	}

	dist2D := func(x1, y1, x2, y2 float32) float32 {
		dx := x1 - x2
		dy := y1 - y2
		return float32(math.Sqrt(float64(dx*dx + dy*dy)))
	}

	// --- Step 1: Sort all positions by packet number ---
	sorted := make([]rawPosition, len(r.rawPositions))
	copy(sorted, r.rawPositions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].packetNum < sorted[j].packetNum
	})

	// --- Step 2: Build tracks using nearest-neighbor assignment ---
	const trackThreshold float32 = 1.8 // max distance to assign to existing track

	type spatialTrack struct {
		positions []rawPosition
		lastX     float32
		lastY     float32
		lastPkt   int
	}

	tracks := make([]*spatialTrack, 0, 20)

	for _, pos := range sorted {
		// Find nearest active track
		bestTrack := -1
		bestDist := float32(math.MaxFloat32)

		for i, t := range tracks {
			d := dist2D(pos.x, pos.y, t.lastX, t.lastY)
			if d < bestDist {
				bestDist = d
				bestTrack = i
			}
		}

		if bestTrack >= 0 && bestDist <= trackThreshold {
			// Assign to existing track
			tracks[bestTrack].positions = append(tracks[bestTrack].positions, pos)
			tracks[bestTrack].lastX = pos.x
			tracks[bestTrack].lastY = pos.y
			tracks[bestTrack].lastPkt = pos.packetNum
		} else {
			// Create new track
			tracks = append(tracks, &spatialTrack{
				positions: []rawPosition{pos},
				lastX:     pos.x,
				lastY:     pos.y,
				lastPkt:   pos.packetNum,
			})
		}
	}

	// --- Step 3: Keep top tracks by size ---
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].positions) > len(tracks[j].positions)
	})

	// Keep at most numPlayers tracks, with a minimum size and real XY movement.
	// Tracks stuck near the origin (0,0) with no XY spread are static entities
	// (spectator camera, reference points) -- not players.
	const minTrackSize = 30
	const minXYSpread float32 = 2.0 // minimum XY bounding box dimension to be a real player

	var playerTracks []*spatialTrack
	for _, t := range tracks {
		if len(t.positions) < minTrackSize {
			break
		}

		// Calculate XY bounding box
		var minX, maxX, minY, maxY float32
		minX, maxX = t.positions[0].x, t.positions[0].x
		minY, maxY = t.positions[0].y, t.positions[0].y
		for _, p := range t.positions {
			if p.x < minX { minX = p.x }
			if p.x > maxX { maxX = p.x }
			if p.y < minY { minY = p.y }
			if p.y > maxY { maxY = p.y }
		}
		xSpread := maxX - minX
		ySpread := maxY - minY

		// Skip tracks with negligible XY movement (static objects at origin, etc.)
		if xSpread < minXYSpread && ySpread < minXYSpread {
			continue
		}

		playerTracks = append(playerTracks, t)
		if len(playerTracks) >= numPlayers {
			break
		}
	}

	// --- Step 4: Assign tracks to players ---
	// Use prep-phase movement to separate defenders (high movement) from attackers (low movement)
	prepPktFraction := 45.0 / totalTime
	prepPhaseEndPkt := minPkt + int(pktRange*prepPktFraction)

	type trackMeta struct {
		track         *spatialTrack
		prepPhaseMove float32
		majorityPID   uint32  // most common player ID in this track (hint only)
		trackEndTime  float64 // elapsed time of last position in this track
	}
	var metas []trackMeta

	for _, t := range playerTracks {
		// Calculate prep phase total distance
		var prepMove float32
		for i := 1; i < len(t.positions); i++ {
			if t.positions[i].packetNum > prepPhaseEndPkt {
				break
			}
			prepMove += dist2D(t.positions[i].x, t.positions[i].y, t.positions[i-1].x, t.positions[i-1].y)
		}

		// Find majority player ID as a hint
		pidCounts := make(map[uint32]int)
		for _, pos := range t.positions {
			if pos.playerID >= 5 && pos.playerID <= 14 {
				pidCounts[pos.playerID]++
			}
		}
		var bestPID uint32
		bestCount := 0
		for pid, cnt := range pidCounts {
			if cnt > bestCount {
				bestCount = cnt
				bestPID = pid
			}
		}

		metas = append(metas, trackMeta{track: t, prepPhaseMove: prepMove, majorityPID: bestPID})
	}

	// Sort by prep movement: defenders first (high movement)
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].prepPhaseMove > metas[j].prepPhaseMove
	})

	// Build player info with death times from match feedback
	type playerInfo struct {
		username  string
		operator  string
		team      string
		loadout   *PlayerLoadout
		deathTime float64 // -1 if survived
	}

	// Extract death times from match feedback
	deathTimes := make(map[string]float64)
	for _, ev := range r.MatchFeedback {
		if ev.Type == Kill && ev.Target != "" {
			deathTimes[ev.Target] = ev.TimeInSeconds
		}
		if ev.Type == Death {
			deathTimes[ev.Username] = ev.TimeInSeconds
		}
	}

	var defenders, attackers []playerInfo
	for _, p := range r.Header.Players {
		teamRole := "Unknown"
		if p.TeamIndex >= 0 && p.TeamIndex < len(r.Header.Teams) {
			if r.Header.Teams[p.TeamIndex].Role == Attack {
				teamRole = "Attack"
			} else if r.Header.Teams[p.TeamIndex].Role == Defense {
				teamRole = "Defense"
			}
		}
		dt := -1.0
		if t, died := deathTimes[p.Username]; died {
			dt = t
		}
		pi := playerInfo{
			username:  p.Username,
			operator:  p.Operator.String(),
			team:      teamRole,
			loadout:   p.Loadout,
			deathTime: dt,
		}
		if teamRole == "Defense" {
			defenders = append(defenders, pi)
		} else {
			attackers = append(attackers, pi)
		}
	}

	// Compute track end time for each meta
	for i := range metas {
		t := metas[i].track
		lastPkt := t.positions[len(t.positions)-1].packetNum
		metas[i].trackEndTime = pktToTime(lastPkt)
	}

	// Split tracks into defender group (first N by prep movement) and attacker group
	var defTracks, atkTracks []trackMeta
	for _, meta := range metas {
		if len(defTracks) < len(defenders) {
			defTracks = append(defTracks, meta)
		} else {
			atkTracks = append(atkTracks, meta)
		}
	}

	// matchTracksToPlayers assigns tracks to players using death-time matching.
	// Players who died get tracks whose end time is closest to the death time.
	// Survivors get the remaining tracks.
	type playerTrackPair struct {
		player playerInfo
		track  trackMeta
	}
	matchTracksToPlayers := func(players []playerInfo, tracks []trackMeta) []playerTrackPair {
		if len(players) == 0 || len(tracks) == 0 {
			return nil
		}

		used := make([]bool, len(tracks))
		var result []playerTrackPair

		// Separate players who died from survivors
		type deathEntry struct {
			idx       int
			deathTime float64 // countdown seconds (higher = earlier in round)
		}
		var died []deathEntry
		var survived []int
		for i, p := range players {
			if p.deathTime >= 0 {
				died = append(died, deathEntry{i, p.deathTime})
			} else {
				survived = append(survived, i)
			}
		}

		// Order-based matching for dead players:
		// In R6 countdown time, HIGHER deathTime = died EARLIER = shorter track.
		// Sort deaths: highest countdown first (earliest death = shortest expected track).
		// Sort tracks: shortest end time first.
		// Match in order: earliest death → shortest track.
		sort.Slice(died, func(i, j int) bool {
			return died[i].deathTime > died[j].deathTime // highest countdown = earliest death
		})

		// Sort track indices by end time ascending (shortest first)
		trackOrder := make([]int, len(tracks))
		for i := range trackOrder {
			trackOrder[i] = i
		}
		sort.Slice(trackOrder, func(i, j int) bool {
			return tracks[trackOrder[i]].trackEndTime < tracks[trackOrder[j]].trackEndTime
		})

		// Match each dead player to the next available shortest track
		trackCursor := 0
		for _, d := range died {
			for trackCursor < len(trackOrder) && used[trackOrder[trackCursor]] {
				trackCursor++
			}
			if trackCursor < len(trackOrder) {
				ti := trackOrder[trackCursor]
				used[ti] = true
				result = append(result, playerTrackPair{players[d.idx], tracks[ti]})
				trackCursor++
			}
		}

		// Assign survivors to remaining tracks (longest first for best coverage)
		var remainingTracks []int
		for _, ti := range trackOrder {
			if !used[ti] {
				remainingTracks = append(remainingTracks, ti)
			}
		}
		// Sort remaining by size descending
		sort.Slice(remainingTracks, func(i, j int) bool {
			return len(tracks[remainingTracks[i]].track.positions) > len(tracks[remainingTracks[j]].track.positions)
		})

		for i, si := range survived {
			if i < len(remainingTracks) {
				ti := remainingTracks[i]
				used[ti] = true
				result = append(result, playerTrackPair{players[si], tracks[ti]})
			}
		}

		return result
	}

	defPairs := matchTracksToPlayers(defenders, defTracks)
	atkPairs := matchTracksToPlayers(attackers, atkTracks)

	// Build final result
	result := make([]PlayerMovement, 0, len(defPairs)+len(atkPairs))

	for _, pairs := range [][]playerTrackPair{defPairs, atkPairs} {
		for _, p := range pairs {
			var positions []PlayerPosition
			for _, pos := range p.track.track.positions {
				t := pktToTime(pos.packetNum)
				if math.IsNaN(t) || math.IsInf(t, 0) {
					t = 0
				}
				yaw := pos.yaw
				if math.IsNaN(float64(yaw)) || math.IsInf(float64(yaw), 0) {
					yaw = 0
				}
				positions = append(positions, PlayerPosition{
					TimeInSeconds: t,
					X:             pos.x,
					Y:             pos.y,
					Z:             pos.z,
					Yaw:           yaw,
				})
			}

			result = append(result, PlayerMovement{
				Username:  p.player.username,
				Operator:  p.player.operator,
				Team:      p.player.team,
				Loadout:   p.player.loadout,
				Positions: positions,
			})
		}
	}

	return result
}

// buildTracksByEntityID groups raw positions by their entity ID.
// This is more reliable than position continuity as each entity has a unique ID.
func buildTracksByEntityID(positions []rawPosition) []*positionTrack {
	tracksByID := make(map[uint32]*positionTrack)

	for _, pos := range positions {
		if tracksByID[pos.entityID] == nil {
			tracksByID[pos.entityID] = &positionTrack{
				positions: make([]rawPosition, 0, 1000),
			}
		}
		tracksByID[pos.entityID].positions = append(tracksByID[pos.entityID].positions, pos)
		tracksByID[pos.entityID].lastX = pos.x
		tracksByID[pos.entityID].lastY = pos.y
	}

	// Convert map to slice
	tracks := make([]*positionTrack, 0, len(tracksByID))
	for _, t := range tracksByID {
		tracks = append(tracks, t)
	}

	return tracks
}

// buildTracks groups raw positions into continuous movement tracks (fallback method).
// Positions are assigned to the nearest existing track within threshold,
// or a new track is created if no track is close enough.
func buildTracks(positions []rawPosition, threshold float32) []*positionTrack {
	tracks := make([]*positionTrack, 0, 12)

	for _, pos := range positions {
		// Find nearest track
		bestTrack := -1
		bestDist := float32(math.MaxFloat32)

		for i, t := range tracks {
			dx := pos.x - t.lastX
			dy := pos.y - t.lastY
			dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))
			if dist < bestDist {
				bestDist = dist
				bestTrack = i
			}
		}

		if bestTrack >= 0 && bestDist <= threshold {
			// Assign to existing track
			tracks[bestTrack].positions = append(tracks[bestTrack].positions, pos)
			tracks[bestTrack].lastX = pos.x
			tracks[bestTrack].lastY = pos.y
		} else {
			// Create new track
			newTrack := &positionTrack{
				positions: []rawPosition{pos},
				lastX:     pos.x,
				lastY:     pos.y,
			}
			tracks = append(tracks, newTrack)
		}
	}

	return tracks
}

// captureExperimentalPacket captures non-standard packet types for research.
// Called when ExperimentalTypes is enabled and a non-01/non-03 suffix is encountered.
func captureExperimentalPacket(r *Reader, typeFirst, typeSecond byte, packetNum int) {
	// Extract entity ID from 4 bytes BEFORE the marker (same as standard packets)
	markerLen := 6
	entityID := uint32(0)
	if r.offset >= markerLen+4 {
		idBytes := r.b[r.offset-markerLen-4 : r.offset-markerLen]
		entityID = binary.LittleEndian.Uint32(idBytes)
	}

	// Try reading what would be coordinates at the standard offset
	// (immediately after type bytes, same as 0x01/0x03)
	x, errX := r.Float32()
	y, errY := r.Float32()
	z, errZ := r.Float32()

	hasCoords := errX == nil && errY == nil && errZ == nil &&
		isValidWorldCoord(x) && isValidWorldCoord(y) &&
		z >= -10 && z <= 50

	// Read additional raw bytes for offline analysis
	var rawPost []byte
	postBytes, err := r.Bytes(64)
	if err == nil {
		rawPost = make([]byte, len(postBytes))
		copy(rawPost, postBytes)
	}

	pkt := ExperimentalPacket{
		PacketNum:  packetNum,
		TypeFirst:  typeFirst,
		TypeSecond: typeSecond,
		EntityID:   entityID,
		HasCoords:  hasCoords,
		RawPost:    rawPost,
	}
	if hasCoords {
		pkt.X = x
		pkt.Y = y
		pkt.Z = z
	}

	r.experimentalPositions = append(r.experimentalPositions, pkt)
}

// EnableMovementTracking enables movement packet tracking.
// sampleRate controls how often positions are recorded:
//   - 0 = record all positions (high memory usage)
//   - 1 = record every position
//   - N = record every Nth position
func (r *Reader) EnableMovementTracking(sampleRate int) {
	r.TrackMovement = true
	r.MovementSampleRate = sampleRate
	r.rawPositions = make([]rawPosition, 0, 50000)
}

// RawPosition is an exported version of rawPosition for diagnostic tools
type RawPosition struct {
	PacketNum int
	EntityID  uint32
	PlayerID  uint32 // Player ID from packet (maps to header index via playerID-5)
	X, Y, Z   float32
	Yaw       float32
}

// GetExperimentalPackets returns packets captured from non-standard types.
// Only populated when ExperimentalTypes is enabled.
func (r *Reader) GetExperimentalPackets() []ExperimentalPacket {
	return r.experimentalPositions
}

// ExperimentalSummary returns a human-readable summary of experimental packet capture.
func (r *Reader) ExperimentalSummary() string {
	if len(r.experimentalPositions) == 0 {
		return "No experimental packets captured."
	}

	typeCounts := make(map[byte]int)
	coordCounts := make(map[byte]int)
	for _, p := range r.experimentalPositions {
		typeCounts[p.TypeSecond]++
		if p.HasCoords {
			coordCounts[p.TypeSecond]++
		}
	}

	result := fmt.Sprintf("Experimental packets: %d total\n", len(r.experimentalPositions))
	for suffix, count := range typeCounts {
		withCoords := coordCounts[suffix]
		result += fmt.Sprintf("  Suffix 0x%02X: %d packets, %d with valid coords (%.1f%%)\n",
			suffix, count, withCoords, float64(withCoords)/float64(count)*100)
	}
	return result
}

// GetRawPositions returns the raw position data for diagnostic purposes
func (r *Reader) GetRawPositions() []RawPosition {
	result := make([]RawPosition, len(r.rawPositions))
	for i, p := range r.rawPositions {
		result[i] = RawPosition{
			PacketNum: p.packetNum,
			EntityID:  p.entityID,
			PlayerID:  p.playerID,
			X:         p.x,
			Y:         p.y,
			Z:         p.z,
			Yaw:       p.yaw,
		}
	}
	return result
}

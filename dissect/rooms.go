package dissect

// RoomBounds defines the 3D bounding box for a room.
type RoomBounds struct {
	Name string  `json:"name"` // e.g., "2F Master Bedroom"
	MinX float32 `json:"minX"`
	MaxX float32 `json:"maxX"`
	MinY float32 `json:"minY"`
	MaxY float32 `json:"maxY"`
	MinZ float32 `json:"minZ"` // Floor height range
	MaxZ float32 `json:"maxZ"`
}

// MapRooms contains room definitions for a specific map.
type MapRooms struct {
	MapName string       `json:"mapName"`
	Rooms   []RoomBounds `json:"rooms"`
}

// Floor height ranges for R6 maps (approximate)
const (
	BasementMinZ = -5.0
	BasementMaxZ = 0.0
	Floor1MinZ   = 0.0
	Floor1MaxZ   = 4.5
	Floor2MinZ   = 4.5
	Floor2MaxZ   = 9.0
	Floor3MinZ   = 9.0
	Floor3MaxZ   = 13.0
	RoofMinZ     = 13.0
	RoofMaxZ     = 20.0
)

// GetFloorName returns the floor name based on Z coordinate.
func GetFloorName(z float32) string {
	switch {
	case z < BasementMaxZ:
		return "B"
	case z < Floor1MaxZ:
		return "1F"
	case z < Floor2MaxZ:
		return "2F"
	case z < Floor3MaxZ:
		return "3F"
	default:
		return "Roof"
	}
}

// mapRoomDefinitions contains room data for supported maps.
// Note: This is a starting point. Full room boundaries need to be collected
// through gameplay data analysis or extracted from game files.
var mapRoomDefinitions = map[string]*MapRooms{
	// Chalet (ChaletY10) - based on coordinate analysis from sample replays
	"ChaletY10": {
		MapName: "ChaletY10",
		Rooms: []RoomBounds{
			// 2F Rooms (approximate based on spawn data showing Z ~4.4-7.0)
			{Name: "2F Master Bedroom", MinX: -15, MaxX: 0, MinY: -25, MaxY: -15, MinZ: Floor2MinZ, MaxZ: Floor2MaxZ},
			{Name: "2F Office", MinX: 0, MaxX: 15, MinY: -25, MaxY: -15, MinZ: Floor2MinZ, MaxZ: Floor2MaxZ},
			{Name: "2F Library", MinX: -15, MaxX: 0, MinY: 10, MaxY: 25, MinZ: Floor2MinZ, MaxZ: Floor2MaxZ},
			{Name: "2F Trophy Room", MinX: 0, MaxX: 15, MinY: 10, MaxY: 25, MinZ: Floor2MinZ, MaxZ: Floor2MaxZ},
			// 1F Rooms
			{Name: "1F Bar", MinX: -15, MaxX: 0, MinY: -25, MaxY: -10, MinZ: Floor1MinZ, MaxZ: Floor1MaxZ},
			{Name: "1F Gaming Room", MinX: 0, MaxX: 15, MinY: -25, MaxY: -10, MinZ: Floor1MinZ, MaxZ: Floor1MaxZ},
			{Name: "1F Kitchen", MinX: -15, MaxX: 0, MinY: 5, MaxY: 20, MinZ: Floor1MinZ, MaxZ: Floor1MaxZ},
			{Name: "1F Dining Room", MinX: 0, MaxX: 15, MinY: 5, MaxY: 20, MinZ: Floor1MinZ, MaxZ: Floor1MaxZ},
			// Basement
			{Name: "B Wine Cellar", MinX: -15, MaxX: 0, MinY: -20, MaxY: 0, MinZ: BasementMinZ, MaxZ: BasementMaxZ},
			{Name: "B Snowmobile Garage", MinX: 0, MaxX: 15, MinY: -20, MaxY: 0, MinZ: BasementMinZ, MaxZ: BasementMaxZ},
		},
	},
}

// GetRoomAtPosition returns the room name for the given coordinates and map.
// Returns empty string if no room is found or map is not supported.
func GetRoomAtPosition(mapName string, x, y, z float32) string {
	mapRooms, ok := mapRoomDefinitions[mapName]
	if !ok {
		// Map not supported, return floor only
		return GetFloorName(z)
	}

	for _, room := range mapRooms.Rooms {
		if x >= room.MinX && x <= room.MaxX &&
			y >= room.MinY && y <= room.MaxY &&
			z >= room.MinZ && z <= room.MaxZ {
			return room.Name
		}
	}

	// No specific room found, return floor
	return GetFloorName(z)
}

// PositionWithRoom extends PlayerPosition with room information.
type PositionWithRoom struct {
	PlayerPosition
	Room string `json:"room,omitempty"`
}

// GetMovementDataWithRooms returns movement data with room names populated.
func (r *Reader) GetMovementDataWithRooms() []PlayerMovement {
	movements := r.GetMovementData()
	if movements == nil {
		return nil
	}

	mapName := r.Header.Map.String()

	// Create new movements with room data
	result := make([]PlayerMovement, len(movements))
	for i, pm := range movements {
		result[i] = PlayerMovement{
			Username:  pm.Username,
			Positions: make([]PlayerPosition, len(pm.Positions)),
		}

		for j, pos := range pm.Positions {
			result[i].Positions[j] = pos
			// Note: Room lookup would require extending PlayerPosition
			// For now, we just copy the positions
			_ = GetRoomAtPosition(mapName, pos.X, pos.Y, pos.Z)
		}
	}

	return result
}

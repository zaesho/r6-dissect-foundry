package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

type PacketRecord struct {
	PacketNum int
	Type1     byte
	Type2     byte
	X, Y, Z   float32
	PostBytes []byte
}

var (
	positionMarker = []byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}
	allPackets     []PacketRecord
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: yawtest <replay.rec>")
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

	r.Listen(positionMarker, capturePacket)
	r.Read()

	fmt.Println("=== YAW INTERPRETATION TEST ===")
	fmt.Println("Testing different quaternion orderings and yaw formulas\n")

	// Find a sequence where a player is clearly moving in one direction
	// If moving along +X, they should be facing ~0° or ~180°
	// If moving along +Y, they should be facing ~90° or ~-90°

	// Find packets with consistent movement along X axis
	fmt.Println("=== MOVEMENT ANALYSIS ===")
	fmt.Println("Looking for consistent movement to validate yaw direction\n")

	// Group by approximate position to identify individual tracks
	type trackPos struct {
		pkt PacketRecord
		yaw [4]float64 // Different yaw interpretations
	}

	var sampleTrack []trackPos
	var lastX, lastY float32 = 0, 0
	threshold := float32(2.0)

	for _, p := range allPackets {
		if p.Type2 != 0x03 || len(p.PostBytes) < 20 {
			continue
		}

		// Simple track following for first track we find
		if len(sampleTrack) == 0 {
			lastX, lastY = p.X, p.Y
		}

		dx := p.X - lastX
		dy := p.Y - lastY
		dist := float32(math.Sqrt(float64(dx*dx + dy*dy)))

		if dist <= threshold || len(sampleTrack) == 0 {
			q0 := float64(readFloat32(p.PostBytes[4:8]))
			q1 := float64(readFloat32(p.PostBytes[8:12]))
			q2 := float64(readFloat32(p.PostBytes[12:16]))
			q3 := float64(readFloat32(p.PostBytes[16:20]))

			// Try different interpretations
			yawXYZW := yawFromQuat_XYZW(q0, q1, q2, q3)
			yawWXYZ := yawFromQuat_WXYZ(q3, q0, q1, q2) // treat q3 as W
			yawAlt := yawFromQuat_Alternative(q0, q1, q2, q3)
			yawYUp := yawFromQuat_YUp(q0, q1, q2, q3)

			sampleTrack = append(sampleTrack, trackPos{
				pkt: p,
				yaw: [4]float64{yawXYZW, yawWXYZ, yawAlt, yawYUp},
			})
			lastX, lastY = p.X, p.Y

			if len(sampleTrack) >= 50 {
				break
			}
		}
	}

	fmt.Println("Sample track with different yaw interpretations:")
	fmt.Printf("%-6s %-12s %-12s %-12s %-12s %-12s %-12s\n",
		"Idx", "Position", "DeltaPos", "Yaw(XYZW)", "Yaw(WXYZ)", "Yaw(Alt)", "Yaw(YUp)")
	fmt.Println("-----------------------------------------------------------------------------------------")

	for i, tp := range sampleTrack {
		dx, dy := float32(0), float32(0)
		if i > 0 {
			dx = tp.pkt.X - sampleTrack[i-1].pkt.X
			dy = tp.pkt.Y - sampleTrack[i-1].pkt.Y
		}

		// Calculate expected yaw from movement direction
		movementYaw := float64(0)
		if dx != 0 || dy != 0 {
			movementYaw = math.Atan2(float64(dy), float64(dx)) * 180 / math.Pi
		}

		fmt.Printf("%-6d (%.1f,%.1f)    (%.2f,%.2f)    %-12.1f %-12.1f %-12.1f %-12.1f [expected: %.1f]\n",
			i, tp.pkt.X, tp.pkt.Y, dx, dy,
			tp.yaw[0], tp.yaw[1], tp.yaw[2], tp.yaw[3], movementYaw)
	}

	// Also test with specific known scenarios
	fmt.Println("\n\n=== RAW QUATERNION VALUES ===")
	fmt.Println("First 20 type 0x03 packets with raw quaternion components:\n")
	fmt.Printf("%-6s %-14s %-10s %-10s %-10s %-10s\n",
		"Pkt", "Position", "Q0", "Q1", "Q2", "Q3")
	fmt.Println("-------------------------------------------------------------------")

	count := 0
	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 20 && count < 20 {
			q0 := readFloat32(p.PostBytes[4:8])
			q1 := readFloat32(p.PostBytes[8:12])
			q2 := readFloat32(p.PostBytes[12:16])
			q3 := readFloat32(p.PostBytes[16:20])

			fmt.Printf("%-6d (%.1f,%.1f,%.1f) %-10.4f %-10.4f %-10.4f %-10.4f\n",
				p.PacketNum, p.X, p.Y, p.Z, q0, q1, q2, q3)
			count++
		}
	}

	// Test: When Q2 and Q3 form a unit quaternion with Q0,Q1 near 0,
	// the angle is 2*atan2(Q2, Q3)
	fmt.Println("\n\n=== SIMPLE Z-ROTATION INTERPRETATION ===")
	fmt.Println("When qx≈0, qy≈0: angle = 2*atan2(qz, qw)\n")

	count = 0
	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 20 && count < 20 {
			q0 := float64(readFloat32(p.PostBytes[4:8]))
			q1 := float64(readFloat32(p.PostBytes[8:12]))
			q2 := float64(readFloat32(p.PostBytes[12:16]))
			q3 := float64(readFloat32(p.PostBytes[16:20]))

			// Simple Z-rotation formula
			angle1 := 2 * math.Atan2(q2, q3) * 180 / math.Pi
			angle2 := 2 * math.Atan2(q3, q2) * 180 / math.Pi // Swapped

			// Check if qx and qy are near zero (pure Z rotation)
			isSimpleZ := math.Abs(q0) < 0.1 && math.Abs(q1) < 0.1

			fmt.Printf("Pkt %-6d: atan2(q2,q3)*2 = %7.1f°, atan2(q3,q2)*2 = %7.1f° [simpleZ: %v]\n",
				p.PacketNum, angle1, angle2, isSimpleZ)
			count++
		}
	}
}

func capturePacket(r *dissect.Reader) error {
	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}

	type1 := typeBytes[0]
	type2 := typeBytes[1]

	if type1 < 0xB0 {
		return nil
	}

	x, _ := r.Float32()
	y, _ := r.Float32()
	z, _ := r.Float32()

	if !isValidCoord(x) || !isValidCoord(y) {
		return nil
	}

	postBytes, _ := r.Bytes(64)

	allPackets = append(allPackets, PacketRecord{
		PacketNum: len(allPackets),
		Type1:     type1,
		Type2:     type2,
		X:         x,
		Y:         y,
		Z:         z,
		PostBytes: postBytes,
	})

	return nil
}

func isValidCoord(f float32) bool {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return false
	}
	return f >= -100 && f <= 100
}

func readFloat32(b []byte) float32 {
	if len(b) < 4 {
		return 0
	}
	bits := binary.LittleEndian.Uint32(b)
	return math.Float32frombits(bits)
}

// Standard XYZW quaternion to yaw (Z-up coordinate system)
func yawFromQuat_XYZW(x, y, z, w float64) float64 {
	siny_cosp := 2 * (w*z + x*y)
	cosy_cosp := 1 - 2*(y*y+z*z)
	return math.Atan2(siny_cosp, cosy_cosp) * 180 / math.Pi
}

// WXYZ ordering (W first)
func yawFromQuat_WXYZ(w, x, y, z float64) float64 {
	siny_cosp := 2 * (w*z + x*y)
	cosy_cosp := 1 - 2*(y*y+z*z)
	return math.Atan2(siny_cosp, cosy_cosp) * 180 / math.Pi
}

// Alternative formula using different axes
func yawFromQuat_Alternative(x, y, z, w float64) float64 {
	// For Y-up systems, yaw might be around Y axis
	siny_cosp := 2 * (w*y + x*z)
	cosy_cosp := 1 - 2*(x*x+y*y)
	return math.Atan2(siny_cosp, cosy_cosp) * 180 / math.Pi
}

// Y-up coordinate system interpretation
func yawFromQuat_YUp(x, y, z, w float64) float64 {
	// In Y-up systems, yaw (heading) rotates around Y axis
	// Standard formula: atan2(2*(w*y + x*z), 1 - 2*(x*x + y*y))
	// But if the game swaps axes...
	siny_cosp := 2 * (w*y - x*z)
	cosy_cosp := 1 - 2*(z*z+y*y)
	return math.Atan2(siny_cosp, cosy_cosp) * 180 / math.Pi
}

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
		fmt.Println("Usage: rotationtest <replay.rec>")
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

	totalTime := 240.0
	timePerPacket := totalTime / float64(len(allPackets))

	fmt.Println("=== ROTATION DATA ANALYSIS ===")
	fmt.Println("Looking at type 0x03 packets (most common) for quaternion data\n")

	// Type 0x03 has floats at offsets 4-16 that look like quaternion components
	// Post-bytes structure seems to be:
	// [0-3]: something
	// [4-7]: float (range -0.5 to 0.5) - possibly quat X
	// [8-11]: float (range -0.5 to 0.7) - possibly quat Y  
	// [12-15]: float (range -0.9 to 1.0) - possibly quat Z or W
	// [16-19]: float (range -0.5 to 1.0) - possibly quat W or Z

	// Sample some type 0x03 packets
	fmt.Println("Sample Type 0x03 packets with potential rotation data:\n")
	fmt.Printf("%-8s %-12s %-10s %-10s %-10s %-10s %-10s\n",
		"Packet", "Time", "Pos(X,Y)", "Quat0", "Quat1", "Quat2", "Quat3")
	fmt.Println("-------------------------------------------------------------------------")

	count := 0
	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 20 && count < 30 {
			t := float64(p.PacketNum) * timePerPacket

			q0 := readFloat32(p.PostBytes[4:8])
			q1 := readFloat32(p.PostBytes[8:12])
			q2 := readFloat32(p.PostBytes[12:16])
			q3 := readFloat32(p.PostBytes[16:20])

			fmt.Printf("%-8d %-12.1fs (%.1f,%.1f)    %-10.4f %-10.4f %-10.4f %-10.4f\n",
				p.PacketNum, t, p.X, p.Y, q0, q1, q2, q3)
			count++
		}
	}

	// Analyze type 0x01 packets rotation data
	fmt.Println("\n\n=== TYPE 0x01 ROTATION DATA ===")
	fmt.Println("Looking at offsets 14-38 for rotation values\n")

	fmt.Printf("%-8s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s\n",
		"Packet", "Time", "f@14", "f@18", "f@22", "f@26", "f@30", "f@34", "f@38")
	fmt.Println("---------------------------------------------------------------------------------------------------")

	count = 0
	for _, p := range allPackets {
		if p.Type2 == 0x01 && len(p.PostBytes) >= 42 && count < 30 {
			t := float64(p.PacketNum) * timePerPacket

			f14 := readFloat32(p.PostBytes[14:18])
			f18 := readFloat32(p.PostBytes[18:22])
			f22 := readFloat32(p.PostBytes[22:26])
			f26 := readFloat32(p.PostBytes[26:30])
			f30 := readFloat32(p.PostBytes[30:34])
			f34 := readFloat32(p.PostBytes[34:38])
			f38 := readFloat32(p.PostBytes[38:42])

			fmt.Printf("%-8d %-10.1fs %-10.3f %-10.3f %-10.3f %-10.3f %-10.3f %-10.3f %-10.3f\n",
				p.PacketNum, t, f14, f18, f22, f26, f30, f34, f38)
			count++
		}
	}

	// Check if q0^2 + q1^2 + q2^2 + q3^2 = 1 (unit quaternion)
	fmt.Println("\n\n=== QUATERNION VALIDATION (Type 0x03) ===")
	fmt.Println("Checking if q0^2 + q1^2 + q2^2 + q3^2 ≈ 1\n")

	validQuats := 0
	totalChecked := 0
	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 20 {
			q0 := readFloat32(p.PostBytes[4:8])
			q1 := readFloat32(p.PostBytes[8:12])
			q2 := readFloat32(p.PostBytes[12:16])
			q3 := readFloat32(p.PostBytes[16:20])

			mag := q0*q0 + q1*q1 + q2*q2 + q3*q3
			if math.Abs(float64(mag)-1.0) < 0.1 {
				validQuats++
			}
			totalChecked++
		}
	}

	fmt.Printf("Unit quaternions (|q| ≈ 1): %d/%d (%.1f%%)\n", validQuats, totalChecked, float64(validQuats)*100/float64(totalChecked))

	// Try converting to Euler angles
	fmt.Println("\n\n=== EULER ANGLE CONVERSION ===")
	fmt.Println("Converting quaternions to yaw/pitch/roll\n")

	fmt.Printf("%-8s %-10s %-12s %-12s %-12s\n",
		"Packet", "Time", "Yaw(deg)", "Pitch(deg)", "Roll(deg)")
	fmt.Println("----------------------------------------------------------")

	count = 0
	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 20 && count < 20 {
			t := float64(p.PacketNum) * timePerPacket

			q0 := float64(readFloat32(p.PostBytes[4:8]))  // x
			q1 := float64(readFloat32(p.PostBytes[8:12])) // y
			q2 := float64(readFloat32(p.PostBytes[12:16])) // z
			q3 := float64(readFloat32(p.PostBytes[16:20])) // w

			// Convert quaternion to Euler angles
			// This assumes q = (x, y, z, w) ordering
			yaw, pitch, roll := quatToEuler(q0, q1, q2, q3)

			fmt.Printf("%-8d %-10.1fs %-12.1f %-12.1f %-12.1f\n",
				p.PacketNum, t, yaw, pitch, roll)
			count++
		}
	}

	// Look for rotation changes over time for one track
	fmt.Println("\n\n=== TRACKING ROTATION CHANGES FOR ONE PLAYER ===")
	fmt.Println("Following position packets near a specific area...\n")

	// Track packets near (15, 6) area
	var tracked []struct {
		t   float64
		x, y float32
		yaw float64
	}

	for _, p := range allPackets {
		if p.Type2 == 0x03 && len(p.PostBytes) >= 20 {
			// Filter to one area
			if math.Abs(float64(p.X)-15) < 5 && math.Abs(float64(p.Y)-6) < 5 {
				t := float64(p.PacketNum) * timePerPacket

				q0 := float64(readFloat32(p.PostBytes[4:8]))
				q1 := float64(readFloat32(p.PostBytes[8:12]))
				q2 := float64(readFloat32(p.PostBytes[12:16]))
				q3 := float64(readFloat32(p.PostBytes[16:20]))

				yaw, _, _ := quatToEuler(q0, q1, q2, q3)

				tracked = append(tracked, struct {
					t   float64
					x, y float32
					yaw float64
				}{t, p.X, p.Y, yaw})
			}
		}
	}

	fmt.Printf("Found %d packets in tracking area\n", len(tracked))
	fmt.Println("\nSample rotation timeline:")
	for i := 0; i < min(30, len(tracked)); i++ {
		fmt.Printf("  %.1fs: pos=(%.1f,%.1f) yaw=%.1f°\n", 
			tracked[i].t, tracked[i].x, tracked[i].y, tracked[i].yaw)
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

func quatToEuler(x, y, z, w float64) (yaw, pitch, roll float64) {
	// Convert quaternion to Euler angles (in degrees)
	// Assuming Z-up coordinate system

	// Roll (x-axis rotation)
	sinr_cosp := 2 * (w*x + y*z)
	cosr_cosp := 1 - 2*(x*x+y*y)
	roll = math.Atan2(sinr_cosp, cosr_cosp) * 180 / math.Pi

	// Pitch (y-axis rotation)
	sinp := 2 * (w*y - z*x)
	if math.Abs(sinp) >= 1 {
		pitch = math.Copysign(90, sinp)
	} else {
		pitch = math.Asin(sinp) * 180 / math.Pi
	}

	// Yaw (z-axis rotation)
	siny_cosp := 2 * (w*z + x*y)
	cosy_cosp := 1 - 2*(y*y+z*z)
	yaw = math.Atan2(siny_cosp, cosy_cosp) * 180 / math.Pi

	return yaw, pitch, roll
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

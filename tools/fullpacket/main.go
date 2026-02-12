package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/redraskal/r6-dissect/dissect"
)

type fullPacket struct {
	typeCode  uint16
	packetNum int
	// Position
	x, y, z float32
	// Post-coordinate data (likely rotation, state, etc.)
	rawPost []byte
	// Parsed fields
	playerID   int
	pitch, yaw float32 // rotation
	flags      uint32
}

var packets []fullPacket
var packetNum int

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <replay.rec>")
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

	// Capture with extended data
	r.Listen([]byte{0x00, 0x00, 0x60, 0x73, 0x85, 0xfe}, captureFullPacket)
	r.Read()

	fmt.Printf("Captured %d packets\n\n", len(packets))

	// Analyze 01-type packets (they have player IDs)
	var type01 []fullPacket
	for _, p := range packets {
		if p.typeCode&0xFF == 0x01 && p.playerID >= 1 && p.playerID <= 20 {
			type01 = append(type01, p)
		}
	}

	fmt.Printf("=== Analyzing 01-type packet structure ===\n")
	fmt.Printf("Total 01-type packets with valid player IDs: %d\n\n", len(type01))

	// Show first 20 packets in detail
	fmt.Printf("First 20 packets (raw bytes after XYZ):\n")
	for i := 0; i < 20 && i < len(type01); i++ {
		p := type01[i]
		fmt.Printf("\n[%d] Type=0x%04X PlayerID=%d Pos=(%.1f, %.1f, %.1f)\n",
			i, p.typeCode, p.playerID, p.x, p.y, p.z)
		fmt.Printf("    Raw post bytes: %02X\n", p.rawPost)
		
		// Try to interpret as floats at various offsets
		if len(p.rawPost) >= 24 {
			// Bytes 0-3: flags?
			flags := binary.LittleEndian.Uint32(p.rawPost[0:4])
			// Bytes 4-7: player ID
			// Bytes 8-11, 12-15, 16-19: possibly pitch/yaw/roll or velocity
			f1 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[8:12]))
			f2 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[12:16]))
			f3 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[16:20]))
			f4 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[20:24]))
			
			fmt.Printf("    Flags: 0x%08X\n", flags)
			fmt.Printf("    Post floats: %.3f, %.3f, %.3f, %.3f\n", f1, f2, f3, f4)
			
			// Check if any look like angles (radians: -π to π, or degrees: -180 to 180)
			if isAngle(f1) || isAngle(f2) || isAngle(f3) {
				fmt.Printf("    ^ Possible angles detected!\n")
			}
		}
	}

	// Analyze the distribution of post-byte values
	fmt.Printf("\n=== Post-byte analysis ===\n")
	
	// Check byte 0-3 (flags)
	flagCounts := make(map[uint32]int)
	for _, p := range type01 {
		if len(p.rawPost) >= 4 {
			flags := binary.LittleEndian.Uint32(p.rawPost[0:4])
			flagCounts[flags]++
		}
	}
	
	fmt.Printf("\nFlags (bytes 0-3) distribution:\n")
	printTopN(flagCounts, 15)

	// Check bytes 8-11 as float (possible pitch?)
	fmt.Printf("\nBytes 8-11 as float (possible rotation?):\n")
	var float8Samples []float32
	for _, p := range type01 {
		if len(p.rawPost) >= 12 {
			f := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[8:12]))
			if !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) {
				float8Samples = append(float8Samples, f)
			}
		}
	}
	if len(float8Samples) > 0 {
		min, max := float8Samples[0], float8Samples[0]
		var sum float64
		for _, f := range float8Samples {
			if f < min {
				min = f
			}
			if f > max {
				max = f
			}
			sum += float64(f)
		}
		avg := sum / float64(len(float8Samples))
		fmt.Printf("  Range: %.3f to %.3f, Avg: %.3f\n", min, max, avg)
	}

	// Check bytes 12-15 as float
	fmt.Printf("\nBytes 12-15 as float:\n")
	var float12Samples []float32
	for _, p := range type01 {
		if len(p.rawPost) >= 16 {
			f := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[12:16]))
			if !math.IsNaN(float64(f)) && !math.IsInf(float64(f), 0) {
				float12Samples = append(float12Samples, f)
			}
		}
	}
	if len(float12Samples) > 0 {
		min, max := float12Samples[0], float12Samples[0]
		var sum float64
		for _, f := range float12Samples {
			if f < min {
				min = f
			}
			if f > max {
				max = f
			}
			sum += float64(f)
		}
		avg := sum / float64(len(float12Samples))
		fmt.Printf("  Range: %.3f to %.3f, Avg: %.3f\n", min, max, avg)
	}

	// Now analyze 03-type packets the same way
	fmt.Printf("\n\n=== Analyzing 03-type packet structure ===\n")
	var type03 []fullPacket
	for _, p := range packets {
		if p.typeCode&0xFF == 0x03 {
			type03 = append(type03, p)
		}
	}
	fmt.Printf("Total 03-type packets: %d\n\n", len(type03))

	fmt.Printf("First 20 03-type packets:\n")
	for i := 0; i < 20 && i < len(type03); i++ {
		p := type03[i]
		fmt.Printf("\n[%d] Type=0x%04X Pos=(%.1f, %.1f, %.1f)\n",
			i, p.typeCode, p.x, p.y, p.z)
		fmt.Printf("    Raw post bytes: %02X\n", p.rawPost)
		
		if len(p.rawPost) >= 16 {
			f1 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[0:4]))
			f2 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[4:8]))
			f3 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[8:12]))
			f4 := math.Float32frombits(binary.LittleEndian.Uint32(p.rawPost[12:16]))
			
			fmt.Printf("    As floats: %.3f, %.3f, %.3f, %.3f\n", f1, f2, f3, f4)
		}
	}
}

func captureFullPacket(r *dissect.Reader) error {
	packetNum++

	typeBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	typeCode := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])

	if typeBytes[1] != 0x01 && typeBytes[1] != 0x03 {
		return nil
	}
	if typeBytes[0] < 0xB0 {
		return nil
	}

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

	if x < -100 || x > 100 || y < -100 || y > 100 || z < -5 || z > 15 {
		return nil
	}

	// Read extended post-coordinate data (up to 32 bytes)
	postBytes, err := r.Bytes(32)
	if err != nil {
		postBytes = make([]byte, 0)
	}

	playerID := 0
	if typeBytes[1] == 0x01 && len(postBytes) >= 8 {
		playerID = int(binary.LittleEndian.Uint32(postBytes[4:8]))
	}

	packets = append(packets, fullPacket{
		typeCode:  typeCode,
		packetNum: packetNum,
		x:         x,
		y:         y,
		z:         z,
		rawPost:   postBytes,
		playerID:  playerID,
	})

	return nil
}

func isAngle(f float32) bool {
	// Check if value looks like an angle in radians (-π to π) or degrees (-180 to 180)
	absF := float32(math.Abs(float64(f)))
	return (absF <= math.Pi+0.1) || (absF <= 180 && absF > 0.1)
}

func printTopN(counts map[uint32]int, n int) {
	type kv struct {
		k uint32
		v int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for i := 0; i < n && i < len(sorted); i++ {
		fmt.Printf("  0x%08X: %d\n", sorted[i].k, sorted[i].v)
	}
}

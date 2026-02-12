package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: countmarker <file.bin>")
		return
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Search for 83 00 00 00 62 73 85 fe
	marker := []byte{0x83, 0x00, 0x00, 0x00, 0x62, 0x73, 0x85, 0xfe}
	
	count := 0
	for i := 0; i <= len(data)-len(marker); i++ {
		match := true
		for j, b := range marker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			count++
			if count <= 5 {
				fmt.Printf("Found at offset 0x%06X\n", i)
			}
		}
	}
	
	fmt.Printf("\nTotal: %d occurrences in %d bytes\n", count, len(data))
}

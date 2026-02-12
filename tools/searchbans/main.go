package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// All operator IDs from header.go
var allOperators = map[string]uint64{
	"Recruit":     359656345734,
	"Castle":      92270642682,
	"Aruni":       104189664704,
	"Kaid":        161289666230,
	"Mozzie":      174977508820,
	"Pulse":       92270642708,
	"Ace":         104189664390,
	"Echo":        92270642214,
	"Azami":       378305069945,
	"Solis":       391752120891,
	"Capitao":     92270644215,
	"Zofia":       92270644189,
	"Dokkaebi":    92270644267,
	"Warden":      104189662920,
	"Mira":        92270644319,
	"Sledge":      92270642344,
	"Melusi":      104189664273,
	"Bandit":      92270642526,
	"Valkyrie":    92270642188,
	"Rook":        92270644059,
	"Kapkan":      92270641980,
	"Zero":        291191151607,
	"Iana":        104189664038,
	"Ash":         92270642656,
	"Blackbeard":  92270642136,
	"Osa":         288200867444,
	"Thorn":       373711624351,
	"Jager":       92270642604,
	"Kali":        104189663920,
	"Thermite":    92270642760,
	"Brava":       288200866821,
	"Amaru":       104189663607,
	"Ying":        92270642292,
	"Lesion":      92270642266,
	"Doc":         92270644007,
	"Lion":        104189661861,
	"Fuze":        92270642032,
	"Smoke":       92270642396,
	"Vigil":       92270644293,
	"Mute":        92270642318,
	"Goyo":        104189663698,
	"Wamai":       104189663803,
	"Ela":         92270644163,
	"Montagne":    92270644033,
	"Nokk":        104189663024,
	"Alibi":       104189662071,
	"Finka":       104189661965,
	"Caveira":     92270644241,
	"Nomad":       161289666248,
	"Thunderbird": 288200867351,
	"Sens":        384797789346,
	"IQ":          92270642578,
	"Blitz":       92270642539,
	"Hibana":      92270642240,
	"Maverick":    104189662384,
	"Flores":      328397386974,
	"Buck":        92270642474,
	"Twitch":      92270644111,
	"Gridlock":    174977508808,
	"Thatcher":    92270642422,
	"Glaz":        92270642084,
	"Jackal":      92270644345,
	"Grim":        374667788042,
	"Tachanka":    291437347686,
	"Oryx":        104189664155,
	"Frost":       92270642500,
	"Maestro":     104189662175,
	"Clash":       104189662280,
	"Fenrir":      288200867339,
	"Ram":         395943091136,
	"Tubarao":     288200867549,
	"Deimos":      374667787816,
	"Striker":     409899350463,
	"Sentry":      409899350403,
	"Skopos":      386098331713,
	"Rauora":      386098331923,
	"Denari":      374667787937,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: searchbans <file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File: %s (%d bytes)\n\n", os.Args[1], len(data))

	// List of banned operators we're looking for
	bannedOps := []string{"Azami", "Mira", "Brava", "Twitch", "Fenrir", "Capitao", "Dokkaebi", "Ela"}

	// Search for ALL operators in the entire file
	fmt.Println("=== Searching for ALL operator IDs as uint64 (8 bytes) ===")
	fmt.Println("Operators marked with [BAN] are the ones we're looking for")
	
	foundOps := make(map[string][]int)
	for name, id := range allOperators {
		idBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(idBytes, id)
		matches := searchBytes(data, idBytes)
		if len(matches) > 0 {
			foundOps[name] = matches
		}
	}
	
	// Print found operators
	for name, matches := range foundOps {
		isBanned := false
		for _, b := range bannedOps {
			if b == name {
				isBanned = true
				break
			}
		}
		marker := ""
		if isBanned {
			marker = " [BAN]"
		}
		fmt.Printf("  %s: %d matches at ", name, len(matches))
		for i, m := range matches {
			if i >= 3 {
				fmt.Printf("... ")
				break
			}
			fmt.Printf("0x%X ", m)
		}
		fmt.Printf("%s\n", marker)
	}
	
	// Report which banned operators were NOT found
	fmt.Println("\n=== Banned operators NOT found as uint64 ===")
	for _, name := range bannedOps {
		if _, found := foundOps[name]; !found {
			id := allOperators[name]
			fmt.Printf("  %s (%d) NOT FOUND\n", name, id)
		}
	}

	// Search for banned operator names as strings
	fmt.Println("\n=== Searching for banned operator names as strings ===")
	bannedOpNames := []string{"Azami", "AZAMI", "Mira", "MIRA", "Brava", "BRAVA", "Twitch", "TWITCH", "Fenrir", "FENRIR", "Capitao", "CAPITAO", "Dokkaebi", "DOKKAEBI"}
	for _, name := range bannedOpNames {
		matches := searchBytes(data, []byte(name))
		if len(matches) > 0 {
			fmt.Printf("  '%s': %d matches\n", name, len(matches))
			for _, m := range matches[:min(3, len(matches))] {
				start := m - 20
				if start < 0 {
					start = 0
				}
				end := m + len(name) + 40
				if end > len(data) {
					end = len(data)
				}
				fmt.Printf("    0x%08X: %s\n", m, sanitize(data[start:end]))
			}
		}
	}
	
	// Search in header area (first 20KB) for sequences of operator IDs that might be bans
	fmt.Println("\n=== Searching header area (first 20KB) for operator ID sequences ===")
	headerEnd := min(20000, len(data))
	for name, id := range allOperators {
		idBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(idBytes, id)
		matches := searchBytes(data[:headerEnd], idBytes)
		if len(matches) > 0 {
			isBanned := false
			for _, b := range bannedOps {
				if b == name {
					isBanned = true
					break
				}
			}
			marker := ""
			if isBanned {
				marker = " [BAN]"
			}
			fmt.Printf("  %s at 0x%X in header%s\n", name, matches[0], marker)
		}
	}
}

func searchBytes(data, pattern []byte) []int {
	var matches []int
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			matches = append(matches, i)
		}
	}
	return matches
}

func printMatches(data []byte, matches []int, idLen int) {
	for i, offset := range matches {
		if i >= 5 {
			fmt.Printf("    ... and %d more\n", len(matches)-5)
			break
		}
		start := offset - 16
		if start < 0 {
			start = 0
		}
		end := offset + idLen + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("    0x%08X: ", offset)
		for j := start; j < end; j++ {
			if j == offset {
				fmt.Print("[")
			}
			fmt.Printf("%02X", data[j])
			if j == offset+idLen-1 {
				fmt.Print("]")
			} else if j < end-1 {
				fmt.Print(" ")
			}
		}
		fmt.Println()
	}
}

func sanitize(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			result.WriteByte(b)
		} else {
			fmt.Fprintf(&result, "\\x%02x", b)
		}
	}
	return result.String()
}

func hexDump(data []byte, baseOffset int) {
	for i := 0; i < len(data); i += 32 {
		end := i + 32
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("%08X: ", baseOffset+i)
		for j := i; j < end; j++ {
			fmt.Printf("%02X ", data[j])
		}
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] < 127 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

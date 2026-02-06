package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	outputModeAuto   = "auto"
	outputModePretty = "pretty"
	outputModeKV     = "kv"
	outputModeJSON   = "json"
)

type outputField struct {
	Label string
	Value string
}

func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func resolvePrettyKVJSONOutputMode(mode string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case "", outputModeAuto:
		if stdoutIsTerminal() {
			return outputModePretty, nil
		}
		return outputModeKV, nil
	case outputModePretty, outputModeKV, outputModeJSON:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported output mode %q (expected auto|pretty|kv|json)", mode)
	}
}

func printJSON(payload any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func printPrettyTitle(title string) {
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
}

func printPrettySection(title string) {
	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("-", len(title)))
}

func printPrettyFields(fields []outputField) {
	if len(fields) == 0 {
		return
	}

	maxLabelWidth := 0
	for _, field := range fields {
		if len(field.Label) > maxLabelWidth {
			maxLabelWidth = len(field.Label)
		}
	}

	for _, field := range fields {
		fmt.Printf("%-*s : %s\n", maxLabelWidth, field.Label, field.Value)
	}
}

func printPrettyTable(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}

	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}
	for _, row := range rows {
		for i := range headers {
			if i >= len(row) {
				continue
			}
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}

	printPrettyTableBorder(widths)
	printPrettyTableRow(headers, widths)
	printPrettyTableBorder(widths)
	for _, row := range rows {
		printPrettyTableRow(row, widths)
	}
	printPrettyTableBorder(widths)
}

func printPrettyTableBorder(widths []int) {
	fmt.Print("+")
	for _, width := range widths {
		fmt.Print(strings.Repeat("-", width+2))
		fmt.Print("+")
	}
	fmt.Println()
}

func printPrettyTableRow(values []string, widths []int) {
	fmt.Print("|")
	for i, width := range widths {
		value := ""
		if i < len(values) {
			value = values[i]
		}
		fmt.Printf(" %-*s |", width, value)
	}
	fmt.Println()
}

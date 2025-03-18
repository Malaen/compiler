package compiler

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type rawSymbol struct {
	Address int64
	Content []string
}

type header struct {
	Entrypoint  int64
	DataSection int64
}

func filter[T any](ss []T, test func(T) bool) (ret []T) {
	for _, s := range ss {
		if test(s) {
			ret = append(ret, s)
		}
	}
	return
}

func Map[T any](ss []T, toApply func(T) T) (ret []T) {
	for _, s := range ss {
		ret = append(ret, toApply(s))
	}
	return
}

func getFileLines(filename string) ([]string, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	fileLines := strings.Split(string(file), "\n")
	// Remove blank line
	fileLines = filter(fileLines, func(line string) bool {
		return len(line) != 0
	})

	return fileLines, nil
}

// extractSymbol
// This function takes a list of lines
// Returns an array of strings that represent the content of the symbol (section, goto....)
func extractRawSymbol(lines []string) []string {
	content := []string{}
	// fmt.Println("In extractSymbol:", lines, len(lines))

	// While the line starts with a tabulation, it's in a symbol, if not we are at the next symbol
	for _, line := range lines {
		if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
			content = append(content, line)
		} else {
			break
		}
	}

	return content
}

func parseDataSection(content []string) map[string]any {
	ret := make(map[string]any, 0)
	for _, line := range content {
		lineSplited := strings.Split(line, "=")
		ret[lineSplited[0]] = lineSplited[1]
	}
	return ret
}

func extractRawSymbols(fileLines []string) (map[string]rawSymbol, map[string]rawSymbol) {
	sections := make(map[string]rawSymbol)
	functions := make(map[string]rawSymbol)

	// used for function's address
	funcIdx := 0
	idx := 0

	for idx < len(fileLines) {
		symName := fileLines[idx]
		symContent := extractRawSymbol(fileLines[idx+1:])

		// Trim all lines
		symContent = Map(symContent, func(line string) string {
			return strings.TrimSpace(line)
		})

		if strings.HasPrefix(symName, "section") {
			symName = strings.Split(symName, " ")[1]
			symName = strings.TrimSuffix(symName, ":")
			sections[symName] = rawSymbol{Content: symContent, Address: int64(len(sections))}
		}

		if strings.HasPrefix(symName, "_") {
			symName = strings.TrimSuffix(symName, ":")
			functions[symName] = rawSymbol{Content: symContent, Address: int64(funcIdx)}
			funcIdx += len(symContent)
		}

		// idx = idx + 1 (current line index) + len(symContent) -> number of lines in the symbol
		idx += 1 + len(symContent)
	}
	return sections, functions
}

// Compile takes a viper config with all shellcode's compilation options
func CompileShellcode(
	shellcodeFileName string,
	instructions, registers map[string]int64,
) ([]byte, error) {
	shellcode := make([]any, 0)
	fileLines, err := getFileLines(shellcodeFileName)
	if err != nil {
		return nil, err
	}

	// Find all the symbols (sections, goto ....)
	rawSections, rawFunctions := extractRawSymbols(fileLines)

	// .text section contains the name of the entrypoint
	// The shellcode writer can set the name he wants for the entrypoint function
	entryPointName := rawSections[".text"].Content[0]

	// check if there is an entrypoint
	_, exists := rawFunctions[entryPointName]
	if !exists {
		return nil, errors.New("compiler: No entrypoint found")
	}
	var dataValues map[string]any
	dataSymbol, exists := rawSections[".data"]
	if exists {
		dataValues = parseDataSection(dataSymbol.Content)
	}

	// create header, it's just the address of the entrypoint
	shellcode = append(shellcode, rawFunctions[entryPointName].Address)

	for _, content := range rawFunctions {
		// Compile a function
		compiledInstructions := make([]any, 0)
		for _, instr := range content.Content {
			instruction := make([]any, 0)

			instrSplited := strings.Split(instr, " ")
			opcode := instructions[instrSplited[0]]

			instruction = append(instruction, opcode)

			for _, operande := range instrSplited[1:] {

				// check if it's a register
				reg, ok := registers[operande]
				if ok {
					instruction = append(instruction, reg)
				} else if strings.HasPrefix(operande, "$") { // it's a variable
					instruction = append(instruction, dataValues[operande[1:]])
				} else if strings.HasPrefix(operande, "_") { // it's a reference to a function
					if strings.Contains(operande, "+") {
						opSplited := strings.Split(operande, "+")
						addrOfFunc := rawFunctions[opSplited[0]].Address
						offset, _ := strconv.Atoi(opSplited[1])
						instruction = append(instruction, addrOfFunc+int64(offset))
					}
				} else {
					i, err := strconv.Atoi(operande)
					if err == nil {
						instruction = append(instruction, int64(i))
					} else {
						instruction = append(instruction, operande)
					}
				}

			}
			compiledInstructions = append(compiledInstructions, instruction)
		}
		shellcode = append(shellcode, compiledInstructions...)
	}

	return encodeShellcode(shellcode)
}

func encodeShellcode(shellcode []any) ([]byte, error) {
	var buf bytes.Buffer
	gob.Register([]any{})
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(shellcode); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func CompileCode(config Config) (ret error) {
	cmdName := "go"
	cmdArgs := []string{"build", "-o", config.OutputDir}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Dir = config.BuildDir

	// Run the command and capture combined output
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Print the combined output (stdout + stderr)
	return err
}

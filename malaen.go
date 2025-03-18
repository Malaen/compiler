package compiler

import (
	"encoding/base64"
	"html/template"
	"os"
	"path/filepath"

	"github.com/go-git/go-git"
)

type Config struct {
	ShellcodeFile       string
	BuildDir, OutputDir string
	Instructions        map[string]int64 `yaml:"instructions"`
	Registers           map[string]int64 `yaml:"registers"`
}

func downloadMalaen(buildDir string) (err error) {
	_, err = git.PlainClone(buildDir, false, &git.CloneOptions{
		URL:      "https://git.atao.sh/Atao/nvim",
		Progress: os.Stdout,
	})

	return er
}

func generateCode(config Config) (err error) {
	tpl := `package main

var rawShellcode = "{{.Shellcode}}"

func (p *Process) LoadInstructions(){
  p.InstructionsFunctions = []InstructionFunction{
    {{range $key, $value := .Instructions}}{Opcode: {{$value}}, Func: {{$key}}},
  {{end}}
  }
}`

	t := template.New("t")
	t, err = t.Parse(tpl)
	if err != nil {
		return err
	}
	filePath := filepath.Join(config.BuildDir, "setup.go")
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	encodedShellcode, err := CompileShellcode(
		config.ShellcodeFile,
		config.Instructions,
		config.Registers,
	)
	if err != nil {
		return err
	}

	shellcode := base64.StdEncoding.EncodeToString(encodedShellcode)
	shellcodeEscaped := template.HTML(shellcode)
	data := struct {
		Shellcode    template.HTML
		Instructions map[string]int64
	}{
		Shellcode:    shellcodeEscaped,
		Instructions: config.Instructions,
	}

	err = t.Execute(f, data)
	if err != nil {
		return err
	}
	return nil
}

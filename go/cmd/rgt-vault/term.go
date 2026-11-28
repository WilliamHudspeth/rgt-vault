package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

// terminalIO is the seam of the interactive prompt: tests replace it with a
// fake terminal; production reads the real console.
type terminalIO struct {
	// isTerminal reports whether in is an interactive terminal.
	isTerminal func(in io.Reader) bool
	// readSecret prints prompt to out, reads one line from in WITHOUT echoing
	// it and returns the line without its line ending.
	readSecret func(in io.Reader, out io.Writer, prompt string) (string, error)
}

var term = terminalIO{isTerminal: stdinIsTerminal, readSecret: readSecretNoEcho}

// maxSecretLine bounds what a prompt accepts (a TOTP code is 6-8 digits).
const maxSecretLine = 128

func stdinIsTerminal(in io.Reader) bool {
	f, ok := in.(*os.File)
	return ok && isTerminal(f)
}

// readSecretNoEcho reads one line from the terminal in with echo switched
// off, and restores the terminal on every path.
func readSecretNoEcho(in io.Reader, out io.Writer, prompt string) (string, error) {
	f, ok := in.(*os.File)
	if !ok {
		return "", errors.New("not a terminal")
	}
	restore, err := disableEcho(f)
	if err != nil {
		return "", err
	}
	defer restore()
	_, _ = io.WriteString(out, prompt)
	defer func() { _, _ = io.WriteString(out, "\n") }()
	line, err := bufio.NewReaderSize(f, 512).ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > maxSecretLine {
		return "", errors.New("input too long")
	}
	return line, nil
}

//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// disableEcho turns the console's echo off and returns the function that
// puts the previous mode back.
func disableEcho(f *os.File) (restore func(), err error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}

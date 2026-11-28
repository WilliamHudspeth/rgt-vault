package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"rgt-vault-server/internal/mcp"
	"rgt-vault-server/internal/tui"
)

// runMCP serves MCP on in/out. out is the protocol channel; backend error
// details go to errOut (the command's stderr), never to out.
func runMCP(host string, rt http.RoundTripper, token, agent string, in io.Reader, out, errOut io.Writer) error {
	s := mcp.NewServer(host, token)
	s.SetTransport(rt)
	if err := s.SetAgent(agent); err != nil {
		return fmt.Errorf("agent label (--agent / RGT_VAULT_MCP_AGENT): %w", err)
	}
	s.SetLogger(log.New(errOut, "rgt-vault mcp: ", log.LstdFlags))
	return s.Serve(in, out)
}

func runTUI(host string, rt http.RoundTripper, token, namespace string) error {
	client := tui.NewHTTPClient(host, token)
	client.SetTransport(rt)
	m := tui.New(client, namespace)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func runStatus(host string, rt http.RoundTripper, out io.Writer) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: rt}
	resp, err := client.Get(host + "/healthz")
	if err != nil {
		fmt.Fprintf(out, "Server unreachable: %s\n", host)
		return fmt.Errorf("health check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Fprintf(out, "Server OK: %s\n", host)
		return nil
	}
	fmt.Fprintf(out, "Server unreachable: %s (HTTP %d)\n", host, resp.StatusCode)
	return fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

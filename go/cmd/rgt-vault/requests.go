package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// pendingRequest is one entry of GET /v1/requests.
type pendingRequest struct {
	ID         string  `json:"request_id"`
	Agent      string  `json:"agent"`
	Namespace  string  `json:"namespace"`
	SecretName string  `json:"secret_name"`
	Purpose    string  `json:"purpose"`
	Action     string  `json:"action"`
	Require2FA bool    `json:"require_2fa"`
	CreatedAt  float64 `json:"created_at"`
}

func (c *cli) fetchRequests() ([]pendingRequest, error) {
	body, status, err := c.do(http.MethodGet, c.host+"/v1/requests", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError("requests list", status, body)
	}
	var resp struct {
		Requests []pendingRequest `json:"requests"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return resp.Requests, nil
}

// runRequestsList prints the pending approval requests, oldest first, one
// per line: id, agent, namespace/secret, action, purpose, 2fa, created.
// Every field is server text (an agent chose the purpose), so all of it
// goes through safeText.
func (c *cli) runRequestsList(stderr io.Writer) error {
	reqs, err := c.fetchRequests()
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		fmt.Fprintln(stderr, "No pending requests.")
		return nil
	}
	for _, r := range reqs {
		twoFA := "no"
		if r.Require2FA {
			twoFA = "2fa"
		}
		created := ""
		if r.CreatedAt > 0 {
			created = time.Unix(int64(r.CreatedAt), 0).UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(c.stdout, "%s\t%s\t%s/%s\t%s\t%s\t%s\t%s\n",
			safeText(r.ID, maxIDCol), safeText(r.Agent, maxNameCol),
			safeText(r.Namespace, maxNameCol), safeText(r.SecretName, maxNameCol),
			safeText(r.Action, maxNameCol), safeText(r.Purpose, maxDescCol), twoFA, created)
	}
	return nil
}

const maxIDCol = 64

// runRequestsApprove approves request id. totpCode is "" when the user did
// not pass --totp-code; the code is then asked for, without echo, when the
// request needs a second factor and stdin is a terminal. The body carries
// only totp_code: never an "operator" name (the server takes the approver
// from the token and refuses a different name).
func (c *cli) runRequestsApprove(id, totpCode string, stderr io.Writer) error {
	if id == "" {
		return errors.New("request id must not be empty")
	}
	if totpCode == "" {
		reqs, err := c.fetchRequests()
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if r.ID == id && r.Require2FA {
				if totpCode, err = c.askTOTP(r, stderr); err != nil {
					return err
				}
				break
			}
		}
	}
	reqBody := struct {
		TOTPCode string `json:"totp_code,omitempty"`
	}{TOTPCode: strings.TrimSpace(totpCode)}
	body, status, err := c.do(http.MethodPost, c.host+"/v1/requests/"+url.PathEscape(id)+"/approve", reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("approve", status, body)
	}
	fmt.Fprintf(c.stdout, "Request %s approved.\n", safeText(id, maxIDCol))
	return nil
}

// runRequestsDeny denies request id; an empty reason lets the server use its
// default. No "operator" name is sent (see runRequestsApprove).
func (c *cli) runRequestsDeny(id, reason string) error {
	if id == "" {
		return errors.New("request id must not be empty")
	}
	reqBody := struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: reason}
	body, status, err := c.do(http.MethodPost, c.host+"/v1/requests/"+url.PathEscape(id)+"/deny", reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("deny", status, body)
	}
	fmt.Fprintf(c.stdout, "Request %s denied.\n", safeText(id, maxIDCol))
	return nil
}

func (c *cli) askTOTP(r pendingRequest, stderr io.Writer) (string, error) {
	if !term.isTerminal(c.stdin) {
		return "", fmt.Errorf("request %s needs a TOTP code and stdin is not a terminal: run this on a terminal, or pass --totp-code CODE (visible to other users in the process list)", safeText(r.ID, maxIDCol))
	}
	prompt := fmt.Sprintf("TOTP code to approve %s/%s for %s: ",
		safeText(r.Namespace, maxNameCol), safeText(r.SecretName, maxNameCol), safeText(r.Agent, maxNameCol))
	code, err := term.readSecret(c.stdin, stderr, prompt)
	if err != nil {
		return "", fmt.Errorf("reading the TOTP code: %w", err)
	}
	if strings.TrimSpace(code) == "" {
		return "", errors.New("no TOTP code entered")
	}
	return code, nil
}

func newRequestsCmd(newOperatorCLI func() *cli) *cobra.Command {
	root := &cobra.Command{
		Use:   "requests",
		Short: "List, approve or deny pending approval requests (operator)",
		Long: "Work the approval queue of a server started with --require-approval. These commands need an\n" +
			"operator token: --token, $RGT_VAULT_TOKEN, $RGT_VAULT_TOKEN_FILE, or the operator.token that\n" +
			"`rgt-vault init` wrote under ~/.config/rgt-vault.",
	}
	root.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the pending requests (id, agent, secret, action, purpose, 2fa, created)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return newOperatorCLI().runRequestsList(cmd.ErrOrStderr())
		},
	})
	var totpCode string
	approve := &cobra.Command{
		Use:   "approve <id> [--totp-code CODE]",
		Short: "Approve a pending request (asks for the TOTP code when it needs one)",
		Long: "Approve a pending request. When the request needs a second factor, the code is asked for on the\n" +
			"terminal without echo; with no terminal on stdin the command refuses unless --totp-code is given.\n" +
			"The code is single-use and the approver is the token's agent (no operator name is sent).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return newOperatorCLI().runRequestsApprove(args[0], totpCode, cmd.ErrOrStderr())
		},
	}
	approve.Flags().StringVar(&totpCode, "totp-code", "", "TOTP code, for scripts. VISIBLE in the process list (ps) and shell history: on a terminal, leave it out and type the code at the prompt")
	var reason string
	deny := &cobra.Command{
		Use:   "deny <id> [--reason TEXT]",
		Short: "Deny a pending request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return newOperatorCLI().runRequestsDeny(args[0], reason)
		},
	}
	deny.Flags().StringVar(&reason, "reason", "", "reason shown to the requester (default: \"denied by operator\")")
	root.AddCommand(approve, deny)
	return root
}

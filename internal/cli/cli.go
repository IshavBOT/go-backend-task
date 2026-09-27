// Package cli implements the interactive command-line front end: an
// interactive prompt with history and tab-completion, dispatching to the
// auth, totp, and session packages.
package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chzyer/readline"

	"github.com/osto/cli-login-system/internal/auth"
	"github.com/osto/cli-login-system/internal/config"
	"github.com/osto/cli-login-system/internal/models"
	"github.com/osto/cli-login-system/internal/session"
	"github.com/osto/cli-login-system/internal/totp"
)

const historyFile = "/tmp/.cli-login-history"

// commandSet lists the commands available before and after login, used for
// both the help command and tab-completion.
var (
	preLoginCommands  = []string{"register", "login", "help", "exit"}
	postLoginCommands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}
)

// App wires together the auth, session and totp services behind the
// interactive prompt.
type App struct {
	cfg        *config.Config
	authSvc    *auth.Service
	sessionMgr *session.Manager

	rl *readline.Instance

	// Mutable per-connection state: the currently authenticated session, if any.
	currentSession *models.Session
	currentUser    *models.User
}

// New constructs the CLI application.
func New(cfg *config.Config, authSvc *auth.Service, sessionMgr *session.Manager) (*App, error) {
	app := &App{cfg: cfg, authSvc: authSvc, sessionMgr: sessionMgr}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "> ",
		HistoryFile:     historyFile,
		AutoComplete:    readline.NewPrefixCompleter(app.completionItems()...),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, fmt.Errorf("initializing CLI: %w", err)
	}
	app.rl = rl
	return app, nil
}

// completionItems builds the tab-completion tree. It is regenerated (via
// SetAutoComplete) whenever login state changes, since available commands differ.
func (a *App) completionItems() []readline.PrefixCompleterInterface {
	cmds := preLoginCommands
	if a.loggedIn() {
		cmds = postLoginCommands
	}
	items := make([]readline.PrefixCompleterInterface, len(cmds))
	for i, c := range cmds {
		items[i] = readline.PcItem(c)
	}
	return items
}

func (a *App) refreshCompleter() {
	a.rl.Config.AutoComplete = readline.NewPrefixCompleter(a.completionItems()...)
}

func (a *App) loggedIn() bool {
	return a.currentSession != nil
}

// Run starts the read-eval-print loop and blocks until the user exits or
// input is closed (Ctrl-D / EOF).
func (a *App) Run() error {
	defer a.rl.Close()

	fmt.Println("=================================================")
	fmt.Println(" Containerized CLI Login System  (type 'help')")
	fmt.Println("=================================================")

	for {
		a.updatePrompt()
		line, err := a.rl.Readline()
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			if errors.Is(err, readline.ErrInterrupt) {
				continue
			}
			if errors.Is(err, io.EOF) {
				fmt.Println("\nGoodbye!")
				return nil
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if a.dispatch(line) {
			return nil // "exit" was called
		}
	}
}

// updatePrompt shows the logged-in username in the prompt for clarity, and
// silently expires stale sessions before the next prompt is drawn.
func (a *App) updatePrompt() {
	if a.loggedIn() {
		if _, err := a.sessionMgr.Validate(a.currentSession.ID); err != nil {
			fmt.Println("\n[!] Your session has expired. Please log in again.")
			a.currentSession = nil
			a.currentUser = nil
			a.refreshCompleter()
		}
	}
	if a.loggedIn() {
		a.rl.SetPrompt(fmt.Sprintf("(%s)> ", a.currentUser.Username))
	} else {
		a.rl.SetPrompt("> ")
	}
}

// dispatch executes a single command line. It returns true if the
// application should exit.
func (a *App) dispatch(line string) bool {
	fields := strings.Fields(line)
	cmd := fields[0]

	// Every command that requires a session gets a fresh sliding-window
	// refresh here, except for commands that don't need one.
	if a.loggedIn() {
		if sess, err := a.sessionMgr.Refresh(a.currentSession.ID); err == nil {
			a.currentSession = sess
		}
	}

	switch cmd {
	case "help":
		a.printHelp()

	case "exit", "quit":
		fmt.Println("Goodbye!")
		return true

	case "register":
		a.cmdRegister()

	case "login":
		a.cmdLogin()

	case "whoami":
		a.requireLogin(a.cmdWhoami)

	case "enable-2fa":
		a.requireLogin(a.cmdEnable2FA)

	case "disable-2fa":
		a.requireLogin(a.cmdDisable2FA)

	case "logout":
		a.requireLogin(a.cmdLogout)

	default:
		fmt.Printf("Unknown command: %q. Type 'help' for a list of commands.\n", cmd)
	}
	return false
}

// requireLogin guards post-login commands, printing a helpful message if
// the user isn't authenticated instead of silently doing nothing.
func (a *App) requireLogin(fn func()) {
	if !a.loggedIn() {
		fmt.Println("You must be logged in to use this command. Try 'login'.")
		return
	}
	fn()
}

func (a *App) printHelp() {
	fmt.Println()
	if a.loggedIn() {
		fmt.Println("Available commands:")
		fmt.Println("  whoami       Show your account details")
		fmt.Println("  enable-2fa   Enable TOTP-based two-factor authentication")
		fmt.Println("  disable-2fa  Disable two-factor authentication")
		fmt.Println("  logout       End your session")
		fmt.Println("  help         Show this help message")
		fmt.Println("  exit         Quit the program")
	} else {
		fmt.Println("Available commands:")
		fmt.Println("  register     Create a new user account")
		fmt.Println("  login        Log in with username/password (+ TOTP if enabled)")
		fmt.Println("  help         Show this help message")
		fmt.Println("  exit         Quit the program")
	}
	fmt.Println()
}

// --- Command implementations -----------------------------------------------

func (a *App) cmdRegister() {
	username, ok := a.prompt("Username: ")
	if !ok {
		return
	}
	password, ok := a.promptPassword("Password: ")
	if !ok {
		return
	}
	confirm, ok := a.promptPassword("Confirm password: ")
	if !ok {
		return
	}
	if password != confirm {
		fmt.Println("Error: passwords do not match.")
		return
	}

	if err := a.authSvc.Register(username, password); err != nil {
		fmt.Printf("Registration failed: %v\n", err)
		return
	}
	fmt.Printf("Account %q created successfully. You can now 'login'.\n", username)
}

func (a *App) cmdLogin() {
	username, ok := a.prompt("Username: ")
	if !ok {
		return
	}
	password, ok := a.promptPassword("Password: ")
	if !ok {
		return
	}

	user, err := a.authSvc.VerifyPassword(username, password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountLocked):
			locked, lookupErr := a.authSvc.GetByUsername(username)
			if lookupErr == nil {
				remaining := auth.RemainingLockout(locked).Round(time.Second)
				fmt.Printf("Account is locked due to too many failed attempts. Try again in %s.\n", remaining)
			} else {
				fmt.Println("Account is locked due to too many failed attempts. Try again later.")
			}
		case errors.Is(err, auth.ErrInvalidCreds):
			fmt.Println("Login failed: invalid username or password.")
		default:
			fmt.Printf("Login failed: %v\n", err)
		}
		return
	}

	if user.TOTPEnabled {
		code, ok := a.prompt("2FA code: ")
		if !ok {
			return
		}
		if !totp.Validate(strings.TrimSpace(code), user.TOTPSecret) {
			fmt.Println("Login failed: invalid 2FA code.")
			return
		}
	}

	sess, err := a.sessionMgr.Create(user.ID)
	if err != nil {
		fmt.Printf("Login failed: could not create session: %v\n", err)
		return
	}
	if err := a.authSvc.TouchLastLogin(user.ID); err != nil {
		fmt.Printf("Warning: could not update last login time: %v\n", err)
	}
	// Re-fetch so LastLoginAt reflects what we're about to display consistently
	// with what's now stored (the pre-touch value is the *previous* login, which
	// is exactly what we want to show per the spec — capture it before touching).
	prevLastLogin := user.LastLoginAt

	a.currentSession = sess
	a.currentUser = user
	a.refreshCompleter()

	fmt.Printf("\nWelcome, %s!\n", user.Username)
	a.printUserDetails(user, sess, prevLastLogin)
}

func (a *App) cmdWhoami() {
	user, err := a.authSvc.GetByID(a.currentUser.ID)
	if err != nil {
		fmt.Printf("Error fetching account details: %v\n", err)
		return
	}
	a.currentUser = user
	a.printUserDetails(user, a.currentSession, user.LastLoginAt)
}

// printUserDetails renders the auto-display block required after login /
// on 'whoami': username, registration date, MFA status, session expiration,
// and last login time.
func (a *App) printUserDetails(user *models.User, sess *models.Session, lastLogin *time.Time) {
	fmt.Println("------------------------------------------------")
	fmt.Printf("  Username:          %s\n", user.Username)
	fmt.Printf("  Registered on:     %s\n", user.CreatedAt.Format(time.RFC1123))
	fmt.Printf("  MFA status:        %s\n", mfaStatus(user.TOTPEnabled))
	fmt.Printf("  Session expires:   %s\n", sess.ExpiresAt.Format(time.RFC1123))
	if lastLogin != nil {
		fmt.Printf("  Last login:        %s\n", lastLogin.Format(time.RFC1123))
	} else {
		fmt.Printf("  Last login:        (this is your first login)\n")
	}
	fmt.Println("------------------------------------------------")
}

func mfaStatus(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func (a *App) cmdEnable2FA() {
	if a.currentUser.TOTPEnabled {
		fmt.Println("Two-factor authentication is already enabled.")
		return
	}

	secret, uri, err := totp.GenerateSecret(a.cfg.TOTPIssuer, a.currentUser.Username)
	if err != nil {
		fmt.Printf("Error generating 2FA secret: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Println("Scan this in Google Authenticator (or any TOTP app), or enter the secret manually:")
	fmt.Printf("  Secret:           %s\n", secret)
	fmt.Printf("  Provisioning URI: %s\n", uri)
	fmt.Println()
	fmt.Println("To confirm setup, enter the 6-digit code from your app now.")

	code, ok := a.prompt("2FA code: ")
	if !ok {
		return
	}
	if !totp.Validate(strings.TrimSpace(code), secret) {
		fmt.Println("Incorrect code. 2FA setup was not completed; run 'enable-2fa' again to retry.")
		return
	}

	if err := a.authSvc.SetTOTPSecret(a.currentUser.ID, secret, true); err != nil {
		fmt.Printf("Error saving 2FA settings: %v\n", err)
		return
	}
	a.currentUser.TOTPEnabled = true
	a.currentUser.TOTPSecret = secret
	fmt.Println("Two-factor authentication is now enabled on your account.")
}

func (a *App) cmdDisable2FA() {
	if !a.currentUser.TOTPEnabled {
		fmt.Println("Two-factor authentication is not currently enabled.")
		return
	}
	if err := a.authSvc.DisableTOTP(a.currentUser.ID); err != nil {
		fmt.Printf("Error disabling 2FA: %v\n", err)
		return
	}
	a.currentUser.TOTPEnabled = false
	a.currentUser.TOTPSecret = ""
	fmt.Println("Two-factor authentication has been disabled.")
}

func (a *App) cmdLogout() {
	if err := a.sessionMgr.Destroy(a.currentSession.ID); err != nil {
		fmt.Printf("Warning: error destroying session: %v\n", err)
	}
	fmt.Printf("Goodbye, %s. You have been logged out.\n", a.currentUser.Username)
	a.currentSession = nil
	a.currentUser = nil
	a.refreshCompleter()
}

// --- Input helpers -----------------------------------------------------

// prompt reads a plain line of input with the given prompt text.
// The bool return is false if input was interrupted/closed, signaling the
// caller to abort the current command.
func (a *App) prompt(label string) (string, bool) {
	a.rl.SetPrompt(label)
	defer a.updatePrompt()

	line, err := a.rl.Readline()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(line), true
}

// promptPassword reads a line with input masked as asterisks are not echoed
// at all (standard terminal password behavior), so credentials never appear
// on-screen or in shell/history buffers.
func (a *App) promptPassword(label string) (string, bool) {
	pw, err := a.rl.ReadPassword(label)
	defer a.updatePrompt()
	if err != nil {
		return "", false
	}
	return string(pw), true
}

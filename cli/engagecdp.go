package main

import (
	"context"
	"fmt"

	"blkchain/cli/internal/secgate"
)

func webValidateCDPSelection(session, role, endpoint string) error {
	if session == "" || role == "" {
		return fmt.Errorf("session-cdp requires --session and --role")
	}
	if err := webValidateCDPEndpoint(endpoint); err != nil {
		return fmt.Errorf("session-cdp: %w", err)
	}
	return nil
}

func webSelectCDPRole(path, name string) (webSessionRole, error) {
	roles, err := webLoadSessions(path)
	if err != nil {
		return webSessionRole{}, err
	}
	for _, role := range roles {
		if role.Name != name {
			continue
		}
		if err := webValidateCDPRole(role); err != nil {
			return webSessionRole{}, err
		}
		return role, nil
	}
	return webSessionRole{}, fmt.Errorf("session-cdp role is absent from the session file")
}

func webValidateCDPRole(role webSessionRole) error {
	if role.Origin == "" || len(role.HeadersEnv) != 0 || len(role.CookiesEnv) != 0 || len(role.Storage) != 0 || role.Login != nil {
		return fmt.Errorf("session-cdp role requires only a name and exact origin")
	}
	return nil
}

func webImportCDPRole(ctx context.Context, gate *secgate.Gate, role webSessionRole, endpoint string) (webSessionRole, error) {
	if err := webValidateCDPEndpoint(endpoint); err != nil {
		return webSessionRole{}, fmt.Errorf("session-cdp: %w", err)
	}
	if err := webValidateCDPRole(role); err != nil {
		return webSessionRole{}, err
	}
	if gate == nil || role.Origin == "" {
		return webSessionRole{}, fmt.Errorf("session-cdp requires an authorized role origin")
	}
	if dec := gate.AuthorizeBrowser(ctx, secgate.BrowserAction{URL: role.Origin}); !dec.Allowed {
		return webSessionRole{}, fmt.Errorf("session-cdp role origin denied by the engagement policy: %s", dec.Reason)
	}
	state, err := chatCDPStorageState(ctx, endpoint)
	if err != nil {
		return webSessionRole{}, fmt.Errorf("session-cdp: %w", err)
	}
	role.AuthState, err = chatCDPFilterOrigin(state, role.Origin)
	if err != nil {
		return webSessionRole{}, fmt.Errorf("session-cdp: %w", err)
	}
	return role, nil
}

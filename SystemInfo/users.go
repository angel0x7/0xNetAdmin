package SystemInfo

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type LocalUser struct {
	Name    string `json:"Name"`
	Enabled bool   `json:"Enabled"`
	SID     string `json:"SID"`
}

func GetLocalUsers() ([]LocalUser, error) {
	cmd := exec.Command("powershell", "-Command",
		"Get-LocalUser | Select-Object Name, Enabled, @{Name='SID';Expression={$_.SID.Value}} | ConvertTo-Json")

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("erreur PowerShell: %w", err)
	}

	var users []LocalUser
	if err := json.Unmarshal(out, &users); err != nil {
		var single LocalUser
		if err2 := json.Unmarshal(out, &single); err2 == nil {
			users = append(users, single)
		} else {
			return nil, fmt.Errorf("erreur parsing JSON: %w", err)
		}
	}
	return users, nil
}

type UserGroups struct {
	Username string
	Groups   []string
}

func GetUserGroups(username string) (*UserGroups, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("(Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue) -match '%s' }).Name", username))

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("erreur récupération groupes: %w", err)
	}

	groups := parseLines(string(out))
	return &UserGroups{Username: username, Groups: groups}, nil
}

func parseLines(s string) []string {
	var lines []string
	current := ""
	for _, c := range s {
		if c == '\n' || c == '\r' {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

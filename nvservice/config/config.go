package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func ParseUserCachePaths(iniPath string) ([]string, error) {
	data, err := os.ReadFile(iniPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	inSection := false
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			inSection = strings.EqualFold(section, "UserCache")
			continue
		}
		if !inSection {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		cleaned := filepath.Clean(value)
		if len(cleaned) == 2 && cleaned[1] == ':' {
			cleaned += string(filepath.Separator)
		}
		result = append(result, cleaned)
	}
	if len(result) == 0 {
		return nil, errors.New("no cache entries found in [UserCache]")
	}
	return result, nil
}

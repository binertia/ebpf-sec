package redact

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/events"
)

var sensitiveKeyPattern = regexp.MustCompile(`(?i)(authorization|api[_-]?key|access[_-]?key|token|secret|password|passwd|pwd|session|bearer|cookie|credential|private[_-]?key)`)

func Event(event events.Event) events.Event {
	redacted := event
	redacted.CommandLine = RedactCommandLine(event.CommandLine)
	redacted.ExecutablePath = RedactString(event.ExecutablePath)
	redacted.ProcessName = RedactString(event.ProcessName)
	redacted.ParentProcessName = RedactString(event.ParentProcessName)
	redacted.CWD = RedactString(event.CWD)
	redacted.FilePath = RedactString(event.FilePath)
	redacted.RemoteAddr = RedactString(event.RemoteAddr)
	redacted.Metadata = RedactMap(event.Metadata)
	return redacted
}

func Incident(incident compress.Incident) compress.Incident {
	redacted := incident
	redacted.IncidentID = RedactString(incident.IncidentID)
	redacted.RootProcess.ProcessName = RedactString(incident.RootProcess.ProcessName)
	redacted.RootProcess.ExecutablePath = RedactString(incident.RootProcess.ExecutablePath)
	redacted.ProcessTree = RedactStrings(incident.ProcessTree)
	redacted.Timeline = RedactStrings(incident.Timeline)
	redacted.Summary = RedactString(incident.Summary)
	return redacted
}

func Strings(values []string) []string {
	return RedactStrings(values)
}

func RedactStrings(values []string) []string {
	redacted := make([]string, len(values))
	for index, value := range values {
		redacted[index] = RedactString(value)
	}
	return redacted
}

func RedactCommandLine(values []string) []string {
	redacted := RedactStrings(values)
	for index, value := range values {
		if index+1 >= len(values) {
			break
		}
		switch {
		case requiresSensitiveValueRedaction(value), isUserFlag(value):
			redacted[index+1] = "[REDACTED]"
		case isHeaderFlag(value):
			redacted[index+1] = RedactString(values[index+1])
		}
	}
	return redacted
}

func RedactString(value string) string {
	if value == "" {
		return value
	}
	if redacted, ok := redactURL(value); ok {
		return redacted
	}
	if redacted := redactFlag(value); redacted != value {
		return redacted
	}
	if redacted := redactAssignment(value); redacted != value {
		return redacted
	}
	return value
}

func RedactValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return RedactString(typed)
	case []string:
		return RedactStrings(typed)
	case []any:
		redacted := make([]any, len(typed))
		for index, entry := range typed {
			redacted[index] = RedactValue(entry)
		}
		return redacted
	case map[string]any:
		return RedactMap(typed)
	default:
		return value
	}
}

func RedactMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	redacted := make(map[string]any, len(values))
	for key, entry := range values {
		if sensitiveKeyPattern.MatchString(key) {
			redacted[key] = "[REDACTED]"
			continue
		}
		redacted[key] = RedactValue(entry)
	}
	return redacted
}

func redactURL(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	changed := false
	if parsed.User != nil {
		parsed.User = url.UserPassword("[REDACTED]", "[REDACTED]")
		changed = true
	}
	query := parsed.Query()
	for key := range query {
		if sensitiveKeyPattern.MatchString(key) {
			query[key] = []string{"[REDACTED]"}
			changed = true
		}
	}
	if !changed {
		return "", false
	}
	if parsed.RawQuery != "" {
		parsed.RawQuery = query.Encode()
	}
	return parsed.String(), true
}

func redactFlag(value string) string {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "authorization:") ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "set-cookie:") ||
		strings.Contains(lower, "private key-----") {
		return "[REDACTED]"
	}
	if key, _, found := strings.Cut(value, ":"); found && !strings.ContainsAny(key, " \t") && sensitiveKeyPattern.MatchString(key) {
		return "[REDACTED]"
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value
	}
	redacted := false
	for index, field := range fields {
		if index > 0 && (requiresSensitiveValueRedaction(fields[index-1]) || isUserFlag(fields[index-1])) {
			fields[index] = "[REDACTED]"
			redacted = true
			continue
		}
		if sanitized, ok := redactArgument(field); ok {
			fields[index] = sanitized
			redacted = true
		}
	}
	if !redacted {
		return value
	}
	return strings.Join(fields, " ")
}

func requiresSensitiveValueRedaction(value string) bool {
	switch strings.ToLower(value) {
	case "--token", "--password", "--passwd", "--pwd", "--secret", "--api-key", "--apikey":
		return true
	default:
		return false
	}
}

func isUserFlag(value string) bool {
	return strings.EqualFold(value, "-u") || strings.EqualFold(value, "--user")
}

func isHeaderFlag(value string) bool {
	return strings.EqualFold(value, "-H") || strings.EqualFold(value, "--header")
}

func redactAssignment(value string) string {
	if key, _, found := strings.Cut(value, "="); found && sensitiveKeyPattern.MatchString(key) {
		return key + "=[REDACTED]"
	}
	return value
}

func redactArgument(value string) (string, bool) {
	lower := strings.ToLower(value)
	if lower == "-h" || lower == "--header" {
		return value, false
	}
	for _, prefix := range []string{
		"--token=", "--password=", "--passwd=", "--pwd=", "--secret=", "--api-key=", "--apikey=",
		"--access-key=", "--access_key=", "--cookie=", "--credential=", "--private-key=", "--private_key=",
		"token=", "password=", "passwd=", "pwd=", "secret=", "api_key=", "apikey=",
		"access_key=", "access-key=", "cookie=", "credential=", "private_key=", "private-key=",
	} {
		if strings.HasPrefix(lower, prefix) {
			key, _, _ := strings.Cut(value, "=")
			return key + "=[REDACTED]", true
		}
	}
	if strings.EqualFold(value, "-u") || strings.EqualFold(value, "--user") {
		return value, false
	}
	if strings.EqualFold(value, "-H") || strings.EqualFold(value, "--header") {
		return value, false
	}
	if strings.Contains(value, "://") {
		return redactURL(value)
	}
	if strings.Contains(value, "=") && sensitiveKeyPattern.MatchString(strings.SplitN(value, "=", 2)[0]) {
		key, _, _ := strings.Cut(value, "=")
		return key + "=[REDACTED]", true
	}
	return value, false
}

func CleanFilePath(path string) string {
	if path == "" {
		return path
	}
	base := filepath.Base(path)
	if strings.Contains(strings.ToLower(path), "secret") || strings.Contains(strings.ToLower(path), "token") || strings.Contains(strings.ToLower(path), "password") {
		return filepath.Join(filepath.Dir(path), "[REDACTED]", base)
	}
	return path
}

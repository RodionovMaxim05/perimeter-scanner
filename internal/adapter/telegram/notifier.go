package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"perimeter-scanner/internal/domain"
)

// maxTelegramMessageLen is the character limit set by the Telegram bot API.
const maxTelegramMessageLen = 4096

// NotifierAdapter sends scan diff alerts to a Telegram chat via Bot API.
type NotifierAdapter struct {
	token  string
	chatID string
	client *http.Client
}

// NewNotifierAdapter constructs a NotifierAdapter.
// token is the Telegram bot token; chatID is the target chat or channel ID.
func NewNotifierAdapter(token, chatID string) *NotifierAdapter {
	return &NotifierAdapter{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// telegramMessage is the JSON payload for the Telegram sendMessage endpoint.
type telegramMessage struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// SendDiffAlert formats the scan diff as a MarkdownV2 message and sends it
// to the configured Telegram chat. If the message exceeds the character limit,
// it is split into multiple messages sent sequentially.
func (n *NotifierAdapter) SendDiffAlert(ctx context.Context, diff domain.ScanDiff) error {
	if len(diff.NewServices) == 0 {
		return nil
	}

	parts := n.splitMessage(n.buildMarkdownMessage(diff))
	for _, part := range parts {
		if err := n.sendMessage(ctx, part); err != nil {
			return err
		}
	}
	return nil
}

// sendMessage sends a single MarkdownV2-formatted message to the Telegram Bot API.
func (n *NotifierAdapter) sendMessage(ctx context.Context, text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.token)

	reqBody, err := json.Marshal(telegramMessage{
		ChatID:    n.chatID,
		Text:      text,
		ParseMode: "MarkdownV2",
	})
	if err != nil {
		return fmt.Errorf("failed to marshal telegram message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		errStr := err.Error()
		if n.token != "" {
			errStr = strings.ReplaceAll(errStr, n.token, "[REDACTED]")
		}
		return fmt.Errorf("failed to send telegram request: %s", errStr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var tgErr struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&tgErr)
		return fmt.Errorf("telegram api returned %d: %s", resp.StatusCode, tgErr.Description)
	}

	return nil
}

// splitMessage splits a message into parts that each fit within maxTelegramMessageLen.
// Splitting is done on line boundaries to avoid breaking MarkdownV2 formatting mid-token.
func (n *NotifierAdapter) splitMessage(text string) []string {
	if len(text) <= maxTelegramMessageLen {
		return []string{text}
	}
	var parts []string
	var current strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if current.Len()+len(line)+1 > maxTelegramMessageLen {
			parts = append(parts, current.String())
			current.Reset()
		}
		current.WriteString(line + "\n")
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// buildMarkdownMessage constructs the full MarkdownV2-formatted alert message
// from a ScanDiff. Each new service is listed with its port, protocol, banner,
// and CVE vulnerabilities including severity emoji and exploit availability.
func (n *NotifierAdapter) buildMarkdownMessage(diff domain.ScanDiff) string {
	var sb strings.Builder

	sb.WriteString("🔔 *ОБНАРУЖЕНЫ ИЗМЕНЕНИЯ ПЕРИМЕТРА*\n\n")
	sb.WriteString(fmt.Sprintf("🌐 *Хост:* `%s`\n", n.escape(diff.IP)))
	sb.WriteString(fmt.Sprintf("🕒 *Время фиксации:* %s\n\n", n.escape(time.Now().Format("2006-01-02 15:04:05"))))

	sb.WriteString("🚀 *Новые открытые сервисы:*\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━\n")

	for _, svc := range diff.NewServices {
		sb.WriteString(fmt.Sprintf("• *%d/%s* ➔ _%s_ ", svc.Port, n.escape(svc.Proto), n.escape(svc.Service)))
		if svc.Version != "" {
			sb.WriteString(fmt.Sprintf("\\(_%s_\\)", n.escape(svc.Version)))
		}
		sb.WriteString("\n")

		if svc.Banner != "" {
			sb.WriteString(fmt.Sprintf("  ├ 📋 `Banner: %s`\n", n.escape(svc.Banner)))
		}

		if len(svc.Vulnerabilities) > 0 {
			for _, v := range svc.Vulnerabilities {
				emoji := n.getSeverityEmoji(v.Severity)
				sb.WriteString(fmt.Sprintf("  ├ %s *%s* \\[Score: `%s`\\]", emoji, n.escape(v.CVE), n.escape(fmt.Sprintf("%.1f", v.Score))))
				if v.ExploitAvailable {
					sb.WriteString(" 🔥 *EXPLOIT\\!*")
				}
				sb.WriteString("\n")

				if v.Description != "" {
					desc := v.Description
					if len(desc) > 120 {
						desc = desc[:117] + "..."
					}
					sb.WriteString(fmt.Sprintf("  │   └ _%s_\n", n.escape(desc)))
				}
			}
		} else {
			sb.WriteString("  └ ✅ Известных CVE на порту не найдено\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// severityEmoji returns a coloured circle emoji corresponding to the CVSS severity level.
func (n *NotifierAdapter) getSeverityEmoji(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical:
		return "🔴"
	case domain.SeverityHigh:
		return "🟠"
	case domain.SeverityMedium:
		return "🟡"
	case domain.SeverityLow:
		return "🟢"
	default:
		return "ℹ️"
	}
}

// escape escapes all MarkdownV2 reserved characters in a plain-text string
// so it can be safely embedded in a formatted Telegram message.
func (n *NotifierAdapter) escape(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)",
		"~", "\\~", "`", "\\`", ">", "\\>", "#", "\\#", "+", "\\+", "-", "\\-",
		"=", "\\=", "|", "\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!",
	)
	return replacer.Replace(text)
}

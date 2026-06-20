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
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
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
		ChatID:                n.chatID,
		Text:                  text,
		ParseMode:             "MarkdownV2",
		DisableWebPagePreview: true,
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
	defer func() {
		_ = resp.Body.Close()
	}()

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
	fmt.Fprintf(&sb, "🌐 *Хост:* `%s`\n", escapeMarkdownV2(diff.IP))
	fmt.Fprintf(&sb, "🕒 *Время фиксации:* %s\n\n", escapeMarkdownV2(diff.ScanTime.Format("2006-01-02 15:04:05")))

	sb.WriteString("🚀 *Новые открытые сервисы:*\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━\n")

	for _, svc := range diff.NewServices {
		fmt.Fprintf(&sb, "• *%d/%s* ➔ _%s_ ", svc.Port, escapeMarkdownV2(svc.Proto), escapeMarkdownV2(svc.Service))
		if svc.Version != "" {
			fmt.Fprintf(&sb, "\\(_%s_\\)", escapeMarkdownV2(svc.Version))
		}
		sb.WriteString("\n")

		if svc.Banner != "" {
			fmt.Fprintf(&sb, "  ├ 📋 `Banner: %s`\n", escapeMarkdownV2(svc.Banner))
		}

		if len(svc.Vulnerabilities) > 0 {
			for i, v := range svc.Vulnerabilities {
				prefix := "  ├"
				if i == len(svc.Vulnerabilities)-1 {
					prefix = "  └"
				}

				emoji := n.getSeverityEmoji(v.Score)
				scoreStr := escapeMarkdownV2(fmt.Sprintf("%.1f", v.Score))
				cveName := escapeMarkdownV2(v.CVE)

				urlReplacer := strings.NewReplacer(")", "\\)", "\\", "\\\\")
				escapedLink := urlReplacer.Replace(v.Link)

				fmt.Fprintf(
					&sb,
					"%s %s [%s](%s) \\[Score: `%s`\\]",
					prefix,
					emoji,
					cveName,
					escapedLink,
					scoreStr,
				)

				if v.ExploitAvailable {
					sb.WriteString(" 🔥 *EXPLOIT\\!*")
				}
				sb.WriteString("\n")
			}
		} else {
			sb.WriteString("  └ ✅ Известных CVE на порту не найдено\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// getSeverityEmoji returns a coloured circle emoji corresponding to the CVSS score.
func (n *NotifierAdapter) getSeverityEmoji(score float64) string {
	switch {
	case score >= 9.0:
		return "🔴" // Critical
	case score >= 7.0:
		return "🟠" // High
	case score >= 4.0:
		return "🟡" // Medium
	case score >= 0.1:
		return "🟢" // Low
	default:
		return "ℹ️" // Info / None (0.0)
	}
}

// escapeMarkdownV2 escapes all MarkdownV2 reserved characters in a plain-text string
// so it can be safely embedded in a formatted Telegram message.
func escapeMarkdownV2(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)",
		"~", "\\~", "`", "\\`", ">", "\\>", "#", "\\#", "+", "\\+", "-", "\\-",
		"=", "\\=", "|", "\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!",
	)
	return replacer.Replace(text)
}

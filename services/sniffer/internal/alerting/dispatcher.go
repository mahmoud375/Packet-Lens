package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mahmoud375/PacketLens/services/sniffer/internal/metrics"
)

// Dispatcher is the async alert delivery goroutine. It reads from a buffered
// channel, applies rate limiting, formats the payload for the target webhook
// type, and delivers via HTTP POST. It never blocks the gRPC hot path.
type Dispatcher struct {
	alertChan <-chan Alert
	cfg       Config
	limiter   *RateLimiter
	client    *http.Client
	wg        sync.WaitGroup
}

// NewDispatcher creates a Dispatcher bound to the given channel and config.
func NewDispatcher(alertChan <-chan Alert, cfg Config) *Dispatcher {
	return &Dispatcher{
		alertChan: alertChan,
		cfg:       cfg,
		limiter:   NewRateLimiter(cfg),
		client: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
	}
}

// Start launches the dispatcher goroutine. It runs until the channel is
// closed OR the context is cancelled, then drains any remaining alerts.
func (d *Dispatcher) Start(ctx context.Context) {
	d.wg.Add(1)
	go d.run(ctx)
	log.Printf("[AlertDispatcher] Started (type=%s, cooldown=%s, burst=%d/%s)",
		d.cfg.WebhookType,
		d.cfg.PerLabelCooldown,
		d.cfg.GlobalBurstLimit,
		d.cfg.GlobalBurstWindow,
	)
}

// Wait blocks until the dispatcher goroutine exits.
func (d *Dispatcher) Wait() {
	d.wg.Wait()
}

func (d *Dispatcher) run(ctx context.Context) {
	defer d.wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("[AlertDispatcher] Shutting down")
			return

		case alert, ok := <-d.alertChan:
			if !ok {
				log.Println("[AlertDispatcher] Channel closed, exiting")
				return
			}
			d.processAlert(alert)
		}
	}
}

func (d *Dispatcher) processAlert(alert Alert) {
	// Apply rate limiting
	if !d.limiter.Allow(alert.AttackType) {
		metrics.AlertsSuppressed.Inc()
		return
	}

	// Build and send the webhook payload
	if err := d.sendWebhook(alert); err != nil {
		metrics.AlertSendErrors.Inc()
		log.Printf("[AlertDispatcher] Webhook error: %v", err)
		return
	}

	metrics.AlertsSent.Inc()
	log.Printf("[AlertDispatcher] %s", alert.Summary())
}

func (d *Dispatcher) sendWebhook(alert Alert) error {
	var payload []byte
	var err error

	switch d.cfg.WebhookType {
	case "slack":
		payload, err = d.formatSlack(alert)
	case "telegram":
		payload, err = d.formatTelegram(alert)
	default:
		payload, err = d.formatGeneric(alert)
	}
	if err != nil {
		return fmt.Errorf("format payload: %w", err)
	}

	req, err := http.NewRequest("POST", d.cfg.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		// Read the response body for debugging — Telegram returns a JSON
		// error description that is critical for diagnosing failures.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ─── Payload Formatters ──────────────────────────────────────────────────────

// formatSlack builds a Slack incoming webhook payload with rich formatting.
func (d *Dispatcher) formatSlack(alert Alert) ([]byte, error) {
	payload := map[string]interface{}{
		"text": alert.Summary(),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("🚨 PacketLens Alert: %s", alert.AttackType),
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Source:*\n`%s:%d`", alert.SrcIP, alert.SrcPort)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Destination:*\n`%s:%d`", alert.DstIP, alert.DstPort)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Protocol:*\n%s", alert.ProtocolName())},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Confidence:*\n%.1f%%", alert.Confidence*100)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Inference:*\n%dµs", alert.InferenceUs)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Detected:*\n%s", alert.DetectedAt.Format(time.RFC3339))},
				},
			},
		},
	}
	return json.Marshal(payload)
}

// formatTelegram builds a Telegram Bot API sendMessage payload with HTML.
// chat_id is sent as an integer (Telegram requires this for numeric IDs).
func (d *Dispatcher) formatTelegram(alert Alert) ([]byte, error) {
	text := fmt.Sprintf(
		"🚨 <b>PacketLens Alert: %s</b>\n\n"+
			"<b>Source:</b> <code>%s:%d</code>\n"+
			"<b>Destination:</b> <code>%s:%d</code>\n"+
			"<b>Protocol:</b> %s\n"+
			"<b>Confidence:</b> %.1f%%\n"+
			"<b>Inference:</b> %dµs\n"+
			"<b>Detected:</b> %s",
		alert.AttackType,
		alert.SrcIP, alert.SrcPort,
		alert.DstIP, alert.DstPort,
		alert.ProtocolName(),
		alert.Confidence*100,
		alert.InferenceUs,
		alert.DetectedAt.Format(time.RFC3339),
	)

	// Telegram API requires chat_id as a number for numeric IDs.
	// Parse from string config; fall back to string if not numeric (e.g. @channel).
	var chatID interface{}
	if id, err := strconv.ParseInt(d.cfg.TelegramChatID, 10, 64); err == nil {
		chatID = id
	} else {
		chatID = d.cfg.TelegramChatID // @username-style channel
	}

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	return json.Marshal(payload)
}

// formatGeneric builds a simple JSON payload for any generic webhook endpoint.
func (d *Dispatcher) formatGeneric(alert Alert) ([]byte, error) {
	payload := map[string]interface{}{
		"event":        "packetlens_alert",
		"detected_at":  alert.DetectedAt.Format(time.RFC3339),
		"attack_type":  alert.AttackType,
		"confidence":   alert.Confidence,
		"src_ip":       alert.SrcIP.String(),
		"dst_ip":       alert.DstIP.String(),
		"src_port":     alert.SrcPort,
		"dst_port":     alert.DstPort,
		"protocol":     alert.ProtocolName(),
		"inference_us": alert.InferenceUs,
		"flow_id":      alert.FlowID,
		"summary":      alert.Summary(),
	}
	return json.Marshal(payload)
}

package detect

import (
	"fmt"
	"testing"

	"github.com/modermatt44/portal/internal/fakeserver"
)

// redisHandler emulates a Redis server that answers PING with pong. It
// ignores RESP framing lines ("*1", "$4") and treats other text as inline
// commands, closing on anything it does not know, as Redis does for HTTP.
func redisHandler(pong string) func(string) (string, bool) {
	const info = "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 6.8.0 x86_64\r\n"
	return func(line string) (string, bool) {
		switch {
		case line == "":
		case line[0] == '*' || line[0] == '$':
		case line == "PING":
			return pong + "\r\n", false
		case line == "INFO":
		case line == "server":
			return fmt.Sprintf("$%d\r\n%s\r\n", len(info), info), false
		default:
			return "-ERR unknown command\r\n", true
		}
		return "", false
	}
}

func TestDetectRedis(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		pong        string
		wantConf    Confidence
		wantVersion string
		wantDetail  [2]string
	}{
		{"open", "+PONG", Confirmed, "7.2.4", [2]string{"mode", "standalone"}},
		{"password", "-NOAUTH Authentication required.", Confirmed, "", [2]string{"auth", "required"}},
		{"protected mode", "-DENIED Redis is running in protected mode", Confirmed, "", [2]string{"protected_mode", "enabled; only local clients may connect"}},
		{"other RESP error", "-ERR unknown command 'PING'", Likely, "", [2]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := fakeserver.Start(t, fakeserver.Lines("", redisHandler(tt.pong)))
			best := wantBest(t, detectFake(t, s), Redis, tt.wantConf)
			if best.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", best.Version, tt.wantVersion)
			}
			if k := tt.wantDetail[0]; k != "" && best.Details[k] != tt.wantDetail[1] {
				t.Errorf("detail %s = %q, want %q", k, best.Details[k], tt.wantDetail[1])
			}
		})
	}
}

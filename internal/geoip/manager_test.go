package geoip

import (
	"testing"
	"time"
)

func TestNormalizeProvider(t *testing.T) {
	cases := map[string]string{
		"":          IDDBIPCityLite,
		"dbip":      IDDBIPCityLite,
		"DB-IP":     IDDBIPCityLite,
		"geolite2":  IDGeoLite2City,
		"maxmind":   IDGeoLite2City,
		"something": IDDBIPCityLite,
	}
	for input, want := range cases {
		if got := normalizeProvider(input); got != want {
			t.Fatalf("normalizeProvider(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNextUpdateAfter(t *testing.T) {
	monthly := DatabaseDefinition{Cadence: "monthly"}
	twiceWeekly := DatabaseDefinition{Cadence: "tuesday-friday"}

	if got, want := nextUpdateAfter(monthly, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)), time.Date(2026, 6, 1, updateHourUTC, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("monthly next update = %s, want %s", got, want)
	}
	if got, want := nextUpdateAfter(twiceWeekly, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)), time.Date(2026, 5, 22, updateHourUTC, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("twice-weekly next update = %s, want %s", got, want)
	}
	if got, want := nextUpdateAfter(twiceWeekly, time.Date(2026, 5, 22, 7, 0, 0, 0, time.UTC)), time.Date(2026, 5, 26, updateHourUTC, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("twice-weekly next update after Friday = %s, want %s", got, want)
	}
}

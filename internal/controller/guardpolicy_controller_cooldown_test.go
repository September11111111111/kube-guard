package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestInCooldown(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 17, 18, 0, 0, 0, time.UTC)
	recent := metav1.NewTime(now.Add(-30 * time.Second))
	old := metav1.NewTime(now.Add(-5 * time.Minute))
	boundary := metav1.NewTime(now.Add(-1 * time.Minute))

	tests := []struct {
		name     string
		last     *metav1.Time
		cooldown time.Duration
		want     bool
	}{
		{
			name:     "nil last action",
			last:     nil,
			cooldown: 1 * time.Minute,
			want:     false,
		},
		{
			name:     "recent action still cooling down",
			last:     &recent,
			cooldown: 1 * time.Minute,
			want:     true,
		},
		{
			name:     "old action expired",
			last:     &old,
			cooldown: 1 * time.Minute,
			want:     false,
		},
		{
			name:     "exact boundary not in cooldown",
			last:     &boundary,
			cooldown: 1 * time.Minute,
			want:     false,
		},
		{
			name:     "zero cooldown",
			last:     &recent,
			cooldown: 0,
			want:     false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := inCooldown(tt.last, tt.cooldown, now)
			if got != tt.want {
				t.Fatalf("inCooldown() = %v, want %v", got, tt.want)
			}
		})
	}
}

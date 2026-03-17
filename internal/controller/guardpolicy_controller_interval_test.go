package controller

import (
	"testing"
	"time"

	opsv1alpha1 "example.com/kube-guard/api/v1alpha1"
)

func TestResolveIntervals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		everySeconds int32
		cooldownSecs int32
		wantEvery    time.Duration
		wantCooldown time.Duration
	}{
		{
			name:         "both default when zero",
			everySeconds: 0,
			cooldownSecs: 0,
			wantEvery:    30 * time.Second,
			wantCooldown: 180 * time.Second,
		},
		{
			name:         "both default when negative",
			everySeconds: -1,
			cooldownSecs: -2,
			wantEvery:    30 * time.Second,
			wantCooldown: 180 * time.Second,
		},
		{
			name:         "custom values",
			everySeconds: 15,
			cooldownSecs: 60,
			wantEvery:    15 * time.Second,
			wantCooldown: 60 * time.Second,
		},
		{
			name:         "default every only",
			everySeconds: 0,
			cooldownSecs: 45,
			wantEvery:    30 * time.Second,
			wantCooldown: 45 * time.Second,
		},
		{
			name:         "default cooldown only",
			everySeconds: 20,
			cooldownSecs: 0,
			wantEvery:    20 * time.Second,
			wantCooldown: 180 * time.Second,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gp := opsv1alpha1.GuardPolicy{}
			gp.Spec.EvaluateEverySeconds = tt.everySeconds
			gp.Spec.CooldownSeconds = tt.cooldownSecs

			gotEvery, gotCooldown := resolveIntervals(gp)
			if gotEvery != tt.wantEvery {
				t.Fatalf("every = %v, want %v", gotEvery, tt.wantEvery)
			}
			if gotCooldown != tt.wantCooldown {
				t.Fatalf("cooldown = %v, want %v", gotCooldown, tt.wantCooldown)
			}
		})
	}
}

package controller

import (
	"testing"

	opsv1alpha1 "example.com/kube-guard/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func findCondition(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}

func TestSetReadyConditions(t *testing.T) {
	t.Parallel()

	var status opsv1alpha1.GuardPolicyStatus
	generation := int64(7)

	setReadyConditions(&status, generation)

	if len(status.Conditions) != 2 {
		t.Fatalf("len(status.Conditions) = %d, want 2", len(status.Conditions))
	}

	degraded := findCondition(status.Conditions, ConditionDegraded)
	if degraded == nil {
		t.Fatal("Degraded condition not found")
	}
	if degraded.Status != metav1.ConditionFalse {
		t.Fatalf("Degraded.Status = %s, want %s", degraded.Status, metav1.ConditionFalse)
	}
	if degraded.Reason != "OK" {
		t.Fatalf("Degraded.Reason = %q, want %q", degraded.Reason, "OK")
	}
	if degraded.Message != "Prometheus query succeeded" {
		t.Fatalf("Degraded.Message = %q, want %q", degraded.Message, "Prometheus query succeeded")
	}
	if degraded.ObservedGeneration != generation {
		t.Fatalf("Degraded.ObservedGeneration = %d, want %d", degraded.ObservedGeneration, generation)
	}

	available := findCondition(status.Conditions, ConditionAvailable)
	if available == nil {
		t.Fatal("Available condition not found")
	}
	if available.Status != metav1.ConditionTrue {
		t.Fatalf("Available.Status = %s, want %s", available.Status, metav1.ConditionTrue)
	}
	if available.Reason != "Ready" {
		t.Fatalf("Available.Reason = %q, want %q", available.Reason, "Ready")
	}
	if available.Message != "Policy evaluated" {
		t.Fatalf("Available.Message = %q, want %q", available.Message, "Policy evaluated")
	}
	if available.ObservedGeneration != generation {
		t.Fatalf("Available.ObservedGeneration = %d, want %d", available.ObservedGeneration, generation)
	}
}

func TestSetQueryFailedConditions(t *testing.T) {
	t.Parallel()

	var status opsv1alpha1.GuardPolicyStatus
	generation := int64(8)
	msg := "dial tcp: connection refused"

	setQueryFailedConditions(&status, generation, msg)

	if len(status.Conditions) != 2 {
		t.Fatalf("len(status.Conditions) = %d, want 2", len(status.Conditions))
	}

	degraded := findCondition(status.Conditions, ConditionDegraded)
	if degraded == nil {
		t.Fatal("Degraded condition not found")
	}
	if degraded.Status != metav1.ConditionTrue {
		t.Fatalf("Degraded.Status = %s, want %s", degraded.Status, metav1.ConditionTrue)
	}
	if degraded.Reason != "PrometheusQueryFailed" {
		t.Fatalf("Degraded.Reason = %q, want %q", degraded.Reason, "PrometheusQueryFailed")
	}
	if degraded.Message != msg {
		t.Fatalf("Degraded.Message = %q, want %q", degraded.Message, msg)
	}

	available := findCondition(status.Conditions, ConditionAvailable)
	if available == nil {
		t.Fatal("Available condition not found")
	}
	if available.Status != metav1.ConditionFalse {
		t.Fatalf("Available.Status = %s, want %s", available.Status, metav1.ConditionFalse)
	}
	if available.Reason != "NotReady" {
		t.Fatalf("Available.Reason = %q, want %q", available.Reason, "NotReady")
	}
	if available.Message != "Prometheus query failed" {
		t.Fatalf("Available.Message = %q, want %q", available.Message, "Prometheus query failed")
	}
}

func TestSetTargetNotFoundConditions(t *testing.T) {
	t.Parallel()

	var status opsv1alpha1.GuardPolicyStatus
	generation := int64(9)
	msg := "deployments.apps \"demo\" not found"

	setTargetNotFoundConditions(&status, generation, msg)

	if len(status.Conditions) != 2 {
		t.Fatalf("len(status.Conditions) = %d, want 2", len(status.Conditions))
	}

	degraded := findCondition(status.Conditions, ConditionDegraded)
	if degraded == nil {
		t.Fatal("Degraded condition not found")
	}
	if degraded.Status != metav1.ConditionTrue {
		t.Fatalf("Degraded.Status = %s, want %s", degraded.Status, metav1.ConditionTrue)
	}
	if degraded.Reason != "TargetNotFound" {
		t.Fatalf("Degraded.Reason = %q, want %q", degraded.Reason, "TargetNotFound")
	}
	if degraded.Message != msg {
		t.Fatalf("Degraded.Message = %q, want %q", degraded.Message, msg)
	}

	available := findCondition(status.Conditions, ConditionAvailable)
	if available == nil {
		t.Fatal("Available condition not found")
	}
	if available.Status != metav1.ConditionFalse {
		t.Fatalf("Available.Status = %s, want %s", available.Status, metav1.ConditionFalse)
	}
	if available.Reason != "NotReady" {
		t.Fatalf("Available.Reason = %q, want %q", available.Reason, "NotReady")
	}
	if available.Message != "Target deployment not found" {
		t.Fatalf("Available.Message = %q, want %q", available.Message, "Target deployment not found")
	}
}

func TestSetRestartPatchFailedConditions(t *testing.T) {
	t.Parallel()

	var status opsv1alpha1.GuardPolicyStatus
	generation := int64(10)
	msg := "patch failed"

	setRestartPatchFailedConditions(&status, generation, msg)

	if len(status.Conditions) != 2 {
		t.Fatalf("len(status.Conditions) = %d, want 2", len(status.Conditions))
	}

	degraded := findCondition(status.Conditions, ConditionDegraded)
	if degraded == nil {
		t.Fatal("Degraded condition not found")
	}
	if degraded.Status != metav1.ConditionTrue {
		t.Fatalf("Degraded.Status = %s, want %s", degraded.Status, metav1.ConditionTrue)
	}
	if degraded.Reason != "RestartPatchFailed" {
		t.Fatalf("Degraded.Reason = %q, want %q", degraded.Reason, "RestartPatchFailed")
	}
	if degraded.Message != msg {
		t.Fatalf("Degraded.Message = %q, want %q", degraded.Message, msg)
	}

	available := findCondition(status.Conditions, ConditionAvailable)
	if available == nil {
		t.Fatal("Available condition not found")
	}
	if available.Status != metav1.ConditionFalse {
		t.Fatalf("Available.Status = %s, want %s", available.Status, metav1.ConditionFalse)
	}
	if available.Reason != "NotReady" {
		t.Fatalf("Available.Reason = %q, want %q", available.Reason, "NotReady")
	}
	if available.Message != "Failed to restart target" {
		t.Fatalf("Available.Message = %q, want %q", available.Message, "Failed to restart target")
	}
}

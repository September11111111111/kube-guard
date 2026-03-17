package controller

import (
	"time"

	opsv1alpha1 "example.com/kube-guard/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func resolveIntervals(gp opsv1alpha1.GuardPolicy) (time.Duration, time.Duration) {
	every := time.Duration(gp.Spec.EvaluateEverySeconds) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}

	cooldown := time.Duration(gp.Spec.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = 180 * time.Second
	}

	return every, cooldown
}

func inCooldown(last *metav1.Time, cooldown time.Duration, now time.Time) bool {
	if last == nil {
		return false
	}
	if cooldown <= 0 {
		return false
	}
	return now.Sub(last.Time) < cooldown
}

func setReadyConditions(status *opsv1alpha1.GuardPolicyStatus, generation int64) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionDegraded,
		Status:             metav1.ConditionFalse,
		Reason:             "OK",
		Message:            "Prometheus query succeeded",
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})

	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionAvailable,
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            "Policy evaluated",
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})
}

func setQueryFailedConditions(status *opsv1alpha1.GuardPolicyStatus, generation int64, msg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionDegraded,
		Status:             metav1.ConditionTrue,
		Reason:             "PrometheusQueryFailed",
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})

	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionAvailable,
		Status:             metav1.ConditionFalse,
		Reason:             "NotReady",
		Message:            "Prometheus query failed",
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})
}

func setTargetNotFoundConditions(status *opsv1alpha1.GuardPolicyStatus, generation int64, msg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionDegraded,
		Status:             metav1.ConditionTrue,
		Reason:             "TargetNotFound",
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})

	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionAvailable,
		Status:             metav1.ConditionFalse,
		Reason:             "NotReady",
		Message:            "Target deployment not found",
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})
}

func setRestartPatchFailedConditions(status *opsv1alpha1.GuardPolicyStatus, generation int64, msg string) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionDegraded,
		Status:             metav1.ConditionTrue,
		Reason:             "RestartPatchFailed",
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})

	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               ConditionAvailable,
		Status:             metav1.ConditionFalse,
		Reason:             "NotReady",
		Message:            "Failed to restart target",
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	})
}

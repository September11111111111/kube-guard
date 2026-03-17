package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGuardPolicyDeepCopy(t *testing.T) {
	t.Parallel()

	now := metav1.Now()

	original := &GuardPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "GuardPolicy",
			APIVersion: "ops.example.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
			Labels: map[string]string{
				"app": "demo",
			},
		},
		Spec: GuardPolicySpec{
			PrometheusURL:        "http://prometheus:9090",
			Query:                "up",
			Threshold:            "> 0",
			EvaluateEverySeconds: 30,
			CooldownSeconds:      60,
			TargetRef: TargetRef{
				Namespace: "default",
				Kind:      "Deployment",
				Name:      "demo-app",
			},
		},
		Status: GuardPolicyStatus{
			LastValue:      "1",
			LastActionTime: &now,
			LastAction:     "restart",
			Conditions: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionTrue,
					Reason:             "Healthy",
					Message:            "resource is healthy",
					ObservedGeneration: 1,
					LastTransitionTime: now,
				},
			},
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy() returned nil")
	}
	if copied == original {
		t.Fatal("DeepCopy() returned the same pointer")
	}

	if copied.Name != original.Name {
		t.Fatalf("copied.Name = %q, want %q", copied.Name, original.Name)
	}
	if copied.Spec.TargetRef.Name != original.Spec.TargetRef.Name {
		t.Fatalf("copied.Spec.TargetRef.Name = %q, want %q", copied.Spec.TargetRef.Name, original.Spec.TargetRef.Name)
	}
	if copied.Status.LastAction != original.Status.LastAction {
		t.Fatalf("copied.Status.LastAction = %q, want %q", copied.Status.LastAction, original.Status.LastAction)
	}

	copied.Labels["app"] = "changed"
	if original.Labels["app"] != "demo" {
		t.Fatalf("original labels were modified, got %q, want %q", original.Labels["app"], "demo")
	}

	copied.Spec.TargetRef.Name = "changed-app"
	if original.Spec.TargetRef.Name != "demo-app" {
		t.Fatalf("original targetRef name was modified, got %q, want %q", original.Spec.TargetRef.Name, "demo-app")
	}

	if copied.Status.LastActionTime == original.Status.LastActionTime {
		t.Fatal("LastActionTime pointer was shallow-copied")
	}

	copied.Status.LastAction = "scale"
	if original.Status.LastAction != "restart" {
		t.Fatalf("original LastAction was modified, got %q, want %q", original.Status.LastAction, "restart")
	}

	copied.Status.Conditions[0].Reason = "Changed"
	if original.Status.Conditions[0].Reason != "Healthy" {
		t.Fatalf("original condition was modified, got %q, want %q", original.Status.Conditions[0].Reason, "Healthy")
	}
}

func TestGuardPolicyDeepCopyObject(t *testing.T) {
	t.Parallel()

	original := &GuardPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject() returned nil")
	}

	copied, ok := obj.(*GuardPolicy)
	if !ok {
		t.Fatalf("DeepCopyObject() returned %T, want *GuardPolicy", obj)
	}
	if copied == original {
		t.Fatal("DeepCopyObject() returned the same pointer")
	}
	if copied.Name != original.Name {
		t.Fatalf("copied.Name = %q, want %q", copied.Name, original.Name)
	}
}

func TestGuardPolicyListDeepCopy(t *testing.T) {
	t.Parallel()

	original := &GuardPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "GuardPolicyList",
			APIVersion: "ops.example.com/v1alpha1",
		},
		Items: []GuardPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "policy-1",
					Namespace: "default",
					Labels: map[string]string{
						"env": "test",
					},
				},
				Spec: GuardPolicySpec{
					PrometheusURL:   "http://prometheus:9090",
					Query:           "up",
					Threshold:       "> 0",
					CooldownSeconds: 60,
					TargetRef: TargetRef{
						Namespace: "default",
						Kind:      "Deployment",
						Name:      "app-1",
					},
				},
			},
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("GuardPolicyList DeepCopy() returned nil")
	}
	if copied == original {
		t.Fatal("GuardPolicyList DeepCopy() returned the same pointer")
	}

	if len(copied.Items) != 1 {
		t.Fatalf("len(copied.Items) = %d, want 1", len(copied.Items))
	}

	copied.Items[0].Name = "changed-policy"
	if original.Items[0].Name != "policy-1" {
		t.Fatalf("original item name was modified, got %q, want %q", original.Items[0].Name, "policy-1")
	}

	copied.Items[0].Labels["env"] = "prod"
	if original.Items[0].Labels["env"] != "test" {
		t.Fatalf("original labels were modified, got %q, want %q", original.Items[0].Labels["env"], "test")
	}
}

func TestGuardPolicyListDeepCopyObject(t *testing.T) {
	t.Parallel()

	original := &GuardPolicyList{
		Items: []GuardPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-1"},
			},
		},
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject() returned nil")
	}

	copied, ok := obj.(*GuardPolicyList)
	if !ok {
		t.Fatalf("DeepCopyObject() returned %T, want *GuardPolicyList", obj)
	}
	if copied == original {
		t.Fatal("DeepCopyObject() returned the same pointer")
	}
	if len(copied.Items) != 1 {
		t.Fatalf("len(copied.Items) = %d, want 1", len(copied.Items))
	}
}

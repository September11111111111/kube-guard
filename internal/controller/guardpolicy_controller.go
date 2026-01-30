/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	opsv1alpha1 "example.com/kube-guard/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// +kubebuilder:rbac:groups=ops.example.com,resources=guardpolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=ops.example.com,resources=guardpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch

const (
	ConditionAvailable = "Available"
	ConditionDegraded  = "Degraded"

	ActionNone    = "None"
	ActionRestart = "Restart"
)

// GuardPolicyReconciler reconciles a GuardPolicy object
type GuardPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ops.example.com,resources=guardpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ops.example.com,resources=guardpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ops.example.com,resources=guardpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the GuardPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.0/pkg/reconcile
func (r *GuardPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var gp opsv1alpha1.GuardPolicy
	if err := r.Get(ctx, req.NamespacedName, &gp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 计算周期参数
	every := time.Duration(gp.Spec.EvaluateEverySeconds) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	cooldown := time.Duration(gp.Spec.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = 180 * time.Second
	}

	// status patch 基线
	base := gp.DeepCopy()

	// 小工具：写 condition
	setCond := func(c metav1.Condition) {
		meta.SetStatusCondition(&gp.Status.Conditions, c)
	}

	// 确保 action 不为空（首次创建时）
	if gp.Status.LastAction == "" {
		gp.Status.LastAction = ActionNone
	}

	//  Query Prometheus
	val, err := queryPrometheusInstant(ctx, gp.Spec.PrometheusURL, gp.Spec.Query)
	if err != nil {
		l.Error(err, "failed to query prometheus")

		setCond(metav1.Condition{
			Type:               ConditionDegraded,
			Status:             metav1.ConditionTrue,
			Reason:             "PrometheusQueryFailed",
			Message:            err.Error(),
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})
		setCond(metav1.Condition{
			Type:               ConditionAvailable,
			Status:             metav1.ConditionFalse,
			Reason:             "NotReady",
			Message:            "Prometheus query failed",
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})

		// 把失败状态写回（不要吞错）
		if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
			return ctrl.Result{}, err2
		}
		return ctrl.Result{RequeueAfter: every}, nil
	}

	// query 成功：写 lastValue + 健康条件
	gp.Status.LastValue = fmt.Sprintf("%g", val)
	setCond(metav1.Condition{
		Type:               "Degraded",
		Status:             metav1.ConditionFalse,
		Reason:             "OK",
		Message:            "Prometheus query succeeded",
		ObservedGeneration: gp.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	})
	setCond(metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            "Policy evaluated",
		ObservedGeneration: gp.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	})

	ok, err := evalThreshold(gp.Spec.Threshold, val)
	if err != nil {
		l.Error(err, "invalid threshold", "threshold", gp.Spec.Threshold)

		setCond(metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			Reason:             "PrometheusQueryFailed",
			Message:            err.Error(),
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})
		setCond(metav1.Condition{
			Type:               "Available",
			Status:             metav1.ConditionFalse,
			Reason:             "NotReady",
			Message:            "Prometheus query failed",
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})

		if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
			return ctrl.Result{}, err2
		}
		return ctrl.Result{RequeueAfter: every}, nil
	}

	//  cooldown check（ok=true 才需要）
	if ok && gp.Status.LastActionTime != nil && time.Since(gp.Status.LastActionTime.Time) < cooldown {
		// 只更新 lastValue/conditions/action(None) 即可
		gp.Status.LastAction = ActionNone
		if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
			return ctrl.Result{}, err2
		}
		l.Info("in cooldown, skip action", "policy", req.NamespacedName.String(), "value", val, "cooldown", cooldown.String())
		return ctrl.Result{RequeueAfter: every}, nil
	}

	//  不触发：明确写 None + 写回 status
	if !ok {
		gp.Status.LastAction = ActionNone
		if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
			return ctrl.Result{}, err2
		}
		l.Info("policy evaluated (no action)", "policy", req.NamespacedName.String(), "value", val, "threshold", gp.Spec.Threshold)
		return ctrl.Result{RequeueAfter: every}, nil
	}

	//  触发动作：重启 deployment
	ns := gp.Spec.TargetRef.Namespace
	name := gp.Spec.TargetRef.Name

	var dep appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &dep); err != nil {
		l.Error(err, "target deployment not found", "ns", ns, "name", name)

		setCond(metav1.Condition{
			Type:               ConditionDegraded,
			Status:             metav1.ConditionTrue,
			Reason:             "TargetNotFound",
			Message:            err.Error(),
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})
		setCond(metav1.Condition{
			Type:               ConditionAvailable,
			Status:             metav1.ConditionFalse,
			Reason:             "NotReady",
			Message:            "Target deployment not found",
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})

		gp.Status.LastAction = ActionNone
		if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
			return ctrl.Result{}, err2
		}
		return ctrl.Result{RequeueAfter: every}, nil
	}

	patch := client.MergeFrom(dep.DeepCopy())
	if dep.Spec.Template.Annotations == nil {
		dep.Spec.Template.Annotations = map[string]string{}
	}
	dep.Spec.Template.Annotations["kubeguard/restartedAt"] = time.Now().Format(time.RFC3339)

	if err := r.Patch(ctx, &dep, patch); err != nil {
		l.Error(err, "failed to patch deployment for restart")

		setCond(metav1.Condition{
			Type:               ConditionDegraded,
			Status:             metav1.ConditionTrue,
			Reason:             "RestartPatchFailed",
			Message:            err.Error(),
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})
		setCond(metav1.Condition{
			Type:               ConditionAvailable,
			Status:             metav1.ConditionFalse,
			Reason:             "NotReady",
			Message:            "Failed to restart target",
			ObservedGeneration: gp.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})

		if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
			return ctrl.Result{}, err2
		}
		return ctrl.Result{RequeueAfter: every}, nil
	}

	// restart 成功：写 action + time，再写回 status（一次就够）
	now := metav1.Now()
	gp.Status.LastActionTime = &now
	gp.Status.LastAction = ActionRestart

	if err2 := r.Status().Patch(ctx, &gp, client.MergeFrom(base)); err2 != nil {
		return ctrl.Result{}, err2
	}

	l.Info("restart triggered",
		"policy", req.NamespacedName.String(),
		"value", val,
		"threshold", gp.Spec.Threshold,
		"target", ns+"/"+name,
		"requeueAfter", every.String(),
	)

	return ctrl.Result{RequeueAfter: every}, nil
}

func (r *GuardPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&opsv1alpha1.GuardPolicy{}).
		Complete(r)

}

// ---- helpers ----

type promResp struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Value []any `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func queryPrometheusInstant(ctx context.Context, baseURL, promql string) (float64, error) {
	if baseURL == "" {
		return 0, fmt.Errorf("empty prometheusURL")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return 0, err
	}
	u.Path = u.Path + "/api/v1/query"
	q := u.Query()
	q.Set("query", promql)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	cli := &http.Client{Timeout: 8 * time.Second}

	resp, err := cli.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var pr promResp
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return 0, err
	}
	if pr.Status != "success" {
		return 0, fmt.Errorf("prometheus status=%s", pr.Status)
	}
	// Empty vector => treat as 0
	if len(pr.Data.Result) == 0 || len(pr.Data.Result[0].Value) < 2 {
		return 0, nil
	}
	// value[1] is string number
	s, ok := pr.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, fmt.Errorf("unexpected value type")
	}
	return strconv.ParseFloat(s, 64)
}

func evalThreshold(expr string, v float64) (bool, error) {
	expr = strings.TrimSpace(expr)
	ops := []string{">=", "<=", "==", "!=", ">", "<"}
	var op string
	for _, o := range ops {
		if strings.HasPrefix(expr, o) {
			op = o
			break
		}
	}
	if op == "" {
		return false, fmt.Errorf("threshold must start with one of >= <= == != > <")
	}
	numStr := strings.TrimSpace(strings.TrimPrefix(expr, op))
	t, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return false, err
	}
	switch op {
	case ">":
		return v > t, nil
	case ">=":
		return v >= t, nil
	case "<":
		return v < t, nil
	case "<=":
		return v <= t, nil
	case "==":
		return v == t, nil
	case "!=":
		return v != t, nil
	default:
		return false, fmt.Errorf("unknown op")
	}
}

func (r *GuardPolicyReconciler) setCondition(gp *opsv1alpha1.GuardPolicy, cond metav1.Condition) {
	meta.SetStatusCondition(&gp.Status.Conditions, cond)
}

func nowTimePtr() *metav1.Time {
	t := metav1.Now()
	return &t
}

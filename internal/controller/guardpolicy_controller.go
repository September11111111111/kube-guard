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
		// deleted
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	every := time.Duration(gp.Spec.EvaluateEverySeconds) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	cooldown := time.Duration(gp.Spec.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = 180 * time.Second
	}

	// Query Prometheus
	val, err := queryPrometheusInstant(ctx, gp.Spec.PrometheusURL, gp.Spec.Query)
	if err != nil {
		l.Error(err, "failed to query prometheus")
		// still requeue
		return ctrl.Result{RequeueAfter: every}, nil
	}
	gp.Status.LastValue = fmt.Sprintf("%g", val)

	// Evaluate threshold
	ok, err := evalThreshold(gp.Spec.Threshold, val)
	if err != nil {
		l.Error(err, "invalid threshold", "threshold", gp.Spec.Threshold)
		return ctrl.Result{RequeueAfter: every}, nil
	}

	// Cooldown check
	if ok && gp.Status.LastActionTime != nil {
		if time.Since(gp.Status.LastActionTime.Time) < cooldown {
			// In cooldown; only update status value
			_ = r.Status().Update(ctx, &gp)
			return ctrl.Result{RequeueAfter: every}, nil
		}
	}

	// If not triggered, just update status and requeue
	if !ok {
		_ = r.Status().Update(ctx, &gp)
		return ctrl.Result{RequeueAfter: every}, nil
	}

	// Trigger: restart deployment by patching pod template annotation
	ns := gp.Spec.TargetRef.Namespace
	name := gp.Spec.TargetRef.Name

	var dep appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &dep); err != nil {
		l.Error(err, "target deployment not found", "ns", ns, "name", name)
		_ = r.Status().Update(ctx, &gp)
		return ctrl.Result{RequeueAfter: every}, nil
	}

	patch := client.MergeFrom(dep.DeepCopy())
	if dep.Spec.Template.Annotations == nil {
		dep.Spec.Template.Annotations = map[string]string{}
	}
	dep.Spec.Template.Annotations["kubeguard/restartedAt"] = time.Now().Format(time.RFC3339)

	if err := r.Patch(ctx, &dep, patch); err != nil {
		l.Error(err, "failed to patch deployment for restart")
		return ctrl.Result{RequeueAfter: every}, nil
	}

	now := metav1.Now()
	gp.Status.LastActionTime = &now
	gp.Status.LastAction = fmt.Sprintf("restarted deployment %s/%s", ns, name)
	_ = r.Status().Update(ctx, &gp)

	l.Info("restart triggered", "policy", req.NamespacedName.String(), "value", val, "threshold", gp.Spec.Threshold, "target", ns+"/"+name)
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

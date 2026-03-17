package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	opsv1alpha1 "example.com/kube-guard/api/v1alpha1"
)

var _ = Describe("GuardPolicy Controller", func() {
	const (
		resourceName = "test-resource"
		namespace    = "default"
	)

	ctx := context.Background()
	typeNamespacedName := types.NamespacedName{
		Name:      resourceName,
		Namespace: namespace,
	}

	newGuardPolicy := func() *opsv1alpha1.GuardPolicy {
		return &opsv1alpha1.GuardPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resourceName,
				Namespace: namespace,
			},
			Spec: opsv1alpha1.GuardPolicySpec{
				// TODO: 填入你的最小有效 spec
			},
		}
	}

	BeforeEach(func() {
		resource := &opsv1alpha1.GuardPolicy{}
		err := k8sClient.Get(ctx, typeNamespacedName, resource)
		if err != nil && errors.IsNotFound(err) {
			Expect(k8sClient.Create(ctx, newGuardPolicy())).To(Succeed())
		} else {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	AfterEach(func() {
		resource := &opsv1alpha1.GuardPolicy{}
		err := k8sClient.Get(ctx, typeNamespacedName, resource)
		if err != nil {
			Expect(errors.IsNotFound(err)).To(BeTrue())
			return
		}
		Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
	})

	It("should reconcile an existing GuardPolicy without error", func() {
		controllerReconciler := &GuardPolicyReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: typeNamespacedName,
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue || result.RequeueAfter >= 0).To(BeTrue())

		got := &opsv1alpha1.GuardPolicy{}
		Expect(k8sClient.Get(ctx, typeNamespacedName, got)).To(Succeed())

		// TODO: 根据你的控制器逻辑补充这些断言
		// Expect(got.Status.ObservedGeneration).To(Equal(got.Generation))
		// Expect(got.Status.LastCheckTime.IsZero()).To(BeFalse())
	})

	It("should ignore a missing GuardPolicy", func() {
		controllerReconciler := &GuardPolicyReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "not-found",
				Namespace: namespace,
			},
		}

		_, err := controllerReconciler.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
	})
})

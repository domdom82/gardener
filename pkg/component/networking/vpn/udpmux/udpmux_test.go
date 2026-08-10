// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package udpmux_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/component/networking/vpn/udpmux"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
)

var _ = Describe("UDPMux", func() {
	var (
		ctx    context.Context
		c      client.Client
		values udpmux.Values
		comp   udpmux.Interface
	)

	BeforeEach(func() {
		ctx = context.Background()
		values = udpmux.Values{
			Image:     "some-image:tag",
			Namespace: "vpn-ingress",
			Replicas:  2,
			LoadBalancerAnnotations: map[string]string{
				"service.beta.kubernetes.io/aws-load-balancer-type": "external",
			},
		}
		c = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		comp = udpmux.New(c, values)
	})

	Describe("#Deploy", func() {
		It("should create Namespace with vpn-ingress GardenRole label", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())

			ns := &corev1.Namespace{}
			Expect(c.Get(ctx, types.NamespacedName{Name: values.Namespace}, ns)).To(Succeed())
			Expect(ns.Labels).To(HaveKeyWithValue(v1beta1constants.GardenRole, v1beta1constants.GardenRoleVPNIngress))
		})

		It("should create a Deployment", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())

			deploy := &appsv1.Deployment{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, deploy)).To(Succeed())
			Expect(deploy.Labels).To(HaveKeyWithValue(v1beta1constants.LabelApp, "udp-mux"))
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deploy.Spec.Template.Spec.Containers[0].Name).To(Equal("udp-mux"))
			Expect(deploy.Spec.Template.Spec.Containers[0].Image).To(Equal(values.Image))

			alias := v1beta1constants.LabelNetworkPolicyShootNamespaceAlias
			Expect(deploy.Spec.Template.Labels).To(HaveKeyWithValue(
				gardenerutils.NetworkPolicyLabelUDP(alias+"-vpn-seed-server", 1194),
				v1beta1constants.LabelNetworkPolicyAllowed,
			))
			Expect(deploy.Spec.Template.Labels).To(HaveKeyWithValue(
				gardenerutils.NetworkPolicyLabelUDP(alias+"-vpn-seed-server-0", 1194),
				v1beta1constants.LabelNetworkPolicyAllowed,
			))
			Expect(deploy.Spec.Template.Labels).To(HaveKeyWithValue(
				gardenerutils.NetworkPolicyLabelUDP(alias+"-vpn-seed-server-1", 1194),
				v1beta1constants.LabelNetworkPolicyAllowed,
			))
		})

		It("should create a LoadBalancer Service", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())

			svc := &corev1.Service{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, svc)).To(Succeed())
			Expect(svc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(svc.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Protocol).To(Equal(corev1.ProtocolUDP))
			Expect(svc.Spec.Ports[0].Port).To(BeEquivalentTo(8443))
		})

		It("should create a NetworkPolicy", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())

			np := &networkingv1.NetworkPolicy{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, np)).To(Succeed())
			Expect(np.Spec.Ingress).To(HaveLen(1))
			Expect(np.Spec.Ingress[0].Ports).To(HaveLen(1))
			Expect(*np.Spec.Ingress[0].Ports[0].Protocol).To(Equal(corev1.ProtocolUDP))
		})

		It("should create a HorizontalPodAutoscaler", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())

			hpa := &autoscalingv2.HorizontalPodAutoscaler{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, hpa)).To(Succeed())
			Expect(hpa.Spec.MinReplicas).To(PointTo(BeEquivalentTo(2)))
			Expect(hpa.Spec.MaxReplicas).To(BeEquivalentTo(16))
			Expect(hpa.Spec.ScaleTargetRef.Kind).To(Equal("Deployment"))
			Expect(hpa.Spec.ScaleTargetRef.Name).To(Equal("udp-mux"))
			Expect(hpa.Spec.Metrics).To(HaveLen(1))
			Expect(hpa.Spec.Metrics[0].Resource.Name).To(Equal(corev1.ResourceCPU))
			Expect(hpa.Spec.Metrics[0].Resource.Target.Type).To(Equal(autoscalingv2.UtilizationMetricType))
			Expect(hpa.Spec.Metrics[0].Resource.Target.AverageUtilization).To(PointTo(BeEquivalentTo(75)))
			Expect(hpa.Spec.Behavior.ScaleUp.StabilizationWindowSeconds).To(PointTo(BeEquivalentTo(60)))
			Expect(hpa.Spec.Behavior.ScaleUp.Policies).To(HaveLen(1))
			Expect(hpa.Spec.Behavior.ScaleUp.Policies[0].PeriodSeconds).To(BeEquivalentTo(60))
			Expect(hpa.Spec.Behavior.ScaleDown.StabilizationWindowSeconds).To(PointTo(BeEquivalentTo(300)))
			Expect(hpa.Spec.Behavior.ScaleDown.Policies).To(HaveLen(1))
			Expect(hpa.Spec.Behavior.ScaleDown.Policies[0].PeriodSeconds).To(BeEquivalentTo(300))
		})

		It("should create a VerticalPodAutoscaler", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())

			vpa := &vpaautoscalingv1.VerticalPodAutoscaler{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux-vpa", Namespace: values.Namespace}, vpa)).To(Succeed())
			Expect(vpa.Spec.TargetRef.Kind).To(Equal("Deployment"))
			Expect(vpa.Spec.TargetRef.Name).To(Equal("udp-mux"))
			Expect(vpa.Spec.UpdatePolicy.UpdateMode).To(PointTo(Equal(vpaautoscalingv1.UpdateModeRecreate)))
			Expect(vpa.Spec.ResourcePolicy.ContainerPolicies).To(HaveLen(1))
			Expect(vpa.Spec.ResourcePolicy.ContainerPolicies[0].ContainerName).To(Equal("udp-mux"))
			Expect(vpa.Spec.ResourcePolicy.ContainerPolicies[0].MinAllowed).To(Equal(corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("100Mi"),
			}))
			Expect(vpa.Spec.ResourcePolicy.ContainerPolicies[0].ControlledValues).To(PointTo(Equal(vpaautoscalingv1.ContainerControlledValuesRequestsOnly)))
		})
	})

	Describe("#Destroy", func() {
		It("should succeed even when resources do not exist", func() {
			Expect(comp.Destroy(ctx)).To(Succeed())
		})

		It("should delete created resources", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())
			Expect(comp.Destroy(ctx)).To(Succeed())

			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, &appsv1.Deployment{})).To(MatchError(ContainSubstring("not found")))
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, &autoscalingv2.HorizontalPodAutoscaler{})).To(MatchError(ContainSubstring("not found")))
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux-vpa", Namespace: values.Namespace}, &vpaautoscalingv1.VerticalPodAutoscaler{})).To(MatchError(ContainSubstring("not found")))
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, &corev1.Service{})).To(MatchError(ContainSubstring("not found")))
			Expect(c.Get(ctx, types.NamespacedName{Name: "udp-mux", Namespace: values.Namespace}, &networkingv1.NetworkPolicy{})).To(MatchError(ContainSubstring("not found")))
		})
	})

	Describe("#Wait", func() {
		It("should return nil", func() {
			Expect(comp.Wait(ctx)).To(Succeed())
		})
	})

	Describe("#WaitCleanup", func() {
		It("should return nil", func() {
			Expect(comp.WaitCleanup(ctx)).To(Succeed())
		})
	})

	Describe("#GetLoadBalancerAddress", func() {
		It("should return empty string when service has no LB ingress", func() {
			Expect(comp.Deploy(ctx)).To(Succeed())
			addr, err := comp.GetLoadBalancerAddress(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(addr).To(BeEmpty())
		})
	})
})

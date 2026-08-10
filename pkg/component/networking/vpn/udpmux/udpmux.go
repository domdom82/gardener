// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package udpmux

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/component"
	vpnseedserver "github.com/gardener/gardener/pkg/component/networking/vpn/seedserver"
	"github.com/gardener/gardener/pkg/controllerutils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
)

const (
	deploymentName = "udp-mux"
	serviceName    = "udp-mux"

	containerName                   = "udp-mux"
	udpPortName                     = "udp-mux"
	apiPortName                     = "udp-mux-api"
	udpPort                   int32 = 8443
	apiPort                   int32 = 8081
	protocolVersion                 = "v1"
	baseCPURequest                  = "100m"
	baseMemoryRequest               = "100Mi"
	hpaMinReplicas                  = 2
	hpaMaxReplicas                  = 16
	hpaAvgCPUUtilization            = 75
	hpaScaleUpPeriodSeconds         = 60
	hpaScaleDownPeriodSeconds       = 300
)

// Interface contains functions for a udp-mux deployer.
type Interface interface {
	component.DeployWaiter

	// GetLoadBalancerAddress returns the hostname or IP of the LoadBalancer Service.
	GetLoadBalancerAddress(ctx context.Context) (string, error)
}

// Values is a set of configuration values for the udp-mux component.
type Values struct {
	// Image is the container image for the udp-mux binary.
	Image string
	// Namespace is the namespace in which the component is deployed (typically "vpn-ingress").
	Namespace string
	// Replicas is the number of deployment replicas.
	Replicas int32
	// LoadBalancerAnnotations are annotations applied to the LoadBalancer Service.
	LoadBalancerAnnotations map[string]string
	// LoadBalancerClass is the loadBalancerClass field of the Service, if any.
	LoadBalancerClass *string
	// ExternalTrafficPolicy is the externalTrafficPolicy field of the Service.
	ExternalTrafficPolicy *corev1.ServiceExternalTrafficPolicy
}

// New creates a new instance of the udp-mux deployer.
func New(c client.Client, values Values) Interface {
	return &udpMux{client: c, values: values}
}

type udpMux struct {
	client client.Client
	values Values
}

func (u *udpMux) Deploy(ctx context.Context) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: u.values.Namespace}}
	if _, err := controllerutils.CreateOrGetAndMergePatch(ctx, u.client, ns, func() error {
		metav1.SetMetaDataLabel(&ns.ObjectMeta, v1beta1constants.GardenRole, v1beta1constants.GardenRoleVPNIngress)
		return nil
	}); err != nil {
		return err
	}

	if err := u.deployDeployment(ctx); err != nil {
		return err
	}
	if err := u.deployHPA(ctx); err != nil {
		return err
	}
	if err := u.deployVPA(ctx); err != nil {
		return err
	}
	if err := u.deployService(ctx); err != nil {
		return err
	}
	return u.deployNetworkPolicy(ctx)
}

func (u *udpMux) deployDeployment(ctx context.Context) error {
	deployment := u.emptyDeployment()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, u.client, deployment, func() error {
		maxSurge := intstr.FromInt32(1)
		maxUnavailable := intstr.FromInt32(0)
		replicas := u.values.Replicas
		historyLimit := int32(2)
		allowPrivilegeEscalation := false
		privileged := false
		readOnlyRootFilesystem := true

		deployment.Labels = getLabels()
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas:             &replicas,
			RevisionHistoryLimit: &historyLimit,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{v1beta1constants.LabelApp: deploymentName},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       &maxSurge,
					MaxUnavailable: &maxUnavailable,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: u.podTemplateLabels(),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            containerName,
							Image:           u.values.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"--protocol", protocolVersion,
								"--listenAddr", fmt.Sprintf(":%d", udpPort),
								"--apiListenAddr", fmt.Sprintf(":%d", apiPort),
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          udpPortName,
									ContainerPort: udpPort,
									Protocol:      corev1.ProtocolUDP,
								},
								{
									Name:          apiPortName,
									ContainerPort: apiPort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/healthz",
										Port:   intstr.FromInt32(apiPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								InitialDelaySeconds: 1,
								PeriodSeconds:       2,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/readyz",
										Port:   intstr.FromInt32(apiPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								InitialDelaySeconds: 1,
								PeriodSeconds:       2,
							},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								Privileged:               &privileged,
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(baseCPURequest),
									corev1.ResourceMemory: resource.MustParse(baseMemoryRequest),
								},
							},
						},
					},
				},
			},
		}
		return nil
	})
	return err
}

func (u *udpMux) deployHPA(ctx context.Context) error {
	hpa := u.emptyHPA()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, u.client, hpa, func() error {
		minReplicas := int32(hpaMinReplicas)
		maxReplicas := int32(hpaMaxReplicas)
		avgUtilization := int32(hpaAvgCPUUtilization)
		hpa.Labels = getLabels()
		hpa.Spec = autoscalingv2.HorizontalPodAutoscalerSpec{
			MinReplicas: &minReplicas,
			MaxReplicas: maxReplicas,
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "Deployment",
				Name:       deploymentName,
			},
			Metrics: []autoscalingv2.MetricSpec{{
				Type: autoscalingv2.ResourceMetricSourceType,
				Resource: &autoscalingv2.ResourceMetricSource{
					Name: corev1.ResourceCPU,
					Target: autoscalingv2.MetricTarget{
						Type:               autoscalingv2.UtilizationMetricType,
						AverageUtilization: &avgUtilization,
					},
				},
			}},
			Behavior: &autoscalingv2.HorizontalPodAutoscalerBehavior{
				ScaleUp: &autoscalingv2.HPAScalingRules{
					StabilizationWindowSeconds: new(int32(hpaScaleUpPeriodSeconds)),
					Policies: []autoscalingv2.HPAScalingPolicy{{
						Type:          autoscalingv2.PodsScalingPolicy,
						Value:         1,
						PeriodSeconds: hpaScaleUpPeriodSeconds,
					}},
				},
				ScaleDown: &autoscalingv2.HPAScalingRules{
					StabilizationWindowSeconds: new(int32(hpaScaleDownPeriodSeconds)),
					Policies: []autoscalingv2.HPAScalingPolicy{{
						Type:          autoscalingv2.PodsScalingPolicy,
						Value:         1,
						PeriodSeconds: hpaScaleDownPeriodSeconds,
					}},
				},
			},
		}
		return nil
	})
	return err
}

func (u *udpMux) deployVPA(ctx context.Context) error {
	vpa := u.emptyVPA()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, u.client, vpa, func() error {
		updateMode := vpaautoscalingv1.UpdateModeRecreate
		controlledValues := vpaautoscalingv1.ContainerControlledValuesRequestsOnly
		vpa.Labels = getLabels()
		vpa.Spec = vpaautoscalingv1.VerticalPodAutoscalerSpec{
			TargetRef: &autoscalingv1.CrossVersionObjectReference{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "Deployment",
				Name:       deploymentName,
			},
			UpdatePolicy: &vpaautoscalingv1.PodUpdatePolicy{
				UpdateMode: &updateMode,
			},
			ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
				ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{{
					ContainerName: containerName,
					MinAllowed: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse(baseCPURequest),
						corev1.ResourceMemory: resource.MustParse(baseMemoryRequest),
					},
					ControlledValues: &controlledValues,
				}},
			},
		}
		return nil
	})
	return err
}

func (u *udpMux) deployService(ctx context.Context) error {
	svc := u.emptyService()
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, u.client, svc, func() error {
		svc.Labels = getLabels()
		for k, v := range u.values.LoadBalancerAnnotations {
			metav1.SetMetaDataAnnotation(&svc.ObjectMeta, k, v)
		}
		svc.Spec.Type = corev1.ServiceTypeLoadBalancer
		svc.Spec.LoadBalancerClass = u.values.LoadBalancerClass
		if u.values.ExternalTrafficPolicy != nil {
			svc.Spec.ExternalTrafficPolicy = *u.values.ExternalTrafficPolicy
		}
		svc.Spec.Selector = map[string]string{v1beta1constants.LabelApp: deploymentName}
		svc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       udpPortName,
				Port:       udpPort,
				TargetPort: intstr.FromInt32(udpPort),
				Protocol:   corev1.ProtocolUDP,
			},
		}
		return nil
	})
	return err
}

func (u *udpMux) deployNetworkPolicy(ctx context.Context) error {
	np := u.emptyNetworkPolicy()
	udpProto := corev1.ProtocolUDP
	udpPortIS := intstr.FromInt32(udpPort)
	_, err := controllerutils.GetAndCreateOrMergePatch(ctx, u.client, np, func() error {
		np.Labels = getLabels()
		np.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{v1beta1constants.LabelApp: deploymentName},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &udpProto, Port: &udpPortIS},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		}
		return nil
	})
	return err
}

func (u *udpMux) Destroy(ctx context.Context) error {
	return kubernetesutils.DeleteObjects(ctx, u.client,
		u.emptyNetworkPolicy(),
		u.emptyService(),
		u.emptyVPA(),
		u.emptyHPA(),
		u.emptyDeployment(),
	)
}

func (u *udpMux) Wait(_ context.Context) error        { return nil }
func (u *udpMux) WaitCleanup(_ context.Context) error { return nil }

func (u *udpMux) GetLoadBalancerAddress(ctx context.Context) (string, error) {
	svc := &corev1.Service{}
	if err := u.client.Get(ctx, client.ObjectKey{Name: serviceName, Namespace: u.values.Namespace}, svc); err != nil {
		return "", err
	}
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return "", nil
	}
	ingress := svc.Status.LoadBalancer.Ingress[0]
	if ingress.Hostname != "" {
		return ingress.Hostname, nil
	}
	return ingress.IP, nil
}

func (u *udpMux) emptyDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: u.values.Namespace}}
}

func (u *udpMux) emptyHPA() *autoscalingv2.HorizontalPodAutoscaler {
	return &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: u.values.Namespace}}
}

func (u *udpMux) emptyVPA() *vpaautoscalingv1.VerticalPodAutoscaler {
	return &vpaautoscalingv1.VerticalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: deploymentName + "-vpa", Namespace: u.values.Namespace}}
}

func (u *udpMux) emptyService() *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: u.values.Namespace}}
}

func (u *udpMux) emptyNetworkPolicy() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: u.values.Namespace}}
}

func getLabels() map[string]string {
	return map[string]string{
		v1beta1constants.GardenRole: v1beta1constants.GardenRoleVPNIngress,
		v1beta1constants.LabelApp:   deploymentName,
	}
}

func (u *udpMux) podTemplateLabels() map[string]string {
	labels := getLabels()
	alias := v1beta1constants.LabelNetworkPolicyShootNamespaceAlias
	// non-HA shoots
	labels[gardenerutils.NetworkPolicyLabelUDP(alias+"-"+vpnseedserver.ServiceName, vpnseedserver.OpenVPNPort)] = v1beta1constants.LabelNetworkPolicyAllowed
	// HA shoots (indexed seed servers)
	for i := range vpnseedserver.HighAvailabilityReplicaCount {
		svcName := fmt.Sprintf("%s-%s-%d", alias, vpnseedserver.ServiceName, i)
		labels[gardenerutils.NetworkPolicyLabelUDP(svcName, vpnseedserver.OpenVPNPort)] = v1beta1constants.LabelNetworkPolicyAllowed
	}
	return labels
}

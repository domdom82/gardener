// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package udpmux

import (
	"context"
	"fmt"
	"time"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/component"
	vpnseedserver "github.com/gardener/gardener/pkg/component/networking/vpn/seedserver"
	"github.com/gardener/gardener/pkg/component/observability/monitoring/prometheus/aggregate"
	monitoringutils "github.com/gardener/gardener/pkg/component/observability/monitoring/utils"
	"github.com/gardener/gardener/pkg/controllerutils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/managedresources"
)

const (
	deploymentName  = "udp-mux"
	serviceName     = "udp-mux"
	managedResource = "udp-mux"

	containerName                   = "udp-mux"
	udpPortName                     = "udp-mux"
	apiPortName                     = "udp-mux-api"
	udpPort                   int32 = 8443
	apiPort                   int32 = 8081
	baseCPURequest                  = "100m"
	baseMemoryRequest               = "100Mi"
	hpaMinReplicas                  = 2
	hpaMaxReplicas                  = 16
	hpaAvgCPUUtilization            = 75
	hpaScaleUpPeriodSeconds         = 60
	hpaScaleDownPeriodSeconds       = 300
)

// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResource to become healthy.
var TimeoutWaitForManagedResource = 2 * time.Minute

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

	data, err := u.computeResourcesData()
	if err != nil {
		return err
	}
	return managedresources.CreateForSeed(ctx, u.client, u.values.Namespace, managedResource, false, data)
}

func (u *udpMux) computeResourcesData() (map[string][]byte, error) {
	registry := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)

	maxSurge := intstr.FromInt32(1)
	maxUnavailable := intstr.FromInt32(0)
	replicas := u.values.Replicas
	historyLimit := int32(2)
	allowPrivilegeEscalation := false
	privileged := false
	readOnlyRootFilesystem := true

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: u.values.Namespace, Labels: getLabels()},
		Spec: appsv1.DeploymentSpec{
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
		},
	}

	minReplicas := int32(hpaMinReplicas)
	maxReplicas := int32(hpaMaxReplicas)
	avgUtilization := int32(hpaAvgCPUUtilization)
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: u.values.Namespace, Labels: getLabels()},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
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
		},
	}

	updateMode := vpaautoscalingv1.UpdateModeRecreate
	controlledValues := vpaautoscalingv1.ContainerControlledValuesRequestsOnly
	vpa := &vpaautoscalingv1.VerticalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: deploymentName + "-vpa", Namespace: u.values.Namespace, Labels: getLabels()},
		Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
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
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: u.values.Namespace,
			Labels:    getLabels(),
		},
	}
	metav1.SetMetaDataAnnotation(&svc.ObjectMeta, resourcesv1alpha1.NetworkingFromWorldToPorts, fmt.Sprintf(`[{"protocol":"UDP","port":%d}]`, udpPort))
	utilruntime.Must(gardenerutils.InjectNetworkPolicyNamespaceSelectors(svc, metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "garden"}}))
	utilruntime.Must(gardenerutils.InjectNetworkPolicyAnnotationsForSeedScrapeTargets(svc, networkingv1.NetworkPolicyPort{Port: new(intstr.FromInt32(apiPort)), Protocol: new(corev1.ProtocolTCP)}))
	for k, v := range u.values.LoadBalancerAnnotations {
		metav1.SetMetaDataAnnotation(&svc.ObjectMeta, k, v)
	}
	svc.Spec = corev1.ServiceSpec{
		Type:              corev1.ServiceTypeLoadBalancer,
		LoadBalancerClass: u.values.LoadBalancerClass,
		Selector:          map[string]string{v1beta1constants.LabelApp: deploymentName},
		Ports: []corev1.ServicePort{{
			Name:       udpPortName,
			Port:       udpPort,
			TargetPort: intstr.FromInt32(udpPort),
			Protocol:   corev1.ProtocolUDP,
		}},
	}
	if u.values.ExternalTrafficPolicy != nil {
		svc.Spec.ExternalTrafficPolicy = *u.values.ExternalTrafficPolicy
	}

	serviceMonitor := &monitoringv1.ServiceMonitor{
		ObjectMeta: monitoringutils.ConfigObjectMeta("udp-mux", u.values.Namespace, aggregate.Label),
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				v1beta1constants.LabelApp: deploymentName,
			}},
			Endpoints: []monitoringv1.Endpoint{{
				TargetPort: &intstr.IntOrString{IntVal: apiPort},
				Path:       "/metrics",
			}},
		},
	}

	return registry.AddAllAndSerialize(deployment, hpa, vpa, svc, serviceMonitor)
}

func (u *udpMux) Destroy(ctx context.Context) error {
	return managedresources.DeleteForSeed(ctx, u.client, u.values.Namespace, managedResource)
}

func (u *udpMux) Wait(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()
	return managedresources.WaitUntilHealthy(timeoutCtx, u.client, u.values.Namespace, managedResource)
}

func (u *udpMux) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()
	return managedresources.WaitUntilDeleted(timeoutCtx, u.client, u.values.Namespace, managedResource)
}

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
	// allow DNS traffic to shoot DNS service to resolve endpoints of the seed servers
	labels[v1beta1constants.LabelNetworkPolicyToDNS] = v1beta1constants.LabelNetworkPolicyAllowed
	return labels
}

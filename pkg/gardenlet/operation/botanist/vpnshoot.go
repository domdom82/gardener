// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/imagevector"
	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	vpnseedserver "github.com/gardener/gardener/pkg/component/networking/vpn/seedserver"
	vpnshoot "github.com/gardener/gardener/pkg/component/networking/vpn/shoot"
	vpnudpmux "github.com/gardener/gardener/pkg/component/networking/vpn/udpmux"
	imagevectorutils "github.com/gardener/gardener/pkg/utils/imagevector"
)

// DefaultVPNShoot returns a deployer for the VPNShoot
func (b *Botanist) DefaultVPNShoot(ctx context.Context) (vpnshoot.Interface, error) {
	if b.Shoot.IsWorkerless || b.Shoot.IsSelfHosted() {
		return nil, nil
	}

	image, err := imagevector.Containers().FindImage(imagevector.ContainerImageNameVpnClient, imagevectorutils.RuntimeVersion(b.ShootVersion()), imagevectorutils.TargetVersion(b.ShootVersion()))
	if err != nil {
		return nil, err
	}

	imageUdpProxy, err := imagevector.Containers().FindImage(imagevector.ContainerImageNameUdpProxy, imagevectorutils.RuntimeVersion(b.ShootVersion()), imagevectorutils.TargetVersion(b.ShootVersion()))
	if err != nil {
		return nil, err
	}

	var udpEndpoint string
	if b.Shoot.VPNUDPEnabled {
		udpMux := vpnudpmux.New(b.SeedClientSet.Client(), vpnudpmux.Values{
			Namespace: v1beta1constants.GardenRoleVPNIngress,
		})
		udpEndpoint, err = udpMux.GetLoadBalancerAddress(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get vpn-ingress LoadBalancer address: %w", err)
		}
	}

	return vpnshoot.New(
		b.SeedClientSet.Client(),
		b.Shoot.ControlPlaneNamespace,
		b.SecretsManager,
		vpnshoot.Values{
			Image:             image.String(),
			ImageUdpProxy:     imageUdpProxy.String(),
			VPAEnabled:        b.Shoot.WantsVerticalPodAutoscaler,
			VPAUpdateDisabled: b.Shoot.VPNVPAUpdateDisabled,
			ReversedVPN: vpnshoot.ReversedVPNValues{
				Header:      "outbound|1194||" + vpnseedserver.ServiceName + "." + b.Shoot.ControlPlaneNamespace + ".svc.cluster.local",
				Destination: vpnseedserver.ServiceName + "." + b.Shoot.ControlPlaneNamespace + ".svc.cluster.local" + ":1194",
				Endpoint:    b.outOfClusterAPIServerFQDN(),
				UDPEndpoint: udpEndpoint,
				IPFamilies:  b.Shoot.GetInfo().Spec.Networking.IPFamilies,
			},
			HighAvailabilityEnabled:              b.Shoot.VPNHighAvailabilityEnabled,
			HighAvailabilityNumberOfSeedServers:  b.Shoot.VPNHighAvailabilityNumberOfSeedServers,
			HighAvailabilityNumberOfShootClients: b.Shoot.VPNHighAvailabilityNumberOfShootClients,
			SeedPodNetwork:                       b.Seed.GetInfo().Spec.Networks.Pods,
			AutoMTU:                              b.Shoot.VPNAutoMTU,
			UDPEnabled:                           b.Shoot.VPNUDPEnabled,
		},
	), nil
}

// DeployVPNShoot deploys the vpn-shoot.
func (b *Botanist) DeployVPNShoot(ctx context.Context) error {
	b.Shoot.Components.SystemComponents.VPNShoot.SetPodNetworkCIDRs(b.Shoot.Networks.Pods)
	b.Shoot.Components.SystemComponents.VPNShoot.SetServiceNetworkCIDRs(b.Shoot.Networks.Services)
	b.Shoot.Components.SystemComponents.VPNShoot.SetNodeNetworkCIDRs(b.Shoot.Networks.Nodes)

	if err := b.Shoot.Components.SystemComponents.VPNShoot.Deploy(ctx); err != nil {
		return err
	}

	return b.Shoot.UpdateInfoStatus(ctx, b.GardenClient, true, false, func(shoot *gardencorev1beta1.Shoot) error {
		condition := v1beta1helper.GetOrInitConditionWithClock(b.Clock, shoot.Status.Constraints, gardencorev1beta1.ShootUsesUnifiedHTTPProxyPort)
		condition = v1beta1helper.UpdatedConditionWithClock(b.Clock, condition, gardencorev1beta1.ConditionTrue, "ShootUsesUnifiedHTTPProxyPort", fmt.Sprintf("Shoot uses http-proxy port %d for VPN", vpnseedserver.HTTPProxyGatewayPort))
		shoot.Status.Constraints = v1beta1helper.MergeConditions(shoot.Status.Constraints, condition)
		return nil
	})
}

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package udpmux

import (
	_ "embed"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/component/crddeployer"
)

var (
	//go:embed charts/udpmux/udpmux-crds/crd-endpoint.yaml
	crds string
)

// NewCRD can be used to deploy udpmux CRDs.
func NewCRD(
	client client.Client,
) (component.DeployWaiter, error) {
	return crddeployer.New(client, []string{crds}, false)
}

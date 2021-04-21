// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// podToWorld implements a Scenario.
type podToWorld struct {
	name string
}

func PodToWorld(name string) check.Scenario {
	return &podToWorld{
		name: name,
	}
}

func (s *podToWorld) Name() string {
	tn := "pod-to-world"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s-%s", tn, s.name)
}

func (s *podToWorld) Run(ctx context.Context, t *check.Test) {
	ghttp := check.NetworkEndpoint("google-http", "google.com", 80)
	ghttps := check.NetworkEndpoint("google-https", "google.com", 443)
	wwwghttp := check.NetworkEndpoint("www-google-http", "www.google.com", 80)

	// With https
	if client := t.Context().RandomClientPod(); client != nil {
		cmd := curl("https://" + ghttps.Address())

		a := t.NewAction(s, "https-to-google", client, ghttps)

		// TODO(timo): This is silly
		_, _, _ = a.ExecInPod(ctx, cmd)

		egressFlowRequirements := a.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
		})
		a.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
	}

	// With http
	if client := t.Context().RandomClientPod(); client != nil {
		cmd := curl("http://" + ghttp.Address())

		a := t.NewAction(s, "http-to-google", client, ghttp)

		_, _, _ = a.ExecInPod(ctx, cmd)

		egressFlowRequirements := a.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
		})
		a.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
	}

	// With http to www.google.com
	if client := t.Context().RandomClientPod(); client != nil {
		cmd := curl("http://" + wwwghttp.Address())

		a := t.NewAction(s, "http-to-www-google", client, wwwghttp)

		_, _, _ = a.ExecInPod(ctx, cmd)

		egressFlowRequirements := a.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
		})
		a.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
	}
}

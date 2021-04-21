// +build !linux
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
	"net"
	"strconv"

	"github.com/cilium/cilium-cli/connectivity/check"
)

type podToPod struct {
	name string
}

func (t *podToPod) Name() string {
	tn := "pod-to-pod"
	if t.name == "" {
		return tn
	}
	return fmt.Sprintf("%s-%s", tn, t.name)
}

func PodToPod(name string) check.Scenario {
	return &podToPod{
		name: name,
	}
}

func (t *podToPod) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		for _, echo := range c.EchoPods() {
			run := check.NewAction(t, c, client, echo, 8080)
			cmd := curlCommand(net.JoinHostPort(echo.Pod.Status.PodIP, strconv.Itoa(8080)))
			stdout, stderr, err := client.K8sClient.ExecInPodWithStderr(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
			run.LogResult(cmd, err, stdout, stderr)
			egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{})
			run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
			ingressFlowRequirements := run.GetIngressRequirements(check.FlowParameters{})
			if ingressFlowRequirements != nil {
				run.ValidateFlows(ctx, echo.Name(), echo.Pod.Status.PodIP, ingressFlowRequirements)
			}
			run.End()
		}
	}
}

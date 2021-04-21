// +build !linux
// Copyright 2020 Authors of Cilium
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

type podToService struct {
	name string
}

func PodToService(name string) check.Scenario {
	return &podToService{
		name: name,
	}
}

func (t *podToService) Name() string {
	tn := "pod-to-service"
	if t.name == "" {
		return tn
	}
	return fmt.Sprintf("%s-%s", tn, t.name)
}

func (t *podToService) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		serviceDestinations := serviceDefinitionMap{}
		for _, echoSvc := range c.EchoServices() {
			serviceDestinations[echoSvc.Service.Name] = serviceDefinition{
				port: 8080,
				name: "ClusterIP",
				dns:  true,
			}
		}

		testConnetivityToServiceDefinition(ctx, c, t, client, serviceDestinations)
	}

}

type podToNodePort struct {
	name string
}

func PodToNodePort(name string) check.Scenario {
	return &podToNodePort{
		name: name,
	}
}

func (t *podToNodePort) Name() string {
	tn := "pod-to-nodeport"
	if t.name == "" {
		return tn
	}
	return fmt.Sprintf("%s-%s", tn, t.name)
}

func (t *podToNodePort) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		serviceDestinations := serviceDefinitionMap{}
		for _, echoSvc := range c.EchoServices() {
			for _, echo := range c.EchoPods() {
				if echo.Pod.Status.HostIP != client.Pod.Status.HostIP {
					serviceDestinations[echo.Pod.Status.HostIP] = serviceDefinition{
						port: int(echoSvc.Service.Spec.Ports[0].NodePort),
						name: "NodePort",
					}
				}
			}
		}

		testConnetivityToServiceDefinition(ctx, c, t, client, serviceDestinations)
	}
}

type podToLocalNodePort struct {
	name string
}

func PodToLocalNodePort(name string) check.Scenario {
	return &podToLocalNodePort{
		name: name,
	}
}

func (t *podToLocalNodePort) Name() string {
	tn := "pod-to-local-nodeport"
	if t.name == "" {
		return tn
	}
	return fmt.Sprintf("%s-%s", tn, t.name)
}

func (t *podToLocalNodePort) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		serviceDestinations := serviceDefinitionMap{}
		for _, client := range c.ClientPods() {
			for _, echoSvc := range c.EchoServices() {
				for _, echo := range c.EchoPods() {
					if echo.Pod.Status.HostIP == client.Pod.Status.HostIP {
						serviceDestinations[echo.Pod.Status.HostIP] = serviceDefinition{
							port: int(echoSvc.Service.Spec.Ports[0].NodePort),
							name: "NodePort",
						}
					}
				}
			}
		}

		testConnetivityToServiceDefinition(ctx, c, t, client, serviceDestinations)
	}
}

type serviceDefinition struct {
	port int
	name string
	dns  bool
}

type serviceDefinitionMap map[string]serviceDefinition

func testConnetivityToServiceDefinition(ctx context.Context, c check.TestContext, t check.Scenario, client check.PodContext, def serviceDefinitionMap) {
	for peer, definition := range def {
		destination := net.JoinHostPort(peer, strconv.Itoa(definition.port))
		run := check.NewAction(t, c, client, check.NetworkEndpointContext{
			CustomName: destination + " (" + definition.name + ")",
			Peer:       destination,
		}, 8080)
		cmd := curlCommand(destination)
		stdout, stderr, err := client.K8sClient.ExecInPodWithStderr(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
		run.LogResult(cmd, err, stdout, stderr)
		egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
			DNSRequired: definition.dns,
			NodePort:    definition.port,
		})
		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
		run.End()
	}
}

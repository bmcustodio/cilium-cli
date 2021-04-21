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

package check

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	ClientDeploymentName  = "client"
	Client2DeploymentName = "client2"

	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
)

var serviceLabels = map[string]string{
	"kind": kindEchoName,
}

func newService(name string, selector map[string]string, labels map[string]string, portName string, port int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{Name: name, Port: int32(port)},
			},
			Selector: selector,
		},
	}
}

type deploymentParameters struct {
	Name           string
	Kind           string
	Image          string
	Replicas       int
	Port           int
	Command        []string
	Affinity       *corev1.Affinity
	ReadinessProbe *corev1.Probe
	Labels         map[string]string
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	replicas32 := int32(p.Replicas)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
			Labels: map[string]string{
				"name": p.Name,
				"kind": p.Kind,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: p.Name,
					Labels: map[string]string{
						"name": p.Name,
						"kind": p.Kind,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: p.Name,
							Env: []corev1.EnvVar{
								{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
							},
							Ports: []corev1.ContainerPort{
								{ContainerPort: int32(p.Port)},
							},
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							ReadinessProbe:  p.ReadinessProbe,
						},
					},
					Affinity: p.Affinity,
				},
			},
			Replicas: &replicas32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": p.Name,
					"kind": p.Kind,
				},
			},
		},
	}

	for k, v := range p.Labels {
		dep.Spec.Template.ObjectMeta.Labels[k] = v
	}

	return dep
}

func newLocalReadinessProbe(port int, path string) *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   path,
				Port:   intstr.FromInt(port),
				Scheme: corev1.URISchemeHTTP,
			},
		},
		TimeoutSeconds:      int32(2),
		SuccessThreshold:    int32(1),
		PeriodSeconds:       int32(1),
		InitialDelaySeconds: int32(1),
		FailureThreshold:    int32(3),
	}
}

// Pod is a Kubernetes Pod acting as a peer in a connectivity test.
type Pod struct {
	// Kubernetes client of the cluster this pod is running in.
	K8sClient *k8s.Client

	// Pod is the Kubernetes Pod resource.
	Pod *corev1.Pod
}

// Name returns the absolute name of the Pod.
func (p Pod) Name() string {
	return p.Pod.Namespace + "/" + p.Pod.Name
}

// Address returns the network address of the Pod.
func (p Pod) Address() string {
	return p.Pod.Status.PodIP
}

// HasLabel checks if given label exists and value matches.
func (p Pod) HasLabel(name, value string) bool {
	v, ok := p.Pod.Labels[name]
	return ok && v == value
}

// Service is a service acting as a peer in a connectivity test.
type Service struct {
	// Service  is the Kubernetes service resource
	Service *corev1.Service
}

// Name returns the absolute name of the service.
func (s Service) Name() string {
	return s.Service.Namespace + "/" + s.Service.Name
}

// Address returns the network address of the service.
func (s Service) Address() string {
	return s.Service.Name
}

// HasLabel checks if given label exists and value matches.
func (s Service) HasLabel(name, value string) bool {
	v, ok := s.Service.Labels[name]
	return ok && v == value
}

// NetworkEndpoint returns a new network endpoint.
func NetworkEndpoint(name, hostname string, port uint32) networkEndpoint {
	return networkEndpoint{
		name:     name,
		hostname: hostname,
		port:     port,
	}
}

// NetworkEndpoint is a network endpoint acting as a peer in a connectivity test.
// It implements interface TestPeer.
type networkEndpoint struct {
	// Name of the endpoint.
	name string

	// Address of the endpoint.
	hostname string

	// Port number of the endpoint.
	port uint32
}

// Name is the absolute name of the network endpoint.
func (n networkEndpoint) Name() string {
	if n.name != "" {
		return n.name
	}

	return n.hostname
}

// Address it the network address of the network endpoint.
func (n networkEndpoint) Address() string {
	return n.hostname
}

func (n networkEndpoint) Port() uint32 {
	return n.port
}

// HasLabel checks if given label exists and value matches.
func (n networkEndpoint) HasLabel(name, value string) bool {
	return false
}

type MatchMap map[int]bool

type FlowRequirementResults struct {
	FirstMatch         int
	LastMatch          int
	Matched            MatchMap
	Log                []string
	Failures           int
	NeedMoreFlows      bool
	LastMatchTimestamp time.Time
}

// L4Protocol identifies the network protocol being tested
type L4Protocol int

const (
	TCP L4Protocol = iota
	UDP
	ICMP
)

// FlowParameters defines parameters for test result flow matching
type FlowParameters struct {
	// Protocol is the network protocol being tested
	Protocol L4Protocol

	// DNSRequired is true if DNS flows must be seen before the test protocol
	DNSRequired bool

	// RSTAllowed is true if TCP connection may end with either RST or FIN
	RSTAllowed bool

	// NodePort, if non-zero, indicates an alternative port number for the DstPort to be matched
	NodePort uint32
}

// TestPeer is the abstraction used for all peer types (pods, services, IPs,
// DNS names) used for connectivity testing
type TestPeer interface {
	// Name must return the absolute name of the peer.
	Name() string

	// Address must return the network address of the peer. This can be a
	// DNS name or an IP address.
	Address() string

	// Port must return the destination port number used by the test traffic to the peer.
	Port() uint32

	// HasLabel checks if given label with the given name and value exists.
	HasLabel(name, value string) bool
}

type TestResult struct {
	Name     string
	Failures int
	Warnings int
}

func (t TestResult) String() string {
	switch {
	case t.Failures > 0:
		return "❌ " + t.Name
	case t.Warnings > 0:
		return "⚠️  " + t.Name
	default:
		return "✅ " + t.Name
	}
}

type TestResults map[string]TestResult

func (t TestResults) Warnings() (warnings int) {
	for _, result := range t {
		if result.Warnings > 0 {
			warnings++
		}
	}
	return
}

func (t TestResults) Failed() (failed int) {
	for _, result := range t {
		if result.Failures > 0 {
			failed++
		}
	}
	return
}

type flowsSet []*observer.GetFlowsResponse

func (f flowsSet) Contains(filter filters.FlowFilterImplementation) (int, bool, *flow.Flow) {
	if f == nil {
		return 0, false, nil
	}

	for i, res := range f {
		flow := res.GetFlow()
		if filter.Match(flow) {
			return i, true, flow
		}
	}

	return 0, false, nil
}

const (
	FlowValidationModeDisabled = "disabled"
	FlowValidationModeWarning  = "warning"
	FlowValidationModeStrict   = "strict"
)

type Parameters struct {
	CiliumNamespace       string
	TestNamespace         string
	SingleNode            bool
	PrintFlows            bool
	ForceDeploy           bool
	Hubble                bool
	HubbleServer          string
	MultiCluster          string
	Tests                 []string
	PostTestSleepDuration time.Duration
	FlowValidation        string
	AllFlows              bool
	Writer                io.Writer
	Verbose               bool
}

func (p Parameters) ciliumEndpointTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) podReadyTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) serviceReadyTimeout() time.Duration {
	return 5 * time.Minute
}

func (p Parameters) validate() error {
	switch p.FlowValidation {
	case FlowValidationModeDisabled, FlowValidationModeWarning, FlowValidationModeStrict:
	default:
		return fmt.Errorf("invalid flow validation mode %q", p.FlowValidation)
	}

	return nil
}

func (p Parameters) testEnabled(test string) bool {
	if len(p.Tests) == 0 {
		return true
	}

	numAllow := 0
	numDeny := 0

	for _, p := range p.Tests {
		result := true
		if p[0] == '!' {
			numDeny++
			p = p[1:]
			result = false
		} else {
			numAllow++
		}

		if strings.HasPrefix(test, p) {
			return result
		}
	}

	if numDeny == 0 {
		return false
	}

	if numAllow > 0 {
		return false
	}

	return true
}

type deploymentClients struct {
	dstInOtherCluster bool
	src               *k8s.Client
	dst               *k8s.Client
}

func (d *deploymentClients) clients() []*k8s.Client {
	if d.dstInOtherCluster {
		return []*k8s.Client{d.src, d.dst}
	}
	return []*k8s.Client{d.src}
}

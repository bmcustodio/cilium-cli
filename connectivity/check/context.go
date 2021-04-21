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
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium/api/v1/observer"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	hubprinter "github.com/cilium/hubble/pkg/printer"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConnectivityTest is the root context of the connectivity test suite
// and holds all resources belonging to it. It implements interface
// ConnectivityTest and is instantiated once at the start of the program,
type ConnectivityTest struct {
	// Client connected to a Kubernetes cluster.
	client       *k8s.Client
	hubbleClient observer.ObserverClient

	verbose         bool
	flowAggregation bool

	// Parameters to the test suite, specified by the CLI user.
	params Parameters

	// Clients for source and destination clusters?
	// TODO(timo): not clear what exactly this is for; multi-cluster?
	clients *deploymentClients

	echoPods     map[string]Pod
	clientPods   map[string]Pod
	echoServices map[string]Service

	tests map[string]*Test

	lastFlowTimestamps map[string]time.Time

	results TestResults
}

func NewConnectivityTest(client *k8s.Client, p Parameters) (*ConnectivityTest, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	k := &ConnectivityTest{
		client:             client,
		params:             p,
		echoPods:           make(map[string]Pod),
		clientPods:         make(map[string]Pod),
		echoServices:       make(map[string]Service),
		tests:              make(map[string]*Test),
		lastFlowTimestamps: make(map[string]time.Time),
	}

	return k, nil
}

func (ct *ConnectivityTest) NewTest(name string) *Test {
	if name == "" {
		panic("empty test name")
	}

	if _, ok := ct.tests[name]; ok {
		ct.Fatal("test %s exists in suite", name)
	}

	t := &Test{
		ctx:       ct,
		name:      name,
		scenarios: make(map[Scenario][]*Action),
		cnps:      make(map[string]*ciliumv2.CiliumNetworkPolicy),
	}

	ct.tests[name] = t

	return t
}

// Run kicks off execution of all Tests registered to the ConnectivityTest.
func (ct *ConnectivityTest) Run(ctx context.Context) error {
	if err := ct.initClients(ctx); err != nil {
		return err
	}

	if err := ct.deploy(ctx); err != nil {
		return err
	}

	if err := ct.validateDeployment(ctx); err != nil {
		return err
	}

	if ct.params.Hubble {
		ct.Log("🔭 Enabling Hubble telescope...")
		if err := ct.enableHubbleClient(ctx); err != nil {
			return fmt.Errorf("unable to create hubble client: %s", err)
		}
	}

	ct.Debug("Registered connectivity tests:", ct.tests)

	// Execute all tests in the order they were registered by the test suite.
	for _, t := range ct.tests {
		ct.Debug("Running test", t.Name())

		// Mark tests as skipped when the user requested so.
		if !ct.params.testEnabled(t.Name()) {
			t.Skip()
			continue
		}

		if err := t.Run(ctx); err != nil {
			return fmt.Errorf("Running test %s: %w", t.Name(), err)
		}
	}

	ct.Header("📋 Test Report")
	failed := ct.results.Failed()
	warnings := ct.results.Warnings()

	if failed > 0 {
		ct.Logf("❌ %d/%d tests failed (%d warnings)", failed, len(ct.results), warnings)

		var testStatus []string
		for _, result := range ct.results {
			testStatus = append(testStatus, result.String())
		}
		ct.Log("")
		ct.Log("Failed tests: " + strings.Join(testStatus, ", "))

		return fmt.Errorf("%d tests failed", failed)
	}

	ct.Logf("✅ %d/%d tests successful (%d warnings)", len(ct.results), len(ct.results), warnings)

	return nil
}

func (ct *ConnectivityTest) enableHubbleClient(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := grpc.DialContext(dialCtx, ct.params.HubbleServer, grpc.WithInsecure())
	if err != nil {
		return err
	}

	ct.hubbleClient = observer.NewObserverClient(c)

	status, err := ct.hubbleClient.ServerStatus(ctx, &observer.ServerStatusRequest{})
	if err != nil {
		ct.Log("⚠️  Unable to contact Hubble Relay:", err)
		ct.Log("⚠️  Did you enable and expose Hubble + Relay?")
		ct.Log("ℹ️  You can export Relay with a port-forward: kubectl port-forward -n kube-system deployment/hubble-relay 4245:4245")
		ct.Log("ℹ️  Disabling Hubble telescope and flow validation...")
		ct.hubbleClient = nil
		ct.params.Hubble = false

		if ct.params.FlowValidation == FlowValidationModeStrict {
			ct.Log("❌ In --flow-validation=strict mode, Hubble must be available to validate flows")
			return fmt.Errorf("hubble is not available: %w", err)
		}
	} else {
		ct.Logf("ℹ️  Hubble is OK, flows: %d/%d", status.NumFlows, status.MaxFlows)
	}

	return nil
}

func (ct *ConnectivityTest) Print(pod string, f *flowsSet) {
	if f == nil {
		ct.Log("📄 No flows recorded for pod", pod)
		return
	}

	ct.Log("📄 Flow logs for pod", pod)
	printer := hubprinter.New(hubprinter.Compact(), hubprinter.WithIPTranslation())
	defer printer.Close()
	for _, flow := range *f {
		if err := printer.WriteProtoFlow(flow); err != nil {
			ct.Log("Unable to print flow", err)
		}
	}
}

func (k *ConnectivityTest) deleteDeployments(ctx context.Context, client *k8s.Client) error {
	k.Logf("🔥 [%s] Deleting connectivity check deployments...", client.ClusterName())
	_ = client.DeleteDeployment(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, k.params.TestNamespace, ClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, k.params.TestNamespace, Client2DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteNamespace(ctx, k.params.TestNamespace, metav1.DeleteOptions{})

	_, err := client.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
	if err == nil {
		k.Logf("⌛ [%s] Waiting for namespace %s to disappear", client.ClusterName(), k.params.TestNamespace)
		for err == nil {
			time.Sleep(time.Second)
			_, err = client.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
		}
	}

	return nil
}

// deploymentList returns 2 lists of Deployments to be used for running tests with.
func (k *ConnectivityTest) deploymentList() (srcList []string, dstList []string) {
	srcList = []string{ClientDeploymentName, Client2DeploymentName, echoSameNodeDeploymentName}

	if k.params.MultiCluster != "" || !k.params.SingleNode {
		dstList = append(dstList, echoOtherNodeDeploymentName)
	}

	return srcList, dstList
}

func (k *ConnectivityTest) logAggregationMode(ctx context.Context, client *k8s.Client) (string, error) {
	cm, err := client.GetConfigMap(ctx, k.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data == nil {
		return "", fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	return cm.Data[defaults.ConfigMapKeyMonitorAggregation], nil
}

// initClients checks if Cilium is installed on the cluster, whether the cluster
// has multiple nodes, and whether or not monitor aggregation is enabled.
// TODO: Split this up, it does too much.
func (k *ConnectivityTest) initClients(ctx context.Context) error {
	c := &deploymentClients{
		src: k.client,
		dst: k.client,
	}

	if a, _ := k.logAggregationMode(ctx, c.src); a != defaults.ConfigMapValueMonitorAggregatonNone {
		k.flowAggregation = true
	}

	// In single-cluster environment, automatically detect a single-node
	// environment so we can skip deploying tests which depend on multiple
	// nodes.
	if k.params.MultiCluster == "" && !k.params.SingleNode {
		daemonSet, err := k.client.GetDaemonSet(ctx, k.params.CiliumNamespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
		if err != nil {
			k.Log("❌ Unable to determine status of Cilium DaemonSet. Run \"cilium status\" for more details")
			return fmt.Errorf("unable to determine status of Cilium DaemonSet: %w", err)
		}

		isSingleNode := false
		if daemonSet.Status.DesiredNumberScheduled == 1 {
			isSingleNode = true
		} else {
			nodes, err := k.client.ListNodes(ctx, metav1.ListOptions{})
			if err != nil {
				k.Log("❌ Unable to list nodes.")
				return fmt.Errorf("unable to list nodes: %w", err)
			}

			numWorkerNodes := len(nodes.Items)
			for _, n := range nodes.Items {
				for _, t := range n.Spec.Taints {
					// cannot schedule connectivity test pods on
					// master node.
					if t.Key == "node-role.kubernetes.io/master" {
						numWorkerNodes--
					}
				}
			}

			isSingleNode = numWorkerNodes == 1
		}

		if isSingleNode {
			k.Log("ℹ️  Single node environment detected, enabling single node connectivity test")
			k.params.SingleNode = true
		}
	} else {
		dst, err := k8s.NewClient(k.params.MultiCluster, "")
		if err != nil {
			return fmt.Errorf("unable to create Kubernetes client for remote cluster %q: %w", k.params.MultiCluster, err)
		}

		c.dst = dst
		c.dstInOtherCluster = true

		if a, _ := k.logAggregationMode(ctx, c.dst); a != defaults.ConfigMapValueMonitorAggregatonNone {
			k.flowAggregation = true
		}
	}

	if k.flowAggregation {
		k.Log("ℹ️  Monitor aggregation detected, will skip some flow validation steps")
	}

	k.clients = c

	return nil
}

// deploy ensures the test Namespace, Services and Deployments are running on the cluster.
func (k *ConnectivityTest) deploy(ctx context.Context) error {
	if k.params.ForceDeploy {
		if err := k.deleteDeployments(ctx, k.clients.src); err != nil {
			return err
		}
	}

	_, err := k.clients.src.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
	if err != nil {
		k.Logf("✨ [%s] Creating namespace for connectivity check...", k.clients.src.ClusterName())
		_, err = k.clients.src.CreateNamespace(ctx, k.params.TestNamespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create namespace %s: %s", k.params.TestNamespace, err)
		}
	}

	if k.params.MultiCluster != "" {
		if k.params.ForceDeploy {
			if err := k.deleteDeployments(ctx, k.clients.dst); err != nil {
				return err
			}
		}

		_, err = k.clients.dst.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
		if err != nil {
			k.Logf("✨ [%s] Creating namespace for connectivity check...", k.clients.dst.ClusterName())
			_, err = k.clients.dst.CreateNamespace(ctx, k.params.TestNamespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %s", k.params.TestNamespace, err)
			}
		}
	}

	_, err = k.clients.src.GetService(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Logf("✨ [%s] Deploying echo-same-node service...", k.clients.src.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, serviceLabels, "http", 8080)
		_, err = k.clients.src.CreateService(ctx, k.params.TestNamespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	if k.params.MultiCluster != "" {
		_, err = k.clients.src.GetService(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			k.Logf("✨ [%s] Deploying echo-other-node service...", k.clients.src.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)
			svc.ObjectMeta.Annotations = map[string]string{}
			svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"

			_, err = k.clients.src.CreateService(ctx, k.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}

	_, err = k.clients.src.GetDeployment(ctx, k.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Logf("✨ [%s] Deploying same-node deployment...", k.clients.src.ClusterName())
		echoDeployment := newDeployment(deploymentParameters{
			Name:   echoSameNodeDeploymentName,
			Kind:   kindEchoName,
			Port:   8080,
			Image:  "quay.io/cilium/json-mock:1.2",
			Labels: map[string]string{"other": "echo"},
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
			ReadinessProbe: newLocalReadinessProbe(8080, "/"),
		})

		_, err = k.clients.src.CreateDeployment(ctx, k.params.TestNamespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoSameNodeDeploymentName, err)
		}
	}

	_, err = k.clients.src.GetDeployment(ctx, k.params.TestNamespace, ClientDeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Logf("✨ [%s] Deploying client deployment...", k.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    ClientDeploymentName,
			Kind:    kindClientName,
			Port:    8080,
			Image:   "quay.io/cilium/alpine-curl:1.1",
			Command: []string{"/bin/ash", "-c", "sleep 10000000"},
		})
		_, err = k.clients.src.CreateDeployment(ctx, k.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", ClientDeploymentName, err)
		}
	}

	// 2nd client with label other=client
	_, err = k.clients.src.GetDeployment(ctx, k.params.TestNamespace, Client2DeploymentName, metav1.GetOptions{})
	if err != nil {
		k.Logf("✨ [%s] Deploying client2 deployment...", k.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    Client2DeploymentName,
			Kind:    kindClientName,
			Port:    8080,
			Image:   "quay.io/cilium/alpine-curl:1.1",
			Command: []string{"/bin/ash", "-c", "sleep 10000000"},
			Labels:  map[string]string{"other": "client"},
		})
		_, err = k.clients.src.CreateDeployment(ctx, k.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", Client2DeploymentName, err)
		}
	}

	if !k.params.SingleNode || k.params.MultiCluster != "" {
		_, err = k.clients.dst.GetService(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			k.Logf("✨ [%s] Deploying echo-other-node service...", k.clients.dst.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)

			if k.params.MultiCluster != "" {
				svc.ObjectMeta.Annotations = map[string]string{}
				svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"
			}

			_, err = k.clients.dst.CreateService(ctx, k.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}

		_, err = k.clients.dst.GetDeployment(ctx, k.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			k.Logf("✨ [%s] Deploying other-node deployment...", k.clients.dst.ClusterName())
			echoOtherNodeDeployment := newDeployment(deploymentParameters{
				Name:  echoOtherNodeDeploymentName,
				Kind:  kindEchoName,
				Port:  8080,
				Image: "quay.io/cilium/json-mock:1.2",
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
									},
								},
								TopologyKey: "kubernetes.io/hostname",
							},
						},
					},
				},
				ReadinessProbe: newLocalReadinessProbe(8080, "/"),
			})

			_, err = k.clients.dst.CreateDeployment(ctx, k.params.TestNamespace, echoOtherNodeDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %s", echoOtherNodeDeploymentName, err)
			}
		}
	}

	return nil
}

func (k *ConnectivityTest) validateCiliumEndpoint(ctx context.Context, client *k8s.Client, namespace, name string) error {
	k.Logf("⌛ [%s] Waiting for CiliumEndpoint for pod %s to appear...", client.ClusterName(), namespace+"/"+name)
	for {
		_, err := client.GetCiliumEndpoint(ctx, k.params.TestNamespace, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return fmt.Errorf("aborted waiting for CiliumEndpoint for pod %s to appear: %w", name, ctx.Err())
		}
	}
}

func (k *ConnectivityTest) waitForDeploymentsReady(ctx context.Context, client *k8s.Client, deployments []string) error {
	k.Logf("⌛ [%s] Waiting for deployments %s to become ready...", client.ClusterName(), deployments)

	ctx, cancel := context.WithTimeout(ctx, k.params.podReadyTimeout())
	defer cancel()
	for _, name := range deployments {
		for client.DeploymentIsReady(ctx, k.params.TestNamespace, name) != nil {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return fmt.Errorf("waiting for deployment %s to become ready has been interrupted: %w", name, ctx.Err())
			}
		}
	}

	return nil
}

func (k *ConnectivityTest) RandomClientPod() *Pod {
	for _, p := range k.clientPods {
		return &p
	}
	return nil
}

func (k *ConnectivityTest) waitForService(ctx context.Context, client *k8s.Client, service string) error {
	k.Logf("⌛ [%s] Waiting for service %s to become ready...", client.ClusterName(), service)

	ctx, cancel := context.WithTimeout(ctx, k.params.serviceReadyTimeout())
	defer cancel()

	clientPod := k.RandomClientPod()
	if clientPod == nil {
		return fmt.Errorf("no client pod available")
	}

retry:
	if _, _, err := client.ExecInPodWithStderr(ctx, clientPod.Pod.Namespace, clientPod.Pod.Name, clientPod.Pod.Labels["name"], []string{"nslookup", service}); err != nil {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return fmt.Errorf("waiting for service %s timed out, last error: %s", service, err)
		}
		goto retry
	}

	return nil
}

// validateDeployment checks if the Deployments we created have the expected Pods in them.
func (k *ConnectivityTest) validateDeployment(ctx context.Context) error {

	k.Debug("Validating Deployments...")

	srcDeployments, dstDeployments := k.deploymentList()
	if err := k.waitForDeploymentsReady(ctx, k.clients.src, srcDeployments); err != nil {
		return err
	}
	if err := k.waitForDeploymentsReady(ctx, k.clients.dst, dstDeployments); err != nil {
		return err
	}

	clientPods, err := k.client.ListPods(ctx, k.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	k.clientPods = map[string]Pod{}
	for _, pod := range clientPods.Items {
		ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
		defer cancel()
		if err := k.validateCiliumEndpoint(ctx, k.clients.src, k.params.TestNamespace, pod.Name); err != nil {
			return err
		}

		k.clientPods[pod.Name] = Pod{
			K8sClient: k.client,
			Pod:       pod.DeepCopy(),
		}
	}

	k.echoPods = map[string]Pod{}
	for _, client := range k.clients.clients() {
		echoPods, err := client.ListPods(ctx, k.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %s", err)
		}
		for _, echoPod := range echoPods.Items {
			ctx, cancel := context.WithTimeout(ctx, k.params.ciliumEndpointTimeout())
			defer cancel()
			if err := k.validateCiliumEndpoint(ctx, client, k.params.TestNamespace, echoPod.Name); err != nil {
				return err
			}

			k.echoPods[echoPod.Name] = Pod{
				K8sClient: client,
				Pod:       echoPod.DeepCopy(),
			}
		}
	}

	k.echoServices = map[string]Service{}
	for _, client := range k.clients.clients() {
		echoServices, err := client.ListServices(ctx, k.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo services: %s", err)
		}

		for _, echoService := range echoServices.Items {
			k.echoServices[echoService.Name] = Service{
				Service: echoService.DeepCopy(),
			}
		}
	}

	for serviceName := range k.echoServices {
		if err := k.waitForService(ctx, k.client, serviceName); err != nil {
			return err
		}
	}

	return nil
}

func (ct *ConnectivityTest) Log(a ...interface{}) {
	fmt.Fprintln(ct.params.Writer, a...)
}

func (ct *ConnectivityTest) Logf(format string, a ...interface{}) {
	fmt.Fprintf(ct.params.Writer, format+"\n", a...)
}

// Info logs an informational message.
func (ct *ConnectivityTest) Info(a ...interface{}) {
	ct.Log("ℹ️ ", a)
}

// Infof logs a formatted informational message.
func (ct *ConnectivityTest) Infof(format string, a ...interface{}) {
	ct.Logf("ℹ️  "+format, a...)
}

// Debug logs a debug message.
func (ct *ConnectivityTest) Debug(a ...interface{}) {
	if ct.verbose {
		ct.Log("🐛", a)
	}
}

// Debugf logs a formatted debug message.
func (ct *ConnectivityTest) Debugf(format string, a ...interface{}) {
	if ct.verbose {
		ct.Logf("🐛 "+format, a...)
	}
}

// Fatal logs an error and exits the calling goroutine.
func (ct *ConnectivityTest) Fatal(a ...interface{}) {
	ct.Log("🔥", a)
	runtime.Goexit()
}

// Fatalf logs a formatted error and exits the calling goroutine.
func (ct *ConnectivityTest) Fatalf(format string, a ...interface{}) {
	ct.Logf("🔥 "+format, a...)
	runtime.Goexit()
}

func (k *ConnectivityTest) StoreLastTimestamp(pod string, t time.Time) {
	k.lastFlowTimestamps[pod] = t
}

func (k *ConnectivityTest) LoadLastTimestamp(pod string) time.Time {
	return k.lastFlowTimestamps[pod]
}

func (k *ConnectivityTest) Header(format string, a ...interface{}) {
	k.Log("")
	k.Logf("  [%s]", fmt.Sprintf(format, a...))
}

func (k *ConnectivityTest) HubbleClient() observer.ObserverClient {
	return k.hubbleClient
}

func (k *ConnectivityTest) PrintFlows() bool {
	return k.params.PrintFlows
}

func (k *ConnectivityTest) AllFlows() bool {
	return k.params.AllFlows
}

func (k *ConnectivityTest) Verbose() bool {
	return k.verbose
}

func (k *ConnectivityTest) SetVerbose(verbose bool) {
	k.verbose = verbose
}

func (k *ConnectivityTest) ResetVerbose() {
	k.verbose = k.params.Verbose
}

func (k *ConnectivityTest) FlowAggregation() bool {
	return k.flowAggregation
}

func (k *ConnectivityTest) EchoPods() map[string]Pod {
	return k.echoPods
}

func (k *ConnectivityTest) ClientPods() map[string]Pod {
	return k.clientPods
}

func (k *ConnectivityTest) EchoServices() map[string]Service {
	return k.echoServices
}

func (k *ConnectivityTest) PostTestSleepDuration() time.Duration {
	return k.params.PostTestSleepDuration
}

func (k *ConnectivityTest) Report(r TestResult) {
	if k.results == nil {
		k.results = TestResults{}
	}

	if _, ok := k.results[r.Name]; ok {
		k.Log("❌ Overwriting results for test $q, failing the test", r.Name)
		r.Failures++
	}
	k.results[r.Name] = r
}

// deleteCNP deletes a CiliumNetworkPolicy from the cluster.
func (ct *ConnectivityTest) deleteCNP(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy) error {
	if err := ct.clients.src.DeleteCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("❌ [%s/%s] policy delete failed: %w", cnp.Namespace, cnp.Name, err)
	}

	return nil
}

// getCiliumPolicyRevision returns the current policy revision in a Cilium pod
func (ct *ConnectivityTest) getCiliumPolicyRevision(ctx context.Context, pod *corev1.Pod) (int, error) {
	stdout, err := ct.clients.src.ExecInPod(ctx, pod.Namespace, pod.Name,
		"cilium-agent", []string{"cilium", "policy", "get", "-o", "jsonpath='{.revision}'"})
	if err != nil {
		return 0, err
	}
	revision, err := strconv.Atoi(strings.Trim(stdout.String(), "'\n"))
	if err != nil {
		return 0, fmt.Errorf("revision '%s' is not valid: %w", stdout.String(), err)
	}
	return revision, nil
}

// getCiliumPolicyRevisions returns the current policy revisions of all Cilium pods
func (ct *ConnectivityTest) getCiliumPolicyRevisions(ctx context.Context) (map[*corev1.Pod]int, error) {
	revisions := make(map[*corev1.Pod]int)
	pods, err := ct.clients.src.ListPods(ctx, ct.params.CiliumNamespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return revisions, err
	}

	for i := range pods.Items {
		// Get the address of the pod we can use as a map key
		pod := &pods.Items[i]
		revision, err := ct.getCiliumPolicyRevision(ctx, pod)
		if err != nil {
			return revisions, err
		}
		revisions[pod] = revision
	}
	return revisions, nil
}

// waitCiliumPolicyRevision waits for a Cilium pod to reach a given policy revision.
func (ct *ConnectivityTest) waitCiliumPolicyRevision(ctx context.Context, pod *corev1.Pod, rev int, timeout time.Duration) error {
	timeoutStr := strconv.Itoa(int(timeout.Seconds()))
	_, err := ct.clients.src.ExecInPod(ctx, pod.Namespace, pod.Name,
		"cilium-agent", []string{"cilium", "policy", "wait", strconv.Itoa(rev), "--max-wait-time", timeoutStr})
	return err
}

// waitCiliumPolicyRevisions waits for the Cilium policy revisions to be bumped
// TODO: Improve error returns here, currently not possible for the caller to reliably detect timeout.
func (ct *ConnectivityTest) waitCiliumPolicyRevisions(ctx context.Context, revisions map[*corev1.Pod]int) error {
	var err error
	for pod, oldRevision := range revisions {
		err = ct.waitCiliumPolicyRevision(ctx, pod, oldRevision+1, defaults.PolicyWaitTimeout)
		if err == nil {
			if ct.Verbose() {
				ct.Debugf("Pod %s revision > %d", pod.Name, oldRevision)
			}
			delete(revisions, pod)
		}
	}
	if len(revisions) == 0 {
		return nil
	}
	return err
}

func (k *ConnectivityTest) updateOrCreateCNP(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy) (bool, error) {
	mod := false

	if kcnp, err := k.clients.src.GetCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.GetOptions{}); err == nil {
		// Check if the local CNP's Spec or Specs differ from the remote version.
		//TODO(timo): What about label changes? Do they trigger a Cilium agent policy revision?
		if !kcnp.Spec.DeepEqual(cnp.Spec) ||
			!kcnp.Specs.DeepEqual(&cnp.Specs) {
			mod = true
		}

		kcnp.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		kcnp.Spec = cnp.Spec
		kcnp.Specs = cnp.Specs
		kcnp.Status = ciliumv2.CiliumNetworkPolicyStatus{}

		_, err = k.clients.src.UpdateCiliumNetworkPolicy(ctx, kcnp, metav1.UpdateOptions{})
		return mod, err
	}

	// Creating, so a resource will definitely be modified.
	mod = true
	_, err := k.clients.src.CreateCiliumNetworkPolicy(ctx, cnp, metav1.CreateOptions{})
	return mod, err
}

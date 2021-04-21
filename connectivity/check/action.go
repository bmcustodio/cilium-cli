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
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium-cli/connectivity/filters"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	hubprinter "github.com/cilium/hubble/pkg/printer"
)

// Action represents an individual action (e.g. a curl call) in a Scenario
// between a source and a destination peer.
type Action struct {
	// name of the Action
	name string

	// the Test this Action is executed in
	test *Test

	// the Scenario this Action belongs to
	scenario Scenario

	// Src is the Pod used to execute the test from.
	Src *Pod

	// Dst is the peer used as the destination for the action.
	Dst TestPeer

	// expEgress is the expected test result for egress from the source pod
	expEgress Result

	// expIngress is the expected test result for the ingress in to the destination pod
	expIngress Result

	// flows is a map of all flow logs, indexed by pod name
	flows map[string]*flowsSet

	flowResults map[string]FlowRequirementResults

	// started is the timestamp the test started
	started time.Time

	// failures is the number of failures encountered in this test run
	failures int

	// warnings is the number of warnings encountered in this test run
	warnings int
}

func newAction(t *Test, name string, s Scenario, src *Pod, dst TestPeer) *Action {
	return &Action{
		name:        name,
		test:        t,
		scenario:    s,
		Src:         src,
		Dst:         dst,
		started:     time.Now(),
		flows:       map[string]*flowsSet{},
		flowResults: map[string]FlowRequirementResults{},
	}
}

// Short name of what the Action does.
func (a *Action) Name() string {
	return a.name
}

// FriendlyName returns the name of the peers and the destination port.
func (a *Action) FriendlyName() string {
	return fmt.Sprintf("%s -> %s:%d", a.Src.Name(), a.Dst.Name(), a.Dst.Port())
}

func (a *Action) ExecInPod(ctx context.Context, cmd []string) (bytes.Buffer, bytes.Buffer, error) {
	// Execute tests at the source.
	pod := a.Src

	o, e, err := pod.K8sClient.ExecInPodWithStderr(ctx,
		pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"], cmd)

	a.LogResult(cmd, o, e, err)

	return o, e, err
}

// Failure must be called when a failure is detected performing the test
func (a *Action) Failure(format string, s ...interface{}) {
	a.test.ctx.Logf("❌ "+format, s...)
	a.failures++
	a.test.ctx.SetVerbose(true)
}

// Success can be called to log a successful event
func (a *Action) Success(format string, s ...interface{}) {
	a.test.ctx.Logf("✅ "+format, s...)
}

// Waiting can be called to log a slow event
func (a *Action) Waiting(format string, s ...interface{}) {
	a.test.ctx.Logf("⌛ "+format+"...", s...)
}

// LogResult can be called to log command results
func (a *Action) LogResult(cmd []string, stdout, stderr bytes.Buffer, err error) {
	cmdName := cmd[0]
	cmdStr := strings.Join(cmd, " ")
	shouldSucceed := !a.expEgress.Drop && !a.expIngress.Drop
	if err != nil || stderr.Len() > 0 {
		if shouldSucceed {
			a.Failure("%s command %q failed: %s", cmdName, cmdStr, err)
		} else {
			a.Success("%s command %q failed as expected: %s", cmdName, cmdStr, err)
		}
	} else {
		if shouldSucceed {
			a.Success("%s command %q succeeded", cmdName, cmdStr)
		} else {
			a.Failure("%s command %q succeeded while it should have failed", cmdName, cmdStr)
		}
	}

	if a.test.Verbose() {
		if stderr.Len() > 0 {
			a.test.Infof("%s error: %s", cmdName, stderr.String())
		} else if stdout.Len() > 0 {
			a.test.Infof("%s output: %s", cmdName, stdout.String())
		}
	}
}

// Warning must be called when a warning is detected performing the Action.
func (a *Action) Warning(format string, s ...interface{}) {
	a.test.Logf("⚠️  "+format, s...)
	a.warnings++
}

func (a *Action) printFlows(pod string, f *flowsSet, r FlowRequirementResults) {
	if f == nil {
		a.test.Logf("📄 No flows recorded for pod %s", pod)
		return
	}

	a.test.Logf("📄 Flow logs of pod %s:", pod)
	printer := hubprinter.New(hubprinter.Compact(), hubprinter.WithIPTranslation())
	defer printer.Close()
	for index, flow := range *f {
		if !a.test.ctx.AllFlows() && r.FirstMatch > 0 && r.FirstMatch > index {
			continue
		}

		if !a.test.ctx.AllFlows() && r.LastMatch > 0 && r.LastMatch < index {
			continue
		}

		f := flow.GetFlow()

		src, dst := printer.GetHostNames(f)

		ts := "N/A"
		flowTimestamp, err := ptypes.Timestamp(f.GetTime())
		if err == nil {
			ts = flowTimestamp.Format(time.StampMilli)
		}

		flowPrefix := "❓"
		if expect, ok := r.Matched[index]; ok {
			if expect {
				flowPrefix = "✅"
			} else {
				flowPrefix = "❌"
			}
		}

		//nolint:staticcheck // Summary is deprecated but there is no real alternative yet
		a.test.Logf("%s%s: %s -> %s %s %s (%s)", flowPrefix, ts, src, dst, hubprinter.GetFlowType(f), f.Verdict.String(), f.Summary)
	}
}

func (a *Action) matchFlowRequirements(ctx context.Context, flows *flowsSet, pod string, req *filters.FlowSetRequirement) (r FlowRequirementResults) {
	var goodLog []string

	r.Matched = MatchMap{}

	match := func(expect bool, f filters.FlowRequirement) (int, bool, *flow.Flow) {
		index, match, flow := flows.Contains(f.Filter)

		if match {
			r.Matched[index] = expect
		}

		if match != expect {
			// Unless we show all flows, good flows are only shown on failure
			if !a.test.ctx.AllFlows() {
				r.Log = append(r.Log, goodLog...)
				goodLog = []string{}
			}

			msgSuffix := "not found"
			if !expect {
				msgSuffix = "found"
			}

			r.Log = append(r.Log, fmt.Sprintf("❌ %s %s %s for pod %s", f.Msg, f.Filter.String(), msgSuffix, pod))
			r.Failures++
		} else {
			msgSuffix := "found"
			if !expect {
				msgSuffix = "not found"
			}

			entry := "✅ " + fmt.Sprintf("%s %s for pod %s", f.Msg, msgSuffix, pod)
			// Either show all flows or collect them so we can attach on failure
			if a.test.ctx.AllFlows() {
				r.Log = append(r.Log, entry)
			} else {
				goodLog = append(goodLog, entry)
			}
		}

		return index, expect, flow
	}

	if index, match, _ := match(true, req.First); !match {
		r.NeedMoreFlows = true
	} else {
		r.FirstMatch = index
	}

	for _, f := range req.Middle {
		if f.SkipOnAggregation && a.test.ctx.FlowAggregation() {
			continue
		}
		match(true, f)
	}

	if !(req.Last.SkipOnAggregation && a.test.ctx.FlowAggregation()) {
		if index, match, lastFlow := match(true, req.Last); !match {
			r.NeedMoreFlows = true
		} else {
			r.LastMatch = index

			if lastFlow != nil {
				flowTimestamp, err := ptypes.Timestamp(lastFlow.Time)
				if err == nil {
					r.LastMatchTimestamp = flowTimestamp
				}
			}
		}
	}

	for _, f := range req.Except {
		match(false, f)
	}

	return
}

func (a *Action) GetEgressRequirements(p FlowParameters) *filters.FlowSetRequirement {
	var egress *filters.FlowSetRequirement
	srcIP := a.Src.Address()
	dstIP := a.Dst.Address()

	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipResponse := filters.IP(dstIP, srcIP)
	ipRequest := filters.IP(srcIP, dstIP)

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if a.expEgress.Drop {
			egress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			if a.expIngress.Drop {
				// If ingress drops is in the same node we get the drop flows also for egress, tolerate that
				egress = &filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last:  filters.FlowRequirement{Filter: filters.Or(filters.And(ipResponse, icmpResponse), filters.And(ipRequest, filters.Drop())), Msg: "ICMP response or request drop", SkipOnAggregation: true},
				}
			} else {
				egress = &filters.FlowSetRequirement{
					First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
					Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
					Except: []filters.FlowRequirement{
						{Filter: filters.Drop(), Msg: "Drop"},
					},
				}
			}
		}
	case TCP:
		tcpRequest := filters.TCP(0, a.Dst.Port())
		tcpResponse := filters.TCP(a.Dst.Port(), 0)
		if p.NodePort != 0 {
			tcpRequest = filters.Or(filters.TCP(0, p.NodePort), tcpRequest)
			tcpResponse = filters.Or(filters.TCP(p.NodePort, 0), tcpResponse)
		}

		if a.expEgress.Drop {
			egress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.SYNACK(), Msg: "SYN-ACK"},
					{Filter: filters.FIN(), Msg: "FIN"},
				},
			}
		} else {
			egress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Middle: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
				},
				// Either side may FIN first
				Last: filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				Except: []filters.FlowRequirement{
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
			if a.expEgress.HTTP.Status != "" || a.expEgress.HTTP.Method != "" || a.expEgress.HTTP.URL != "" {
				code, err := strconv.Atoi(a.expEgress.HTTP.Status)
				if err != nil {
					code = math.MaxUint32
				}
				egress.Middle = append(egress.Middle, filters.FlowRequirement{Filter: filters.HTTP(uint32(code), a.expEgress.HTTP.Method, a.expEgress.HTTP.URL), Msg: "HTTP"})
			}
			if p.RSTAllowed {
				// For the connection termination, we will either see:
				// a) FIN + FIN b) FIN + RST c) RST
				// Either side may RST or FIN first
				egress.Last = filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.Or(filters.FIN(), filters.RST())), Msg: "FIN or RST", SkipOnAggregation: true}
			} else {
				egress.Except = append(egress.Except, filters.FlowRequirement{Filter: filters.RST(), Msg: "RST"})
			}
		}
	case UDP:
		a.Failure("UDP egress flow matching not implemented yet")
	default:
		a.Failure("Invalid egress flow matching protocol %d", p.Protocol)
	}

	if p.DNSRequired || a.expEgress.DNSProxy {
		dnsRequest := filters.Or(filters.UDP(0, 53), filters.TCP(0, 53))
		dnsResponse := filters.Or(filters.UDP(53, 0), filters.TCP(53, 0))

		first := egress.First
		egress.First = filters.FlowRequirement{Filter: filters.And(ipRequest, dnsRequest), Msg: "DNS request"}
		egress.Middle = append([]filters.FlowRequirement{
			{Filter: filters.And(ipResponse, dnsResponse), Msg: "DNS response"},
			first,
		}, egress.Middle...)

		if a.expEgress.DNSProxy {
			egress.Middle = append([]filters.FlowRequirement{
				{Filter: filters.And(ipResponse, dnsResponse, filters.DNS(a.Dst.Address()+".", 0)), Msg: "DNS proxy"},
			}, egress.Middle...)
		}
	}

	return egress
}

func (a *Action) GetIngressRequirements(p FlowParameters) *filters.FlowSetRequirement {
	var ingress *filters.FlowSetRequirement
	if a.expIngress.None {
		return ingress
	}

	srcIP := a.Src.Address()
	dstIP := a.Dst.Address()
	if dstIP != "" && net.ParseIP(dstIP) == nil {
		// dstIP is not an IP address, assume it is a domain name
		dstIP = ""
	}

	ipResponse := filters.IP(dstIP, srcIP)
	ipRequest := filters.IP(srcIP, dstIP)

	tcpRequest := filters.TCP(0, a.Dst.Port())
	tcpResponse := filters.TCP(a.Dst.Port(), 0)
	if p.NodePort != 0 {
		tcpRequest = filters.Or(filters.TCP(0, p.NodePort), tcpRequest)
		tcpResponse = filters.Or(filters.TCP(p.NodePort, 0), tcpResponse)
	}

	switch p.Protocol {
	case ICMP:
		icmpRequest := filters.Or(filters.ICMP(8), filters.ICMPv6(128))
		icmpResponse := filters.Or(filters.ICMP(0), filters.ICMPv6(129))

		if a.expIngress.Drop {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest, filters.Drop()), Msg: "Drop"},
				Except: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response"},
				},
			}
		} else {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, icmpRequest), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(ipResponse, icmpResponse), Msg: "ICMP response", SkipOnAggregation: true},
				Except: []filters.FlowRequirement{
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
		}
	case TCP:
		if a.expIngress.Drop {
			// Ingress drops not supported yet
			a.Failure("Unimplemented expected TCP ingress result %s", a.expIngress.String())
		} else {
			ingress = &filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(ipRequest, tcpRequest, filters.SYN()), Msg: "SYN"},
				Middle: []filters.FlowRequirement{
					{Filter: filters.And(ipResponse, tcpResponse, filters.SYNACK()), Msg: "SYN-ACK"},
				},
				// Either side may FIN first
				Last: filters.FlowRequirement{Filter: filters.And(filters.Or(filters.And(ipRequest, tcpRequest), filters.And(ipResponse, tcpResponse)), filters.FIN()), Msg: "FIN"},
				Except: []filters.FlowRequirement{
					{Filter: filters.RST(), Msg: "RST"},
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			}
		}
	case UDP:
		a.Failure("UDP ingress flow matching not implemented yet")
	default:
		a.Failure("Invalid ingress flow matching protocol %d", p.Protocol)
	}

	return ingress
}

// ValidateFlows retrieves the flow pods of the specified pod and validates
// that all filters find a match. On failure, t.Failure() is called.
func (a *Action) ValidateFlows(ctx context.Context, pod, podIP string, req *filters.FlowSetRequirement) {
	hubbleClient := a.test.ctx.HubbleClient()
	if hubbleClient == nil {
		return
	}

	w := utils.NewWaitObserver(ctx, utils.WaitParameters{
		Timeout:       defaults.FlowWaitTimeout,
		RetryInterval: defaults.FlowRetryInterval,
		Log: func(err error, wait string) {
			a.test.Logf("⌛ Waiting (%s) for flows: %s", wait, err)
		}})
	defer w.Cancel()

retry:
	flows, err := a.getFlows(ctx, hubbleClient, a.started, pod, podIP)
	if err != nil || flows == nil || len(*flows) == 0 {
		if err == nil {
			err = fmt.Errorf("no flows returned")
		}
		if err := w.Retry(err); err != nil {
			a.Failure("Unable to retrieve flows of pod %q: %s", pod, err)
			return
		}
		goto retry
	}

	r := a.matchFlowRequirements(ctx, flows, pod, req)
	if r.NeedMoreFlows {
		// Retry until timeout. On timeout, print the flows and
		// consider it a failure
		if err := w.Retry(err); err != nil {
			goto retry
		}
	}

	a.flows[pod] = flows
	a.flowResults[pod] = r

	if !r.LastMatchTimestamp.IsZero() {
		a.test.ctx.StoreLastTimestamp(pod, r.LastMatchTimestamp)
	}

	if r.Failures == 0 {
		a.test.Logf("✅ Flow validation successful for pod %s (first: %d, last: %d, matched: %d, nlog: %d)", pod, r.FirstMatch, r.LastMatch, len(r.Matched), len(r.Log))
	} else {
		a.test.Logf("❌ Flow validation failed for pod %s: %d failures (first: %d, last: %d, matched: %d, nlog: %d)", pod, r.Failures, r.FirstMatch, r.LastMatch, len(r.Matched), len(r.Log))
	}

	for _, p := range r.Log {
		a.test.ctx.Log(p)
	}

	if r.Failures > 0 {
		a.failures++
	}
}

// end is called on each Action at the end of each Scenario.
func (a *Action) end() {
	if a.test.ctx.PrintFlows() || a.failures > 0 || a.warnings > 0 {
		for name, flows := range a.flows {
			a.printFlows(name, flows, a.flowResults[name])
		}
	}

	prefix := "✅"
	if a.failures > 0 {
		prefix = "❌"
	} else if a.warnings > 0 {
		prefix = "⚠️ "
	}

	a.test.Logf("%s [%s] %s (%s) -> %s (%s)",
		prefix, a.name,
		a.Src.Name(), a.Src.Address(),
		a.Dst.Name(), a.Dst.Address())

	if duration := a.test.ctx.PostTestSleepDuration(); duration != time.Duration(0) {
		time.Sleep(duration)
	}

	a.test.ctx.Report(TestResult{
		Name:     a.FriendlyName(),
		Failures: a.failures,
		Warnings: a.warnings,
	})
}

func (a *Action) getFlows(ctx context.Context, hubbleClient observer.ObserverClient, since time.Time, pod, podIP string) (*flowsSet, error) {
	var set flowsSet

	if hubbleClient == nil {
		return &set, nil
	}

	sinceTimestamp, err := ptypes.TimestampProto(since)
	if err != nil {
		return nil, fmt.Errorf("invalid since value %s: %s", since, err)
	}

	lastFlowTimestamp := a.test.ctx.LoadLastTimestamp(pod)
	if !lastFlowTimestamp.IsZero() && lastFlowTimestamp.After(since) {
		a.test.Logf("Using last flow timestamp: %s", lastFlowTimestamp)
		sinceTimestamp, err = ptypes.TimestampProto(lastFlowTimestamp)
		if err != nil {
			return nil, fmt.Errorf("invalid since value %s: %s", since, err)
		}
	}

	// The filter is liberal, it includes any flow that:
	// - source or destination IP matches pod IP
	// - source or destination pod name matches pod name
	filter := []*flow.FlowFilter{
		{SourceIp: []string{podIP}},
		{SourcePod: []string{pod}},
		{DestinationIp: []string{podIP}},
		{DestinationPod: []string{pod}},
	}

	request := &observer.GetFlowsRequest{
		Whitelist: filter,
		Since:     sinceTimestamp,
	}

	b, err := hubbleClient.GetFlows(ctx, request)
	if err != nil {
		return nil, err
	}

	for {
		res, err := b.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return &set, nil
		case nil:
		default:
			if status.Code(err) == codes.Canceled {
				return &set, nil
			}
			return nil, err
		}

		switch res.GetResponseTypes().(type) {
		case *observer.GetFlowsResponse_Flow:
			set = append(set, res)
		}

	}
}

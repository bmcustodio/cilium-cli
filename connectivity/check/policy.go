// Copyright 2021 Authors of Cilium
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
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type HTTP struct {
	Status string
	Method string
	URL    string
}

type Result struct {
	// Request is dropped
	Drop bool

	// No flows are to be expected. Used for ingress when egress drops
	None bool

	// DNSProxy is true when DNS Proxy is to be expected, only valid for egress
	DNSProxy bool

	// L7Proxy is true when L7 proxy (e.g., Envoy) is to be expected
	L7Proxy bool

	// HTTPStatus is true when a HTTP status code in response is to be expected
	HTTP HTTP
}

var (
	ResultOK      = Result{}
	ResultDNSOK   = Result{DNSProxy: true}
	ResultNone    = Result{None: true}
	ResultDrop    = Result{Drop: true}
	ResultDNSDrop = Result{Drop: true, DNSProxy: true}
)

func (r Result) String() string {
	if r.None {
		return "None"
	}
	ret := "Allow"
	if r.Drop {
		ret = "Drop"
	}
	if r.DNSProxy {
		ret += "-DNS"
	}
	if r.L7Proxy {
		ret += "-L7"
	}
	if r.HTTP.Status != "" || r.HTTP.Method != "" || r.HTTP.URL != "" {
		ret += "-HTTP"
	}
	if r.HTTP.Method != "" {
		ret += "-"
		ret += r.HTTP.Method
	}
	if r.HTTP.URL != "" {
		ret += "-"
		ret += r.HTTP.URL
	}
	if r.HTTP.Status != "" {
		ret += "-"
		ret += r.HTTP.Status
	}
	return ret
}

type ExpectationsFunc func(t *Action) (egress, ingress Result)

// addCNPs adds one or more CiliumNetworkPolicy resources to the Test.
func (t *Test) addCNPs(cnps ...*ciliumv2.CiliumNetworkPolicy) error {
	for _, p := range cnps {
		if p == nil {
			return errors.New("cannot add nil CiliumNetworkPolicy to test")
		}
		if p.Name == "" {
			return fmt.Errorf("adding CiliumNetworkPolicy with empty name to test: %v", p)
		}
		if _, ok := t.cnps[p.Name]; ok {
			return fmt.Errorf("CiliumNetworkPolicy with name %s already in test scope", p.Name)
		}

		t.cnps[p.Name] = p
	}

	return nil
}

// WithExpectations sets the getExpectations test result function to use during tests
func (t *Test) WithExpectations(f ExpectationsFunc) *Test {
	if t.expectFunc == nil {
		t.expectFunc = f
		return t
	}

	t.ctx.Fatal("test %s already has an expectation set", t.name)
	return nil
}

// getExpectations returns the expected results for a specific Action.
func (t *Test) expectations(a *Action) (egress, ingress Result) {
	// Default to success
	if t.expectFunc == nil {
		return ResultOK, ResultOK
	}

	egress, ingress = t.expectFunc(a)
	if egress.Drop || ingress.Drop {
		a.Waiting("The following command is expected to fail")
	}

	return egress, ingress
}

// ParsePolicyYAML decodes policy yaml into a slice of CiliumNetworkPolicies.
func ParsePolicyYAML(policy string) (cnps []*ciliumv2.CiliumNetworkPolicy, err error) {
	if policy == "" {
		return nil, nil
	}
	yamls := strings.Split(policy, "---")
	for _, yaml := range yamls {
		if strings.TrimSpace(yaml) == "" {
			continue
		}
		obj, groupVersionKind, err := scheme.Codecs.UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("resource decode error (%s) in: %s", err, yaml)
		}
		switch groupVersionKind.Kind {
		case "CiliumNetworkPolicy":
			cnp, ok := obj.(*ciliumv2.CiliumNetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("object cast to CiliumNetworkPolicy failed: %s", yaml)
			}
			cnps = append(cnps, cnp)
		default:
			return nil, fmt.Errorf("unknown policy type '%s' in: %s", groupVersionKind.Kind, yaml)
		}
	}
	return cnps, nil
}

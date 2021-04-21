package check

import (
	"context"
	"fmt"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type Test struct {
	// Reference to the enclosing test suite for logging etc.
	ctx *ConnectivityTest

	// Name of the test. Must be unique within the scope of a test run.
	name string

	// Scenarios registered to this test.
	scenarios map[Scenario][]*Action

	// Policies active during this test.
	cnps map[string]*ciliumv2.CiliumNetworkPolicy

	expectFunc ExpectationsFunc
}

func (t *Test) String() string {
	return fmt.Sprintf("<Test %s, %d scenarios, %d CNPs, expectFunc %v>", t.name, len(t.scenarios), len(t.cnps), t.expectFunc)
}

// Name returns the name of the test.
func (t *Test) Name() string {
	return t.name
}

// Context returns the enclosing context of the Test.
func (t *Test) Context() *ConnectivityTest {
	return t.ctx
}

// setup sets up the environment for the Test to execute in, like applying CNPs.
// The returned function must be called when test execution has concluded.
func (t *Test) setup(ctx context.Context) (func() error, error) {

	// Apply CNPs to the cluster.
	if err := t.applyPolicies(ctx); err != nil {
		return nil, fmt.Errorf("applying CiliumNetworkPolicies: %w", err)
	}

	// Construct closer.
	f := func() error {
		return t.deletePolicies(ctx)
	}

	return f, nil
}

// Run executes all Scenarios registered to the Test.
func (t *Test) Run(ctx context.Context) error {
	close, err := t.setup(ctx)
	if err != nil {
		return fmt.Errorf("setting up test: %w", err)
	}
	defer func() {
		if err := close(); err != nil {
			t.ctx.Fatal("tearing down test: %w", err)
		}
	}()

	for s := range t.scenarios {
		select {
		// Return from the test run if the context expired or has been cancelled.
		case <-ctx.Done():
			return nil
		default:
			s.Run(ctx, t)

			// Run finalizers on all Actions created by the Scenario.
			for _, a := range t.scenarios[s] {
				a.end()
			}
		}
	}

	return nil
}

// Skip marks the Test as skipped.
//TODO: Do some accounting of skipped tests to show in the summary.
func (t *Test) Skip() {
	t.Context().Logf("Skipping test %s", t.Name())
}

func (t *Test) Verbose() bool {
	return t.Context().Verbose()
}

// Log logs a message.
func (t *Test) Log(a ...interface{}) {
	t.Context().Log(a...)
}

// Logf logs a formatted message.
func (t *Test) Logf(format string, a ...interface{}) {
	t.Context().Logf(format, a...)
}

// Info logs an informational message.
func (t *Test) Info(a ...interface{}) {
	t.Context().Info(a...)
}

// Infof logs a formatted informational message.
func (t *Test) Infof(format string, a ...interface{}) {
	t.Context().Infof(format, a...)
}

// Debug logs a debug message.
func (t *Test) Debug(a ...interface{}) {
	t.Context().Debug(a...)
}

// Debugf logs a formatted debug message.
func (t *Test) Debugf(format string, a ...interface{}) {
	t.Context().Debugf(format, a...)
}

// Fatal logs an error and exits the calling goroutine.
func (t *Test) Fatal(a ...interface{}) {
	t.Context().Fatal(a...)
}

// Fatal logs a formatted error and exits the calling goroutine.
func (t *Test) Fatalf(format string, a ...interface{}) {
	t.Context().Fatalf(format, a...)
}

// WithPolicy takes a string containing a YAML policy document and adds
// the polic(y)(ies) to the scope of the Test, to be applied when the test
// starts running.
func (t *Test) WithPolicy(policy string) *Test {
	pl, err := ParsePolicyYAML(policy)
	if err != nil {
		t.ctx.Fatal("Error parsing policy YAML: %w", err)
	}

	if err := t.addCNPs(pl...); err != nil {
		t.ctx.Fatal("adding CNPs to policy context: %w", err)
	}
	return t
}

// WithScenarios adds Scenarios to Test in the given order.
func (t *Test) WithScenarios(sl ...Scenario) *Test {
	// Disallow adding the same Scenario object multiple times.
	for _, s := range sl {
		if _, ok := t.scenarios[s]; ok {
			t.Fatalf("Scenario %v already in %s's list of Scenarios", s, t)
		}

		t.scenarios[s] = make([]*Action, 0)
	}

	return t
}

// NewAction creates a new Action.
func (t *Test) NewAction(s Scenario, name string, src *Pod, dst TestPeer) *Action {
	a := newAction(t, name, s, src, dst)

	// Obtain the expected result for this particular action by calling
	// the registered expectation function.
	a.expEgress, a.expIngress = t.expectations(a)

	// Store a list of Actions per Scenario.
	t.scenarios[s] = append(t.scenarios[s], a)

	return a
}

// applyPolicies applies all the Test's registered network policies.
func (t *Test) applyPolicies(ctx context.Context) error {
	if len(t.cnps) == 0 {
		return nil
	}

	// Get current policy revisions in all Cilium pods.
	revisions, err := t.Context().getCiliumPolicyRevisions(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get policy revisions for Cilium pods: %w", err)
	}

	for pod, revision := range revisions {
		t.Debugf("Pod %s's current policy revision %d", pod.Name, revision)
	}

	// Apply all given CiliumNetworkPolicies.
	wait := false
	for _, cnp := range t.cnps {
		t.Infof("🔌 Applying CiliumNetworkPolicy '%s' to namespace '%s'..", cnp.Name, cnp.Namespace)
		mod, err := t.Context().updateOrCreateCNP(ctx, cnp)
		if err != nil {
			return fmt.Errorf("Policy application failed: %w", err)
		}
		if mod {
			wait = true
		}
	}

	// Wait for policies to take effect on all Cilium nodes.
	if wait {
		t.Debug("Policy difference detected, waiting for Cilium agents to increment policy revisions..")
		if err := t.Context().waitCiliumPolicyRevisions(ctx, revisions); err != nil {
			return fmt.Errorf("Policies were not applied on all Cilium nodes in time: %s", err)
		}
	}

	t.Infof("Successfully applied %d CiliumNetworkPolicies", len(t.cnps))

	return nil
}

// deletePolicies deletes a given set of network policies from the cluster.
func (t *Test) deletePolicies(ctx context.Context) error {
	if len(t.cnps) == 0 {
		return nil
	}

	// Get current policy revisions in all Cilium pods.
	revs, err := t.Context().getCiliumPolicyRevisions(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get policy revisions for Cilium pods: %w", err)
	}
	for pod, rev := range revs {
		t.Debugf("Pod %s's current policy revision: %d", pod.Name, rev)
	}

	// Delete all given CNPs.
	for _, cnp := range t.cnps {
		if err := t.Context().deleteCNP(ctx, cnp); err != nil {
			return fmt.Errorf("Unable to delete CiliumNetworkPolicy: %w", err)
		}
	}

	// Wait for policies to be deleted on all Cilium nodes.
	if err := t.Context().waitCiliumPolicyRevisions(ctx, revs); err != nil {
		return fmt.Errorf("Policies were not deleted in all Cilium nodes on time: %w", err)
	}

	t.Debugf("Successfully deleted CNPs")

	return nil
}

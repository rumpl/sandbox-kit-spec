package spec

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func sshAgentKit(t *testing.T, kind string, entries ...string) *Descriptor {
	t.Helper()
	doc := "schemaVersion: \"3\"\nkind: " + kind + "\ncapabilities:\n"
	for _, entry := range entries {
		doc += entry
	}
	return mustDecode(t, doc)
}

// sshAgentEntry renders one entry; extra is config lines after the phase,
// already indented for the config map.
func sshAgentEntry(phase string, optional bool, extra ...string) string {
	out := "  - type: " + CapabilitySSHAgent + "\n"
	if optional {
		out += "    optional: true\n"
	}
	out += "    config:\n      phase: " + phase + "\n"
	for _, line := range extra {
		out += "      " + line + "\n"
	}
	return out
}

func TestSSHAgentValidation(t *testing.T) {
	for _, kind := range []string{KindWorkload, KindMixin} {
		for _, entry := range []string{
			sshAgentEntry("runtime", false),
			sshAgentEntry("install", true),
			sshAgentEntry("runtime", false, "sign: [git]"),
			sshAgentEntry("runtime", false, "sign: [git, file, release@example.com]"),
			sshAgentEntry("runtime", false, "authenticate: [github.com]"),
			sshAgentEntry("runtime", false, "authenticate: [git@github.com, deploy_bot@ci.example.org]"),
			sshAgentEntry("runtime", false, "sign: [git]", "authenticate: [git@github.com]"),
			// The dash, dot and underscore forms a login name takes.
			sshAgentEntry("runtime", false, "authenticate: [a-b.c_d@x.io]"),
		} {
			_, err := Validate(sshAgentKit(t, kind, entry))
			require.NoError(t, err, "%s:\n%s", kind, entry)
		}
		// One entry per phase: both phases together are two asks.
		_, err := Validate(sshAgentKit(t, kind, sshAgentEntry("install", false, "sign: [git]"), sshAgentEntry("runtime", true)))
		require.NoError(t, err)
	}

	for name, tc := range map[string]struct{ doc, want string }{
		"phase missing":       {"  - type: " + CapabilitySSHAgent + "\n    config: {}\n", "phase must be"},
		"no config":           {"  - type: " + CapabilitySSHAgent + "\n", "phase must be"},
		"unknown phase":       {sshAgentEntry("always", false), "phase must be"},
		"unknown field":       {sshAgentEntry("runtime", false, "socket: /tmp/agent"), "socket"},
		"empty sign":          {sshAgentEntry("runtime", false, "sign: []"), "empty sign list"},
		"empty authenticate":  {sshAgentEntry("runtime", false, "authenticate: []"), "empty authenticate list"},
		"namespace space":     {sshAgentEntry("runtime", false, `sign: ["my ns"]`), "printable ASCII"},
		"namespace empty":     {sshAgentEntry("runtime", false, `sign: [""]`), "printable ASCII"},
		"namespace twice":     {sshAgentEntry("runtime", false, "sign: [git, git]"), "twice"},
		"wildcard host":       {sshAgentEntry("runtime", false, `authenticate: ["*.github.com"]`), "literal lowercase DNS name"},
		"host with port":      {sshAgentEntry("runtime", false, `authenticate: ["github.com:22"]`), "literal lowercase DNS name"},
		"uppercase host":      {sshAgentEntry("runtime", false, "authenticate: [GitHub.com]"), "literal lowercase DNS name"},
		"ip address":          {sshAgentEntry("runtime", false, "authenticate: [192.0.2.1]"), "IP address"},
		"user with ip":        {sshAgentEntry("runtime", false, "authenticate: [git@192.0.2.1]"), "IP address"},
		"empty user":          {sshAgentEntry("runtime", false, `authenticate: ["@github.com"]`), "literal lowercase DNS name"},
		"destination twice":   {sshAgentEntry("runtime", false, "authenticate: [github.com, github.com]"), "twice"},
		"same phase twice":    {sshAgentEntry("runtime", false) + sshAgentEntry("runtime", true, "sign: [git]"), "already declared"},
		"identical same kind": {sshAgentEntry("install", false) + sshAgentEntry("install", false), "identical"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Validate(sshAgentKit(t, KindWorkload, tc.doc))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// An arg-referenced entry defers its value checks until expansion, but
// the presence rules hold before it: an empty list is wrong whatever the
// arg later says.
func TestSSHAgentPresenceRulesDoNotWaitForArgs(t *testing.T) {
	doc := "schemaVersion: \"3\"\nkind: mixin\nargs:\n  ns: {default: git}\ncapabilities:\n" +
		sshAgentEntry("runtime", false, "sign: [\"${{ kit.args.ns }}\"]", "authenticate: []")
	_, err := Validate(mustDecode(t, doc))
	require.ErrorContains(t, err, "empty authenticate list")
}

func TestSSHAgentBounded(t *testing.T) {
	require.False(t, SSHAgent{Phase: "runtime"}.Bounded())
	require.True(t, SSHAgent{Phase: "runtime", Sign: []string{"git"}}.Bounded())
	require.True(t, SSHAgent{Phase: "runtime", Authenticate: []string{"github.com"}}.Bounded())
}

func mergedSSHAgents(t *testing.T, inputs ...Contribution) map[string]Capability {
	t.Helper()
	merged := mergeOK(t, inputs...).Descriptor
	_, err := Validate(merged)
	require.NoError(t, err)
	out := map[string]Capability{}
	for _, n := range merged.Capabilities {
		require.Equal(t, CapabilitySSHAgent, n.Type)
		var a SSHAgent
		require.NoError(t, DecodeCapabilityConfig(n, &a))
		out[a.Phase] = n
	}
	return out
}

// One socket per phase serves every kit that asked, so what it signs is
// what any of them may: the union of bounded asks, and everything when
// any ask is unbounded. The required declaration wins in either order.
func TestSSHAgentMergeUnionsBounds(t *testing.T) {
	workload := Contribution{Reference: "workload", Descriptor: sshAgentKit(t, KindWorkload,
		sshAgentEntry("runtime", true, "sign: [git]"))}
	mixin := Contribution{Reference: "mixin", Descriptor: sshAgentKit(t, KindMixin,
		sshAgentEntry("runtime", false, "sign: [file, git]", "authenticate: [git@github.com]"),
		sshAgentEntry("install", true, "authenticate: [github.com]"))}
	for _, inputs := range [][]Contribution{{workload, mixin}, {mixin, workload}} {
		byPhase := mergedSSHAgents(t, inputs...)
		var runtime, install SSHAgent
		require.NoError(t, DecodeCapabilityConfig(byPhase["runtime"], &runtime))
		require.NoError(t, DecodeCapabilityConfig(byPhase["install"], &install))
		require.Equal(t, SSHAgent{Phase: "runtime", Sign: []string{"file", "git"}, Authenticate: []string{"git@github.com"}}, runtime)
		require.False(t, byPhase["runtime"].Optional, "a required declaration wins")
		require.Equal(t, SSHAgent{Phase: "install", Authenticate: []string{"github.com"}}, install)
		require.True(t, byPhase["install"].Optional)
	}

	unbounded := Contribution{Reference: "unbounded", Descriptor: sshAgentKit(t, KindMixin, sshAgentEntry("runtime", true))}
	for _, inputs := range [][]Contribution{{workload, unbounded}, {unbounded, workload}} {
		var runtime SSHAgent
		require.NoError(t, DecodeCapabilityConfig(mergedSSHAgents(t, inputs...)["runtime"], &runtime))
		require.False(t, runtime.Bounded(), "an unbounded ask makes the phase unbounded")
	}
}

func surfaceOf(t *testing.T, entries ...string) Surface {
	t.Helper()
	return SurfaceOf(sshAgentKit(t, KindWorkload, entries...))
}

func TestSSHAgentSurface(t *testing.T) {
	require.Equal(t, []string{"runtime"}, surfaceOf(t, sshAgentEntry("runtime", true)).SSHAgent)
	require.Equal(t,
		[]string{"install", "runtime authenticate git@github.com", "runtime sign file", "runtime sign git"},
		surfaceOf(t,
			sshAgentEntry("runtime", false, "sign: [git, file]", "authenticate: [git@github.com]"),
			sshAgentEntry("install", false)).SSHAgent)
	require.Empty(t, surfaceOf(t, sshAgentEntry("runtime", false, "sign: [git]")).Services,
		"a well-known type never falls back to a service digest")
}

func TestSSHAgentWidenings(t *testing.T) {
	var (
		none         = surfaceOf(t)
		unbounded    = surfaceOf(t, sshAgentEntry("runtime", false))
		installOnly  = surfaceOf(t, sshAgentEntry("install", false))
		git          = surfaceOf(t, sshAgentEntry("runtime", false, "sign: [git]"))
		gitAndFile   = surfaceOf(t, sshAgentEntry("runtime", false, "sign: [git, file]"))
		anyGitHub    = surfaceOf(t, sshAgentEntry("runtime", false, "authenticate: [github.com]"))
		gitAtGitHub  = surfaceOf(t, sshAgentEntry("runtime", false, "authenticate: [git@github.com]"))
		rootAtGitHub = surfaceOf(t, sshAgentEntry("runtime", false, "authenticate: [root@github.com]"))
	)
	details := func(granted, candidate Surface) []string {
		var out []string
		for _, w := range DiffWidenings(granted, candidate) {
			require.Equal(t, "ssh-agent", w.Category)
			out = append(out, w.Detail)
		}
		return out
	}

	require.Equal(t, []string{"runtime sign git"}, details(none, git))
	require.Equal(t, []string{"runtime sign file"}, details(git, gitAndFile), "a new namespace widens")
	require.Equal(t, []string{"runtime"}, details(git, unbounded), "dropping the bounds widens")
	require.Empty(t, details(unbounded, gitAndFile), "bounding an unbounded grant narrows it")
	require.Empty(t, details(gitAndFile, git))
	require.Empty(t, details(anyGitHub, gitAtGitHub), "host covers user@host")
	require.Equal(t, []string{"runtime authenticate github.com"}, details(gitAtGitHub, anyGitHub),
		"dropping the user widens")
	require.Equal(t, []string{"runtime authenticate root@github.com"}, details(gitAtGitHub, rootAtGitHub),
		"another user is another grant")
	// Moving from install to runtime keeps the agent reachable for the
	// workload's whole life: a widening, even though the count is equal.
	require.Equal(t, []string{"runtime"}, details(installOnly, unbounded))
	// The reverse is a widening too: install hooks gain an agent they
	// were never granted. Only dropping a phase needs no approval.
	require.Equal(t, []string{"install"}, details(unbounded, installOnly))
	bothPhases := surfaceOf(t, sshAgentEntry("runtime", false), sshAgentEntry("install", false))
	require.Empty(t, details(bothPhases, installOnly), "giving up a phase needs no approval")

	for _, w := range DiffWidenings(none, gitAtGitHub) {
		require.False(t, strings.Contains(w.Detail, "  "), "surface entries are single-spaced tokens: %q", w.Detail)
	}
}

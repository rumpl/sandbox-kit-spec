# `com.docker.sandbox/ssh-agent@1`

An SSH agent the workload can use on the user's behalf. The workload can
list the agent's public keys and ask it to sign — to sign a commit, or to
log in to a git server over SSH — while the private keys stay outside the
sandbox.

The runtime exposes the agent inside the sandbox and relays to a
**backing agent**: the agent that holds the keys. Where the backing agent
runs is the runtime's decision — the user's own agent forwarded from their
workstation over the client's connection, or an agent the runtime manages
on the user's behalf. The sandbox cannot tell which, and nothing on this
page depends on it.

- **Shape**: instance — one entry per phase; duplicates rejected.
- **Permission surface**: yes — the phase, and what the entry lets the
  agent sign.

## Config

```yaml
- type: com.docker.sandbox/ssh-agent@1
  optional: true                       # entry-level: skip when no backing agent is available
  description: Sign commits and push to GitHub over SSH with the user's key
  config:
    phase: runtime                     # REQUIRED: "install" | "runtime"
    sign: [git]                        # namespaced signatures the agent may make
    authenticate: [git@github.com]     # servers the agent may log in to, as [user@]host
```

| Field | Type | Rules |
|---|---|---|
| `phase` | string | REQUIRED. `install` or `runtime`: the phase whose processes can reach the agent, with the same boundary as `credential@1`. |
| `sign` | list\<string\> | optional. Namespaces of the namespaced signatures the agent may make, such as `git` for commits and tags or `file` for files. Each is printable ASCII without spaces. |
| `authenticate` | list\<string\> | optional. Servers the agent may log in to, each `host` or `user@host`: a literal lowercase DNS name — no wildcard, port, or IP address — optionally preceded by the account name the login must use. |

An entry stating neither `sign` nor `authenticate` is **unbounded**: the
agent signs whatever the sandbox asks, with every key it holds. An entry
stating either is **bounded**: the agent signs only what the entry names,
and a bounded entry with only `sign` makes no logins at all. An empty
`sign` or `authenticate` list is an error, and so is a value listed twice.

The Kit names the need, never a backing agent, a socket, or a key: which
agent answers is the runtime's decision and the user's grant.

## What a signature is for

Every signature goes through one request, `SSH_AGENTC_SIGN_REQUEST`, and
the data it carries says what the signature is for. A runtime classifies
each request by that data:

- A **namespaced signature** is data beginning with the six-byte
  `SSHSIG` preamble of OpenSSH's `PROTOCOL.sshsig`, followed by its
  namespace. `ssh-keygen -Y sign` makes these, and git's SSH commit and
  tag signing uses the namespace `git`.
- A **login signature** is data that is the payload of an SSH public-key
  authentication request (RFC 4252 §7): a session identifier, then
  `SSH_MSG_USERAUTH_REQUEST` with the user name, the service, the method
  `publickey` or `publickey-hostbound-v00@openssh.com`, and the key.
- **Anything else** — a certificate signed with a CA key the agent
  holds, or bytes no protocol above describes — is neither.

A login signature does not name the server it logs in to. OpenSSH (8.9
and later) tells the agent through a **session binding**: the
`session-bind@openssh.com` extension of OpenSSH's `PROTOCOL.agent`, which
carries the server's host key, the session identifier, the host key's
signature over that identifier, and whether the binding is for a
forwarded agent rather than the connection itself.

## Runtime behavior

A conforming runtime:

- **MUST** expose the backing agent through a Unix socket inside the <!-- tck: ssh-agent@1/agent-reachable -->
  sandbox during the granted phase, and set `SSH_AUTH_SOCK` to that
  socket's path in the environment the granted phase's processes start
  with. For a `runtime` grant, those are the workload, the sessions and
  commands run in the sandbox, and `startup` hooks that declare
  `SSH_AUTH_SOCK` in `env`; for an `install` grant, `install` hooks that
  declare it. Listing identities returns the backing agent's public
  keys, and a sign request the entry admits is signed by the backing
  agent.
- **MUST** relay only the requests that list identities and sign data <!-- tck: ssh-agent@1/operations-restricted -->
  (`SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST`), plus
  session bindings as the rules below allow, and answer every other
  request with `SSH_AGENT_FAILURE` without passing it to the backing
  agent: adding, removing, or locking keys, loading smartcard or PKCS#11
  providers, and every other extension. Each of those changes the agent
  for everything else that uses it, and loading a provider has been a
  path to running code on the machine that holds the backing agent.
- **MUST**, for a bounded entry, sign a namespaced signature only when <!-- tck: ssh-agent@1/signatures-bounded -->
  its namespace is listed in `sign`, and refuse, without passing it to
  the backing agent, every sign request that is neither such a
  signature nor a login signature `authenticate` admits. An unbounded
  entry relays every sign request.
- **MUST**, for a bounded entry, sign a login signature only when every <!-- tck: ssh-agent@1/logins-bounded -->
  one of these holds, and otherwise refuse it without passing it to the
  backing agent: the same connection to the agent carries a session
  binding the runtime verified; the session identifier in the signed
  data is that binding's; the binding's host key is a host key of a
  server named in `authenticate`; where that `authenticate` entry names
  a user, the signed data's user name is that user; and, for the method
  `publickey-hostbound-v00@openssh.com`, the host key in the signed data
  is the binding's.
- **MUST** verify a session binding before it counts — the host key's <!-- tck: ssh-agent@1/binding-verified -->
  signature over the session identifier — and **MUST NOT** treat a
  binding marked as forwarding as the server a login is for.
- **MUST** obtain the host keys it matches against `authenticate` from <!-- tck: ssh-agent@1/destination-keys-outside-sandbox -->
  outside the sandbox — the user's known hosts, keys the server's
  operator publishes, or keys the runtime pins — never from anything the
  sandbox presents. A binding is the sandbox's word about which server
  it is talking to; the host key is what makes that word checkable.
- **MUST NOT** place private key material in the sandbox. <!-- tck: ssh-agent@1/key-material-outside-sandbox -->
- **MUST NOT** give a sandbox that was not granted this capability any <!-- tck: ssh-agent@1/absent-without-grant -->
  path to the backing agent, even when one is available. An agent the
  runtime itself happens to reach, such as an `SSH_AUTH_SOCK` in its own
  environment, is never passed into the sandbox that way.
- **MUST** scope by phase: an `install` grant is reachable only while <!-- tck: ssh-agent@1/phase-scoped -->
  install hooks run and closes before the workload's entrypoint starts; a
  `runtime` grant is the workload's steady state.
- **MUST** re-establish the agent on every boot, so a runtime grant <!-- tck: ssh-agent@1/every-boot -->
  survives stop and start.
- **MUST** refuse a **required** entry when no backing agent is <!-- tck: ssh-agent@1/unavailable-refuses-required -->
  available — the runtime has none to offer, or the user withheld it —
  by type name, before starting the workload.
- **MUST** skip and record an **optional** entry it cannot back, and <!-- tck: ssh-agent@1/unavailable-skips-optional -->
  start the sandbox without `SSH_AUTH_SOCK`.

What a Kit grants, the user can narrow further. A runtime:

- **SHOULD** let the user limit which of the backing agent's keys a <!-- tck: ssh-agent@1/keys-selectable -->
  sandbox can use: identities outside the selection are left out of the
  list, and sign requests naming them are refused.
- **SHOULD** offer to ask the user to confirm each signature before the <!-- tck: ssh-agent@1/confirmation-offered -->
  backing agent makes it.
- **SHOULD** offer to end a grant, at a time the user chooses, before <!-- tck: ssh-agent@1/grant-expiry-offered -->
  its phase ends.
- **SHOULD** record each sign request it relays or refuses — the key, <!-- tck: ssh-agent@1/signatures-observable -->
  what the signature was for (the namespace, or the login's user and
  server), and the outcome — where the user can see it.

A Kit cannot configure any of these: each narrows what the user granted,
and none can widen it.

### Compatibility

Git's SSH commit and tag signing makes only namespaced signatures in the
namespace `git`, so `sign: [git]` serves it with no login grant at all.
OpenSSH clients bind sessions before logging in. A client that does not
cannot log in through a bounded entry, because nothing tells the agent
which server it is talking to; such a workload needs an unbounded entry,
or HTTPS with `credential@1` instead.

`authenticate` grants a signature, not a connection: reaching the server
is the network policy's business, and a login the policy does not let
the sandbox make never reaches the agent.

A backing agent forwarded over a client's connection can come and go
with that connection while the sandbox keeps running. This page judges
availability when the sandbox is created and asks nothing about the
backing agent staying reachable afterwards: while it is unreachable,
signing through the socket fails as it does with any unreachable agent.

## Composition

Entries for the same phase merge into one: it is unbounded when any of
them is, and otherwise its `sign` and `authenticate` are the unions of
the entries' lists. A required entry wins over an optional one. The
sandbox gets one socket per phase, whichever Kits asked for it.

## Gate

Per phase, what the agent may sign is permission surface: everything,
for an unbounded entry; otherwise each namespace and each destination.
Widening is a phase newly asking for the agent, an install-only ask
moving to `runtime`, a bounded entry becoming unbounded, a new
namespace, or a new destination — where `host` already covers
`user@host`, and the reverse is a widening.

An unbounded entry lets the agent sign with every key it holds, for
anything the sandbox asks: logins to any server the sandbox can reach,
signatures carrying the user's identity, such as commits a code host
shows as verified, and certificates, if the agent holds a certificate
authority's key.

A runtime **SHOULD** state what a grant allows when it asks the user to <!-- tck: ssh-agent@1/grant-names-scope -->
approve it — the namespaces and servers of a bounded entry, and every
key for anything for an unbounded one — rather than presenting it like
a single credential.

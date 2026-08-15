# ContextSeal: the five-page explanation

This is the version to study before a portfolio review, recruiter screen, product interview, or technical conversation. It explains what ContextSeal does, why it matters, how the request moves through the system, what the demo proves, and where the production boundary begins.

## Page 1: the problem and the product idea

ContextSeal addresses a specific problem in agentic systems: an AI agent may need permission to call a tool, but it should not need possession of the tool's reusable credential.

Imagine an agent that needs a weather API. The easiest implementation is to place the weather provider's API key in the same process or context used by the agent. That combines two different things: the agent's ability to request an action and the infrastructure's authority to authenticate with the provider. If untrusted content influences the model, if context is logged, or if the agent is prompted to reveal what it knows, the credential is unnecessarily close to the risk.

ContextSeal separates those responsibilities. The model receives an opaque capability reference, such as `cap_weather_read_7f3d`. That reference contains no secret and cannot directly authenticate with a provider. The model sends the reference, requested action, resource, and input to a policy proxy. The proxy is the trusted checkpoint. It decides whether the request fits the authority previously granted to that capability.

The simplest one-sentence description is:

> ContextSeal is a deny-by-default policy boundary that lets an agent ask to use a tool without giving the agent the tool's raw credential.

The word "secretless" needs one qualification. ContextSeal is secretless from the agent's point of view, not necessarily from the whole production system. A real provider still expects a credential somewhere. The secure design keeps that credential in a server-side secret manager and resolves it only inside a trusted adapter after policy passes. The current demo does not connect to that adapter or a real vault. It represents the boundary and proves the decision logic using synthetic data.

The product idea has four pillars:

1. **Opaque capabilities.** The agent receives a meaningless reference instead of a reusable provider key.
2. **Least privilege.** The reference permits an exact action, exact resource, and limited time window.
3. **Pre-execution inspection.** Policy and content checks occur before a request could reach a tool.
4. **Decision evidence.** Every result creates a signed, chained receipt, including denials.

This matters because agent security is not only about preventing a model from saying something harmful. Once agents can take actions, the security questions become: What authority did this request have? Where was it allowed to act? What stopped unsafe input? What evidence remains afterward? ContextSeal is a compact answer to those questions.

## Page 2: how a request moves through ContextSeal

The central workflow begins with a request containing four fields:

```json
{
  "capabilityId": "cap_weather_read_7f3d",
  "action": "weather.get_forecast",
  "resource": "weather://nyc",
  "input": "Synthetic request: forecast for NYC"
}
```

The proxy evaluates the request in a strict sequence.

First, it looks up the capability reference. An unknown reference is rejected immediately. This is the deny-by-default posture: there is no fallback permission and no attempt to infer what the caller probably meant.

Second, it checks expiration. A capability is temporary authority. Even if its action and resource match, it stops working after its fixed expiration time.

Third, it compares the requested action with the capability's exact tool allowlist. The weather capability permits `weather.get_forecast`; it does not permit `tickets.update`, `vault.read`, or a similarly named action. The match is explicit rather than semantic.

Fourth, it checks the resource. In the fixture, the weather capability is limited to `weather://nyc`. A caller cannot reuse it for another city or a different resource. This demonstrates object-level scoping, not merely tool-level access.

Fifth, it inspects the input. The prompt-injection screen looks for a small set of common instruction-override patterns. The DLP screen looks for common credential shapes, including API-key prefixes, bearer tokens, private-key headers, and explicit password or access-token fields. If either detector fires, the request is quarantined.

Only a request that passes all five categories is allowed. In this demo, "allowed" means the response says `would-forward-to-tool`. There is intentionally no real provider call. That wording matters when presenting the work because it separates implemented behavior from the production concept.

After the decision, the server creates a receipt. It does this for an allow and for a deny. The receipt records the synthetic principal, action, resource, reason code, capability reference, previous receipt hash, current hash, and HMAC signature.

The API returns HTTP 200 for an allow and HTTP 403 for a policy denial. A denial is still a normal, explainable security outcome. It is not treated like an internal failure. Invalid request data uses a 400 response, and a payload over 100 KB uses 413.

The order makes the control understandable. A capability cannot pass merely because its input is safe. Safe content does not widen authority. Likewise, a valid capability cannot bypass the content boundary. Every gate must pass.

## Page 3: capabilities, content controls, and receipts

The capability model is the heart of least privilege. Each synthetic capability contains an opaque ID, principal, label, exact tool, exact resource, scope label, expiration, status, and grant reason.

The ID is what the agent sees. The remaining fields are policy data resolved at the proxy. This prevents the caller from declaring its own permissions inside the request. Sending `scope: admin` would do nothing because the server trusts its fixture record, not a caller-provided scope.

The implementation uses exact equality for actions and resources. That is intentionally easy to reason about. A richer production system might support resource patterns, typed conditions, budgets, rate limits, or approval rules, but every expansion increases policy complexity. The demo chooses a narrow rule that is easy to test and explain.

The content firewall adds another control layer. Capability checks answer, "Is this caller allowed to request this action on this resource?" Content checks answer, "Does the request contain a known unsafe pattern that should stop before execution?" These are related but distinct questions.

The pattern detectors are examples, not claims of comprehensive protection. Prompt injection is an open-ended adversarial problem. A few regular expressions cannot detect every paraphrase or encoded instruction. Production DLP must also support organization-specific formats, structured secrets, transformed data, and context. The value of this demo is architectural: the content check sits at the enforcement boundary before the tool, and failure produces a recorded reason.

Receipts provide the evidence layer. Each receipt links to the previous receipt's hash. The first points to `GENESIS`. If someone silently edits an older receipt, its hash changes and the next receipt's `previousReceipt` value no longer matches. That is why the chain is described as tamper-evident rather than tamper-proof.

The HMAC signature is computed over the receipt data plus its hash. With the signing secret, a verifier could recompute the signature and detect unauthorized changes. The checked-in fallback key is deliberately public and therefore has no evidentiary value. A deployed demo should set `RECEIPT_SIGNING_KEY`; a production system should use rotated KMS or HSM keys and include a key identifier in each receipt.

The ledger exists only in server memory. It resets on restart, and its sequence restarts. This is appropriate for a self-contained demo but not for an audit system. Production would need durable append-only storage, monotonic identifiers, controlled retention, access logging, and an independent verification path.

A useful way to present the layers is:

- The capability limits **what may be attempted**.
- The content firewall checks **what is being carried into the attempt**.
- The receipt proves **what decision the boundary made**.

Together they form prevention plus evidence, which is stronger than treating agent security as a single filter.

## Page 4: what is actually implemented

ContextSeal is built with Node.js 20 and no external dependencies. That keeps the security flow visible. There is no framework hiding routing or middleware behavior, and no installation step that expands the dependency surface.

`server.mjs` provides the HTTP server, static UI hosting, API routes, request-size cap, in-memory ledger, receipt creation, and read-only JSON-RPC audit method. It maps allowed decisions to `would-forward-to-tool` and denied decisions to `quarantined`.

`src/policy.mjs` contains the fixture capabilities, authorization sequence, prompt-injection patterns, DLP patterns, receipt hashing, and HMAC signing. The authorization function returns reason codes instead of a bare boolean. That lets the UI and audit trail explain why a decision occurred.

`public/index.html`, `public/app.js`, and `public/styles.css` create the interactive teaching interface. The user can run three scenarios, inspect system nodes, drag or keyboard-nudge the architecture map, and see new receipts appear. `public/graph.mjs` separates graph positions, explanations, bounds, and allowed or denied animation paths so those behaviors can be tested.

The denied animation is a small but important product detail. A denied request stops visually at the policy proxy and then proceeds to the receipt ledger. It never lights up the tool node. The diagram reinforces the actual security claim instead of showing the same path for every outcome.

The read-only audit route accepts only the `contextseal.audit` method. It returns the number of fixture capabilities, full in-memory receipts, and the deny-by-default policy label. It does not expose an execution method. This is a synthetic MCP-shaped audit surface, not a full implementation of MCP transport, tool discovery, sessions, or tool invocation.

The suite has 12 passing tests. Eight cover policy and signing behavior: valid allow, future validity, action denial, expiration denial, prompt-injection blocking, DLP blocking, omission of raw input from inspection output, and deterministic signing. Four cover the teaching map: every node has an explanation, dragged positions stay in bounds, allowed paths reach a tool then evidence, and denied paths stop at the proxy before evidence.

Syntax checks cover the server, policy module, application JavaScript, and graph module. Local smoke tests cover health, bootstrap, allowed authorization, and read-only audit. These checks support a precise claim: the demo works as implemented. They do not prove production security, detector completeness, or deployment availability.

## Page 5: how to present it and what comes next

Start a live explanation with the boundary, not the styling:

> An agent needs authority to act, but possessing a provider credential is broader than asking for one approved action. ContextSeal gives the agent an opaque capability and moves the real decision into a deny-by-default proxy.

Then show the principle card. Explain that `cap_weather_read_7f3d` is safe to place in model context because it is not a provider API key. In the production design, the proxy would resolve a real credential only after policy passes, inside a non-model process.

Run the safe forecast. Point out the exact action and resource match. When the receipt appears, explain that an allow is recorded before the request would be forwarded. The demo does not call an external service.

Run the injection scenario. Use the graph to show that the path stops at the proxy. Explain that having a valid capability is necessary but not sufficient; unsafe input is still quarantined.

Run the secret-shaped scenario. Explain that the DLP example catches a credential pattern at the same boundary. Do not describe the regex set as comprehensive. Describe it as a demonstration of control placement and structured denial reasons.

Open the audit concept and explain the chain. Each receipt points backward, so silent mutation becomes detectable. The current HMAC and in-memory storage are demo choices. In production, the key would move to KMS or HSM and the ledger would become durable and append-only.

If asked why this is a product project rather than only a security code sample, emphasize these decisions:

- The user can understand the architecture without reading source code.
- Every denial is legible rather than mysterious.
- The demo makes scope, expiry, and evidence visible.
- The safe and unsafe scenarios are comparable.
- The interface accurately shows denied traffic stopping before the tool.
- The design states its limitations instead of overstating readiness.

If asked what you would build next, give a prioritized answer:

1. **Identity binding and authentication.** Bind a capability to a verified workload, tenant, and audience.
2. **Replay protection.** Add nonce or transaction semantics so captured requests cannot be reused.
3. **Typed policy.** Validate request schemas and version policy decisions.
4. **Real adapter boundary.** Resolve credentials from a secret manager in an isolated non-model process and call a sandbox provider.
5. **Durable verification.** Store receipts in an append-only ledger and ship an independent signature and chain verifier.
6. **Key management.** Rotate signing keys in KMS or HSM and record key IDs.
7. **Adversarial evaluation.** Build a corpus with encoded, multilingual, obfuscated, and organization-specific cases.
8. **Operational controls.** Add rate limits, tenant isolation, observability scrubbing, alerts, and incident workflows.

End with the honest claim:

> ContextSeal is not a finished production broker. It is a tested reference implementation that makes one security principle tangible: agents should receive narrow permission to request an action, not possession of the credential behind that action.

## Fast interview answers

### What did you build?

I built a dependency-free Node.js security demo that sits between an AI agent and a tool. The agent carries an opaque capability, the proxy checks exact scope, expiry, and input safety, and every decision creates a signed, hash-chained receipt.

### Why not just store the API key in an environment variable?

The production proxy should store provider credentials outside the model process, often through a secret manager. The distinction is that the agent receives only limited authority to request a specific action. An environment variable in the same agent process can still be too close to model-controlled execution and broad logging.

### Is this a full MCP proxy?

No. It is an MCP policy-proxy reference demo with a read-only JSON-RPC audit method. It does not implement full MCP sessions, discovery, transports, or actual tool forwarding.

### Does the receipt prevent tampering?

It makes tampering detectable when the chain and HMAC are verified. The project does not yet include an independent verifier, durable ledger, or production key management.

### Can regex stop prompt injection?

No. The regexes are deliberately small examples. They demonstrate where quarantine occurs and how denials are structured. Production needs layered controls and a serious adversarial evaluation corpus.

### What is the strongest design decision?

The agent never gets to define or widen its own authority. The server resolves an opaque reference and requires exact matches for action, resource, and time before content is considered safe enough to proceed.

### What did you test?

The 12 tests cover allowed and denied policy cases, expiration, content blocking, deterministic signing, graph explanations, drag bounds, and the fact that denied walkthroughs stop at the proxy. I also smoke-tested the live HTTP endpoints locally.

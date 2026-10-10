---
layout: default
---

# Vörður

Vörður is a security library for applications that use language models and tools. It checks content as it enters an application, applies policy before tool execution, and inspects outgoing data for disclosure. Its controls run in the surrounding application, where the host can enforce decisions even when a model follows an instruction it should have ignored.

An assistant may read a web page or a document while holding access to systems that its author cannot reach. Instructions embedded in that material can try to turn the assistant's access into an unauthorized action. Detecting the instruction addresses one part of the problem. The application also needs to decide who authorized the proposed action and whether its arguments disclose protected information.

Vörður retains security state across a session so later checks can use facts established earlier. Ingesting untrusted content records contamination. A subsequent tool call can require authorization or be denied under the configured policy. A blocked disclosure can escalate the session and restrict later actions, even when those actions look ordinary in isolation. The host supplies the context of each call, including the source's trust level; Vörður maintains the record of what happened within the session.

## Start here

[Follow an attack through the controls](https://mhcoen.github.io/vordur/demo/vordur_demos.html) shows how an incoming instruction, an attempted disclosure, and a later tool call relate to one another. Open the [system map](https://mhcoen.github.io/vordur/demo/vordur_surface_map.html) to explore individual controls, or read the [visual mechanism guide](https://mhcoen.github.io/vordur/docs/mechanisms/) for illustrated explanations of the architecture.

## How the controls work

Incoming content is processed with source attribution and trust information. Sanitization removes supported forms of hidden content, while provenance tracking retains information that outbound checks can consult. Tool authorization evaluates the proposed action against policy. Outbound inspection separately checks the data carried by that action: permission to call a tool does not establish permission to send every value in its arguments.

| Mechanism | What it does | Illustrated guide |
|---|---|---|
| Session risk | Carries contamination and escalation into later policy decisions. | [What the Guard Remembers](https://mhcoen.github.io/vordur/docs/mechanisms/01-session-risk.html) |
| Canary detection | Remembers a marker placed in private model context and checks for its appearance in outgoing content. | [A Marker Only the Model Sees](https://mhcoen.github.io/vordur/docs/mechanisms/02-canary.html) |
| Request binding | Checks that a proposed call still matches the recorded arguments and user message within its allowed lifetime. | [The Call That Came Back Changed](https://mhcoen.github.io/vordur/docs/mechanisms/03-request-binding.html) |
| Privacy vault | Replaces recognized or host-declared personal values with tokens before the model boundary; restoration requires policy permission for the field and destination. | [What the Provider Sees Instead](https://mhcoen.github.io/vordur/docs/mechanisms/04-privacy-vault.html) |
| Path mediation | Requires the application to route relevant operations through the controls so their decisions reflect the session's actual history. | [The Path Around the Guard](https://mhcoen.github.io/vordur/docs/mechanisms/05-mediated-paths.html) |
| Action and data checks | Separates authorization of a tool call from inspection of the bytes it would send. | [One Call, Two Questions](https://mhcoen.github.io/vordur/docs/mechanisms/06-two-questions.html) |

The [MCP demonstration](https://mhcoen.github.io/vordur/demo/vordur_mcp_demo.html) follows a record that requests a write in its text. It compares that request with a user directive and shows the host's role in establishing authorization. The [security-context demonstration](https://mhcoen.github.io/vordur/demo/vordur_security_context_demo.html) shows how changing a host-declared trust level affects the handling of the same input.

## Reading the demonstrations

The demo pages display recorded results and explanatory diagrams. Browser interactions reveal those results; they do not execute the Vörður library or connect to a model or MCP server. Each scenario includes its scope and supporting evidence. The mechanism guides explain the controls and their limits.

Deployment behavior depends on policy and integration. Several defaults permit behavior that a stricter deployment would reject, and an operation that bypasses the controls leaves no history for later checks to use. Request binding assumes a trusted application process. The privacy vault can replace only values supplied by the host or found by its detectors. These conditions are explained in the corresponding guides.

## Access and licensing

For access or licensing inquiries, contact [Michael H. Coen](mailto:mhcoen@alum.mit.edu).

# MITRE ATLAS and ATT&CK Enterprise mapping

Generated from the code by `internal/threatmap/mapdoc`; do not edit. Regenerate with `task docs:mitre` ([G0 M28](../g0/M28.md), [ADR-0055](../adr/0055-mitre-threat-map.md)).

> This map shows the PantherClaw controls mapped to each technique and the evidence for them. A mapped control covers the technique, not every way of carrying it out. Techniques outside PantherClaw need other tools. It is not a score or a guarantee.

Every technique of both matrices has exactly one place:

- **Mapped:** PantherClaw controls, detection rules, signal kinds, Hub content or range scenarios are mapped to the technique or one of its sub-techniques. What the organization's map shows for it depends on that organization's evidence ([runbook](../runbooks/threat-map.md)).
- **Mapped (partly):** mapped, but some of its sub-techniques have nothing mapped and no other place; they are named as not covered.
- **Outside PantherClaw:** the technique needs something PantherClaw does not see; the kind of tool that covers it is named.
- **No PantherClaw control yet:** the technique is within an agent platform's reach and PantherClaw ships no control for it; why is given.

Mapping digest: `3c7a646923e8e4e3bfb591856fab65aaa575842e9e465600f2835250618d79b4`.

| Framework | Catalogue version | Catalogue digest |
|---|---|---|
| MITRE ATLAS | 2026.10 | `6cb917be68cb7e9c4f9a4d191c5fd9a1c3f344b333b6d99c38cedf19557e5510` |
| MITRE ATT&CK Enterprise | 20.0 | `7c0220f814c9d7e6e97e782bad1cb3186f12e7a3b80649add6d407051cdd74e6` |

## MITRE ATLAS

### Reconnaissance (AML.TA0002)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006) | Active Scanning | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0116](https://atlas.mitre.org/techniques/AML.T0116) | Autonomous Reconnaissance | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0064](https://atlas.mitre.org/techniques/AML.T0064) | Gather RAG-Indexed Targets | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0087](https://atlas.mitre.org/techniques/AML.T0087) | Gather Victim Identity Information | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0004](https://atlas.mitre.org/techniques/AML.T0004) | Search Application Repositories | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0001](https://atlas.mitre.org/techniques/AML.T0001) | Search Open AI Vulnerability Analysis | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0000](https://atlas.mitre.org/techniques/AML.T0000) | Search Open Technical Databases | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0095](https://atlas.mitre.org/techniques/AML.T0095) | Search Open Websites/Domains | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0003](https://atlas.mitre.org/techniques/AML.T0003) | Search Victim-Owned Websites | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |

### Resource Development (AML.TA0003)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0008](https://atlas.mitre.org/techniques/AML.T0008) | Acquire Infrastructure | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0002](https://atlas.mitre.org/techniques/AML.T0002) | Acquire Public AI Artifacts | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0139](https://atlas.mitre.org/techniques/AML.T0139) | Compromise Accounts | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0128](https://atlas.mitre.org/techniques/AML.T0128) | Compromise Infrastructure | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0017](https://atlas.mitre.org/techniques/AML.T0017) | Develop Capabilities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0021](https://atlas.mitre.org/techniques/AML.T0021) | Establish Accounts | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0016](https://atlas.mitre.org/techniques/AML.T0016) | Obtain Capabilities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0060](https://atlas.mitre.org/techniques/AML.T0060) | Publish Hallucinated Entities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0115](https://atlas.mitre.org/techniques/AML.T0115) | Publish Poisoned AI Artifacts | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0005](https://atlas.mitre.org/techniques/AML.T0005) | Replicate AI Model Behavior | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0079](https://atlas.mitre.org/techniques/AML.T0079) | Stage Capabilities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |

### AI Attack Adaptation (AML.TA0001)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0118](https://atlas.mitre.org/techniques/AML.T0118) | Autonomous AI Agent Communication | Mapped (partly) | AML.T0118.001: prevent `prevent.delegation_bounds`; rules `pc.delegation.depth_anomaly`; Hub playbooks `pc.playbook.rogue-sub-agent`; scenarios `RT-006`, `RT-007`, `RT-049`, `RT-051`<br>AML.T0118.000 not covered |
| [AML.T0124](https://atlas.mitre.org/techniques/AML.T0124) | Autonomous Attack Orchestration | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0117](https://atlas.mitre.org/techniques/AML.T0117) | Autonomous Attack-Path Adaptation | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043) | Craft Adversarial Data | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0088](https://atlas.mitre.org/techniques/AML.T0088) | Generate Deepfakes | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0102](https://atlas.mitre.org/techniques/AML.T0102) | Generate Malicious Commands | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0065](https://atlas.mitre.org/techniques/AML.T0065) | LLM Prompt Crafting | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018) | Manipulate AI Model | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0005](https://atlas.mitre.org/techniques/AML.T0005) | Replicate AI Model Behavior | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0066](https://atlas.mitre.org/techniques/AML.T0066) | Retrieval Content Crafting | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0042](https://atlas.mitre.org/techniques/AML.T0042) | Verify Attack | Outside PantherClaw: covered by model security | It happens in model development. |

### Initial Access (AML.TA0004)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0131](https://atlas.mitre.org/techniques/AML.T0131) | Crafted AI Assistant Links | Mapped | prevent `prevent.browser_sites`; scenarios `RT-220` |
| [AML.T0078](https://atlas.mitre.org/techniques/AML.T0078) | Drive-by Compromise | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0119](https://atlas.mitre.org/techniques/AML.T0119) | Exploit Automated Artifact Processing Pipeline | No PantherClaw control yet | Exploit automated artifact processing pipeline (AML.T0119): pipelines that process artifacts have no PantherClaw control. |
| [AML.T0049](https://atlas.mitre.org/techniques/AML.T0049) | Exploit Public-Facing Application | Outside PantherClaw: covered by network security | It needs a network. |
| [AML.T0132](https://atlas.mitre.org/techniques/AML.T0132) | Misconfigured or Publicly Exposed AI Services | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [AML.T0052](https://atlas.mitre.org/techniques/AML.T0052) | Phishing | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [AML.T0093](https://atlas.mitre.org/techniques/AML.T0093) | Prompt Infiltration via Public-Facing Application | Mapped | prevent `prevent.content_hold`; scenarios `RT-154` |
| [AML.T0010](https://atlas.mitre.org/techniques/AML.T0010) | Supply Chain Compromise | Mapped (partly) | AML.T0010.005: prevent `prevent.mcp_catalog`, `prevent.tool_package_review`; rules `pc.tools.drift`; Hub playbooks `pc.playbook.poisoned-mcp-server`, `pc.playbook.poisoned-mcp-server-contain`<br>AML.T0010.000 not covered<br>AML.T0010.001 not covered<br>AML.T0010.002 not covered<br>AML.T0010.003 not covered<br>AML.T0010.004 not covered |
| [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012) | Valid Accounts | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |

### AI Model Access (AML.TA0000)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) | AI Model Inference API Access | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0047](https://atlas.mitre.org/techniques/AML.T0047) | AI-Enabled Product or Service | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044) | Full AI Model Access | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0041](https://atlas.mitre.org/techniques/AML.T0041) | Physical Environment Access | Outside PantherClaw: covered by physical security | It needs physical access. |

### Execution (AML.TA0005)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0100](https://atlas.mitre.org/techniques/AML.T0100) | AI Agent Clickbait | Mapped | prevent `prevent.browser_sites`; scenarios `RT-220` |
| [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | AI Agent Tool Invocation | Mapped | prevent `prevent.grant_scope`, `prevent.mapped_routes`; rules `pc.authority.self_issue`; kinds `behavior.NEW_TOOL`; Hub playbooks `pc.playbook.rogue-sub-agent`, `pc.playbook.rogue-sub-agent-contain`; scenarios `RT-001`, `RT-002`, `RT-019`, `RT-121`, `RT-211`, `RT-212`, `RT-213`, `RT-214`, `RT-223` |
| [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050) | Command and Scripting Interpreter | Mapped | Hub rules `org.hub.held_merge_then_shell`, `org.hub.shell_merge_attempt`; scenarios `RT-003` |
| [AML.T0103](https://atlas.mitre.org/techniques/AML.T0103) | Deploy AI Agent | Mapped | prevent `prevent.agent_deploy`; rules `pc.runtime.agent_deployed`; scenarios `RT-227` |
| [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) | LLM Prompt Injection | Mapped (partly) | AML.T0051.001: prevent `prevent.content_hold`; rules `pc.tools.description_injection`; kinds `content.injection_phrase`; Hub playbooks `pc.playbook.poisoned-mcp-server`; scenarios `RT-154`, `RT-158`, `RT-159`, `RT-163`, `RT-200`; campaigns `RT-140`, `RT-141`, `RT-142`, `RT-143`, `RT-144`, `RT-145`, `RT-146`, `RT-147`<br>AML.T0051.000 not covered<br>AML.T0051.002 not covered |
| [AML.T0011](https://atlas.mitre.org/techniques/AML.T0011) | User Execution | Outside PantherClaw: covered by security awareness | It needs a person. |

### Persistence (AML.TA0006)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0080](https://atlas.mitre.org/techniques/AML.T0080) | AI Agent Context Poisoning | No PantherClaw control yet | AI agent context poisoning (AML.T0080): an agent's memory and context are not read by PantherClaw. |
| [AML.T0121](https://atlas.mitre.org/techniques/AML.T0121) | AI Agent Environment Reconstruction | No PantherClaw control yet | AI agent environment reconstruction (AML.T0121): an agent rebuilding its own environment has no PantherClaw control yet. |
| [AML.T0099](https://atlas.mitre.org/techniques/AML.T0099) | AI Agent Tool Data Poisoning | Mapped | prevent `prevent.content_hold`; scenarios `RT-163` |
| [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) | AI Agent Tool Poisoning | Mapped (partly) | AML.T0110.000: prevent `prevent.tool_package_review`; rules `pc.tools.description_injection`; Hub playbooks `pc.playbook.poisoned-mcp-server`; scenarios `RT-028`<br>AML.T0110.002: prevent `prevent.content_hold`; campaigns `RT-140`, `RT-141`<br>AML.T0110.001 not covered |
| [AML.T0125](https://atlas.mitre.org/techniques/AML.T0125) | Create Account | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [AML.T0142](https://atlas.mitre.org/techniques/AML.T0142) | Event Triggered Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0061](https://atlas.mitre.org/techniques/AML.T0061) | LLM Prompt Self-Replication | No PantherClaw control yet | LLM prompt self-replication (AML.T0061): PantherClaw does not inspect model output for prompts that copy themselves. |
| [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018) | Manipulate AI Model | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081) | Modify AI Agent Configuration | Mapped | prevent `prevent.agent_config`; rules `pc.agent.config_changed`; scenarios `RT-203` |
| [AML.T0145](https://atlas.mitre.org/techniques/AML.T0145) | Poison AI Agent Learning Environment | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0093](https://atlas.mitre.org/techniques/AML.T0093) | Prompt Infiltration via Public-Facing Application | Mapped | prevent `prevent.content_hold`; scenarios `RT-154` |
| [AML.T0070](https://atlas.mitre.org/techniques/AML.T0070) | RAG Poisoning | Mapped | prevent `prevent.vector_writers` |
| [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) | Training Data Poisoning | Outside PantherClaw: covered by model security | It happens in model development. |

### Privilege Escalation (AML.TA0012)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | AI Agent Tool Invocation | Mapped | prevent `prevent.grant_scope`, `prevent.mapped_routes`; rules `pc.authority.self_issue`; kinds `behavior.NEW_TOOL`; Hub playbooks `pc.playbook.rogue-sub-agent`, `pc.playbook.rogue-sub-agent-contain`; scenarios `RT-001`, `RT-002`, `RT-019`, `RT-121`, `RT-211`, `RT-212`, `RT-213`, `RT-214`, `RT-223` |
| [AML.T0105](https://atlas.mitre.org/techniques/AML.T0105) | Escape to Host | Mapped | prevent `prevent.sandbox_closure`; scenarios `RT-015` |
| [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) | LLM Jailbreak | No PantherClaw control yet | LLM jailbreak (AML.T0054): it happens inside the model's conversation; PantherClaw decides on the actions that follow, not on the prompt. |
| [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012) | Valid Accounts | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |

### Defense Evasion (AML.TA0007)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0141](https://atlas.mitre.org/techniques/AML.T0141) | AI Service Request Metadata Sanitization | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0111](https://atlas.mitre.org/techniques/AML.T0111) | AI Supply Chain Reputation Inflation | Outside PantherClaw: covered by threat intelligence | It happens before compromise. Inflated stars and downloads live on public registries; the MCP catalog approves by exact match, not by reputation. |
| [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) | AI Supply Chain Rug Pull | Mapped | prevent `prevent.tool_package_review`; rules `pc.tools.drift`; Hub playbooks `pc.playbook.poisoned-mcp-server`, `pc.playbook.poisoned-mcp-server-contain`; scenarios `RT-029` |
| [AML.T0134](https://atlas.mitre.org/techniques/AML.T0134) | AI Targeted Cloaking | Mapped | rules `pc.browser.cloaking`; scenarios `RT-224` |
| [AML.T0140](https://atlas.mitre.org/techniques/AML.T0140) | Centralized AI Service Request Routing | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [AML.T0076](https://atlas.mitre.org/techniques/AML.T0076) | Corrupt AI Model | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0094](https://atlas.mitre.org/techniques/AML.T0094) | Delay Execution of LLM Instructions | No PantherClaw control yet | Delay execution of LLM instructions (AML.T0094): a delayed instruction is only seen when it turns into an action. |
| [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0107](https://atlas.mitre.org/techniques/AML.T0107) | Exploitation for Defense Evasion | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0071](https://atlas.mitre.org/techniques/AML.T0071) | False RAG Entry Injection | Mapped | prevent `prevent.vector_writers` |
| [AML.T0073](https://atlas.mitre.org/techniques/AML.T0073) | Impersonation | Mapped | prevent `prevent.approval_independence`, `prevent.workload_proof`; scenarios `RT-045`, `RT-047`, `RT-050` |
| [AML.T0138](https://atlas.mitre.org/techniques/AML.T0138) | Indicator Removal | Mapped | rules `pc.integrity.evidence_integrity_failed` |
| [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) | LLM Jailbreak | No PantherClaw control yet | LLM jailbreak (AML.T0054): it happens inside the model's conversation; PantherClaw decides on the actions that follow, not on the prompt. |
| [AML.T0068](https://atlas.mitre.org/techniques/AML.T0068) | LLM Prompt Obfuscation | Mapped | prevent `prevent.content_hold`; scenarios `RT-200` |
| [AML.T0067](https://atlas.mitre.org/techniques/AML.T0067) | LLM Trusted Output Components Manipulation | No PantherClaw control yet | LLM trusted output components manipulation (AML.T0067): citations and labels in a model's answer have no PantherClaw control. |
| [AML.T0092](https://atlas.mitre.org/techniques/AML.T0092) | Manipulate User LLM Chat History | No PantherClaw control yet | Manipulate user LLM chat history (AML.T0092): chat history lives in the assistant, not in PantherClaw's evidence. |
| [AML.T0074](https://atlas.mitre.org/techniques/AML.T0074) | Masquerading | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081) | Modify AI Agent Configuration | Mapped | prevent `prevent.agent_config`; rules `pc.agent.config_changed`; scenarios `RT-203` |
| [AML.T0123](https://atlas.mitre.org/techniques/AML.T0123) | Obfuscated Files or Information | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0129](https://atlas.mitre.org/techniques/AML.T0129) | Triggers in Multimodal Inputs | No PantherClaw control yet | Triggers in multimodal inputs (AML.T0129): content signals read text; images and audio have no control yet. |
| [AML.T0097](https://atlas.mitre.org/techniques/AML.T0097) | Virtualization/Sandbox Evasion | Outside PantherClaw: covered by EDR | It needs an endpoint. |

### Credential Access (AML.TA0013)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0098](https://atlas.mitre.org/techniques/AML.T0098) | AI Agent Tool Credential Harvesting | Mapped | kinds `content.secret_format`; scenarios `RT-221` |
| [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) | Credentials from AI Agent Configuration | Mapped | prevent `prevent.agent_config` |
| [AML.T0106](https://atlas.mitre.org/techniques/AML.T0106) | Exploitation for Credential Access | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0090](https://atlas.mitre.org/techniques/AML.T0090) | OS Credential Dumping | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0082](https://atlas.mitre.org/techniques/AML.T0082) | RAG Credential Harvesting | No PantherClaw control yet | RAG credential harvesting (AML.T0082): credentials retrieved from an index never pass a PantherClaw decision. |
| [AML.T0113](https://atlas.mitre.org/techniques/AML.T0113) | Steal Web Session Cookie | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) | Unsecured Credentials | Mapped | prevent `prevent.edge_credential_strip`, `prevent.secret_outbound`; kinds `content.secret_format`; scenarios `RT-004`, `RT-005`, `RT-190`; campaigns `RT-144`, `RT-148`, `RT-149` |

### Discovery (AML.TA0008)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0084](https://atlas.mitre.org/techniques/AML.T0084) | Discover AI Agent Configuration | Mapped (partly) | prevent `prevent.agent_config`<br>AML.T0084.000 not covered<br>AML.T0084.001 not covered<br>AML.T0084.002 not covered<br>AML.T0084.003 not covered |
| [AML.T0133](https://atlas.mitre.org/techniques/AML.T0133) | Discover AI Agent Runtime Capabilities | Mapped | rules `pc.probing.denial_burst`; Hub rules `org.hub.merge_denial_burst`, `org.hub.refund_cap_probing` |
| [AML.T0007](https://atlas.mitre.org/techniques/AML.T0007) | Discover AI Artifacts | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0014](https://atlas.mitre.org/techniques/AML.T0014) | Discover AI Model Family | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0013](https://atlas.mitre.org/techniques/AML.T0013) | Discover AI Model Ontology | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0063](https://atlas.mitre.org/techniques/AML.T0063) | Discover AI Model Outputs | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0062](https://atlas.mitre.org/techniques/AML.T0062) | Discover LLM Hallucinations | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0069](https://atlas.mitre.org/techniques/AML.T0069) | Discover LLM System Information | No PantherClaw control yet | Discover LLM system information (AML.T0069): asking the model about its system prompt never reaches a PantherClaw decision. |
| [AML.T0089](https://atlas.mitre.org/techniques/AML.T0089) | Enterprise Environment Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0075](https://atlas.mitre.org/techniques/AML.T0075) | Enterprise Resource Discovery | Mapped | rules `pc.reads.enumeration` |
| [AML.T0144](https://atlas.mitre.org/techniques/AML.T0144) | Recover AI Model Internals | Outside PantherClaw: covered by model security | It happens in model development. |

### Lateral Movement (AML.TA0015)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | AI Agent Tool Invocation | Mapped | prevent `prevent.grant_scope`, `prevent.mapped_routes`; rules `pc.authority.self_issue`; kinds `behavior.NEW_TOOL`; Hub playbooks `pc.playbook.rogue-sub-agent`, `pc.playbook.rogue-sub-agent-contain`; scenarios `RT-001`, `RT-002`, `RT-019`, `RT-121`, `RT-211`, `RT-212`, `RT-213`, `RT-214`, `RT-223` |
| [AML.T0122](https://atlas.mitre.org/techniques/AML.T0122) | Exploitation of Remote Services | Outside PantherClaw: covered by network security | It needs a network. |
| [AML.T0143](https://atlas.mitre.org/techniques/AML.T0143) | LLM Prompt Propagation | No PantherClaw control yet | LLM prompt propagation (AML.T0143): instructions carried onward between stores and agents have no control of their own yet. |
| [AML.T0052](https://atlas.mitre.org/techniques/AML.T0052) | Phishing | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [AML.T0091](https://atlas.mitre.org/techniques/AML.T0091) | Use Alternate Authentication Material | Mapped (partly) | AML.T0091.000: prevent `prevent.mcp_token_binding`, `prevent.workload_proof`; rules `pc.identity.key_new_network`, `pc.identity.workload_proof_refused`, `pc.integrity.effect_without_receipt`; Hub playbooks `pc.playbook.leaked-key`; scenarios `RT-012`, `RT-013`, `RT-032`, `RT-036`, `RT-048`, `RT-151`, `RT-152`, `RT-153`, `RT-202`, `RT-260`<br>AML.T0091.001 not covered |
| [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012) | Valid Accounts | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |

### Collection (AML.TA0009)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0035](https://atlas.mitre.org/techniques/AML.T0035) | AI Artifact Collection | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0126](https://atlas.mitre.org/techniques/AML.T0126) | Automated Collection | Mapped | prevent `prevent.read_limits`; rules `pc.reads.enumeration` |
| [AML.T0127](https://atlas.mitre.org/techniques/AML.T0127) | Data Staged | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0085](https://atlas.mitre.org/techniques/AML.T0085) | Data from AI Services | No PantherClaw control yet | Data from AI services (AML.T0085): collection through an organization's AI services has no PantherClaw control yet. |
| [AML.T0036](https://atlas.mitre.org/techniques/AML.T0036) | Data from Information Repositories | Mapped | prevent `prevent.grant_scope`; scenarios `RT-042`, `RT-043` |
| [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037) | Data from Local System | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0135](https://atlas.mitre.org/techniques/AML.T0135) | Outputs from AI Models | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0144](https://atlas.mitre.org/techniques/AML.T0144) | Recover AI Model Internals | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0137](https://atlas.mitre.org/techniques/AML.T0137) | Training Data Information from AI Models | Outside PantherClaw: covered by model security | It happens in model development. |

### Command and Control (AML.TA0014)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0108](https://atlas.mitre.org/techniques/AML.T0108) | AI Agent | No PantherClaw control yet | AI agent (AML.T0108): an agent used as a command channel beyond its grants has no PantherClaw control yet. |
| [AML.T0120](https://atlas.mitre.org/techniques/AML.T0120) | AI Artifact Repository | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0096](https://atlas.mitre.org/techniques/AML.T0096) | AI Service API | No PantherClaw control yet | AI service API (AML.T0096): command and control over an AI provider's API has no PantherClaw control. |
| [AML.T0114](https://atlas.mitre.org/techniques/AML.T0114) | AI Service Web Interface | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0072](https://atlas.mitre.org/techniques/AML.T0072) | Cyber Communication Channel | Mapped | prevent `prevent.sandbox_closure` |

### Exfiltration (AML.TA0010)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) | Exfiltration via AI Agent Tool Invocation | Mapped | prevent `prevent.data_flow_hold`, `prevent.destination_grant`, `prevent.secret_outbound`; rules `pc.drift.behavior`, `pc.sequence.read_then_disclose`; kinds `behavior.NEW_DESTINATION`; Hub rules `org.hub.external_disclosure_repeat`, `org.hub.secret_outbound_refused`; Hub playbooks `pc.playbook.leaked-key`; scenarios `RT-009`, `RT-010`, `RT-011`, `RT-046`, `RT-120`, `RT-196`; campaigns `RT-141`, `RT-145`, `RT-149` |
| [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024) | Exfiltration via AI Inference API | Mapped | scenarios `RT-191`, `RT-193` |
| [AML.T0136](https://atlas.mitre.org/techniques/AML.T0136) | Exfiltration via AI User Interface | No PantherClaw control yet | Exfiltration via AI user interface (AML.T0136): disclosure in an assistant's own answers has no PantherClaw control. |
| [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) | Exfiltration via Cyber Means | Mapped | prevent `prevent.sandbox_closure` |
| [AML.T0077](https://atlas.mitre.org/techniques/AML.T0077) | LLM Response Rendering | No PantherClaw control yet | LLM response rendering (AML.T0077): rendering of model output in a client has no PantherClaw control. |

### Impact (AML.TA0011)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [AML.T0130](https://atlas.mitre.org/techniques/AML.T0130) | AI Agent Response Biasing | No PantherClaw control yet | AI agent response biasing (AML.T0130): bias in what an assistant recommends never reaches a PantherClaw decision. |
| [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034) | Cost Harvesting | Mapped (partly) | prevent `prevent.token_caps`; scenarios `RT-192`, `RT-197`<br>AML.T0034.002: kinds `behavior.VOLUME_SPIKE`<br>AML.T0034.000 not covered<br>AML.T0034.001 not covered |
| [AML.T0101](https://atlas.mitre.org/techniques/AML.T0101) | Data Destruction via AI Agent Tool Invocation | Mapped | prevent `prevent.grant_scope` |
| [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029) | Denial of AI Service | Mapped | prevent `prevent.token_caps`; scenarios `RT-194` |
| [AML.T0031](https://atlas.mitre.org/techniques/AML.T0031) | Erode AI Model Integrity | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0059](https://atlas.mitre.org/techniques/AML.T0059) | Erode Dataset Integrity | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model | Outside PantherClaw: covered by model security | It happens in model development. |
| [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) | External Harms | Mapped (partly) | AML.T0048.000: prevent `prevent.budgets`; rules `pc.budget.splitting`; kinds `behavior.SPEND_SPIKE`; Hub rules `org.hub.refund_burst`, `org.hub.refund_cap_probing`; scenarios `RT-026`, `RT-027`, `RT-040`, `RT-041`<br>AML.T0048.001 not covered<br>AML.T0048.002 not covered<br>AML.T0048.003 not covered<br>AML.T0048.004 not covered |
| [AML.T0112](https://atlas.mitre.org/techniques/AML.T0112) | Machine Compromise | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [AML.T0046](https://atlas.mitre.org/techniques/AML.T0046) | Spamming AI System with Chaff Data | Outside PantherClaw: covered by model security | It happens in model development. |

## MITRE ATT&CK Enterprise

### Reconnaissance (TA0043)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1595](https://attack.mitre.org/techniques/T1595) | Active Scanning | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1592](https://attack.mitre.org/techniques/T1592) | Gather Victim Host Information | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1589](https://attack.mitre.org/techniques/T1589) | Gather Victim Identity Information | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1590](https://attack.mitre.org/techniques/T1590) | Gather Victim Network Information | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1591](https://attack.mitre.org/techniques/T1591) | Gather Victim Org Information | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1598](https://attack.mitre.org/techniques/T1598) | Phishing for Information | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [T1682](https://attack.mitre.org/techniques/T1682) | Query Public AI Services | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1597](https://attack.mitre.org/techniques/T1597) | Search Closed Sources | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1596](https://attack.mitre.org/techniques/T1596) | Search Open Technical Databases | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1593](https://attack.mitre.org/techniques/T1593) | Search Open Websites/Domains | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1681](https://attack.mitre.org/techniques/T1681) | Search Threat Vendor Data | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1594](https://attack.mitre.org/techniques/T1594) | Search Victim-Owned Websites | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |

### Resource Development (TA0042)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1650](https://attack.mitre.org/techniques/T1650) | Acquire Access | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1583](https://attack.mitre.org/techniques/T1583) | Acquire Infrastructure | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1586](https://attack.mitre.org/techniques/T1586) | Compromise Accounts | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1584](https://attack.mitre.org/techniques/T1584) | Compromise Infrastructure | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1587](https://attack.mitre.org/techniques/T1587) | Develop Capabilities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1585](https://attack.mitre.org/techniques/T1585) | Establish Accounts | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1683](https://attack.mitre.org/techniques/T1683) | Generate Content | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1588](https://attack.mitre.org/techniques/T1588) | Obtain Capabilities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |
| [T1608](https://attack.mitre.org/techniques/T1608) | Stage Capabilities | Outside PantherClaw: covered by threat intelligence | It happens before compromise. |

### Initial Access (TA0001)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1659](https://attack.mitre.org/techniques/T1659) | Content Injection | Outside PantherClaw: covered by network security | It needs a network. |
| [T1189](https://attack.mitre.org/techniques/T1189) | Drive-by Compromise | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1190](https://attack.mitre.org/techniques/T1190) | Exploit Public-Facing Application | Outside PantherClaw: covered by network security | It needs a network. |
| [T1133](https://attack.mitre.org/techniques/T1133) | External Remote Services | Outside PantherClaw: covered by network security | It needs a network. |
| [T1200](https://attack.mitre.org/techniques/T1200) | Hardware Additions | Outside PantherClaw: covered by physical security | It needs physical access. |
| [T1566](https://attack.mitre.org/techniques/T1566) | Phishing | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [T1091](https://attack.mitre.org/techniques/T1091) | Replication Through Removable Media | Outside PantherClaw: covered by physical security | It needs physical access. |
| [T1195](https://attack.mitre.org/techniques/T1195) | Supply Chain Compromise | Mapped (partly) | T1195.001: prevent `prevent.tool_package_review`<br>T1195.002 not covered<br>T1195.003 not covered |
| [T1199](https://attack.mitre.org/techniques/T1199) | Trusted Relationship | Mapped | scenarios `RT-217` |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | Mapped (partly) | T1078.001: scenarios `RT-216`<br>T1078.002 not covered<br>T1078.003 not covered<br>T1078.004 not covered |
| [T1669](https://attack.mitre.org/techniques/T1669) | Wi-Fi Networks | Outside PantherClaw: covered by network security | It needs a network. |

### Execution (TA0002)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1197](https://attack.mitre.org/techniques/T1197) | BITS Jobs | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1651](https://attack.mitre.org/techniques/T1651) | Cloud Administration Command | Mapped | prevent `prevent.cloud_admin_command`; scenarios `RT-228` |
| [T1059](https://attack.mitre.org/techniques/T1059) | Command and Scripting Interpreter | Mapped (partly) | T1059.004: Hub rules `org.hub.held_merge_then_shell`, `org.hub.shell_merge_attempt`; scenarios `RT-003`<br>T1059.001 not covered<br>T1059.002 not covered<br>T1059.003 not covered<br>T1059.005 not covered<br>T1059.006 not covered<br>T1059.007 not covered<br>T1059.008 not covered<br>T1059.009 not covered<br>T1059.010 not covered<br>T1059.011 not covered<br>T1059.012 not covered<br>T1059.013 not covered |
| [T1609](https://attack.mitre.org/techniques/T1609) | Container Administration Command | Mapped | scenarios `RT-215` |
| [T1610](https://attack.mitre.org/techniques/T1610) | Deploy Container | Mapped | prevent `prevent.kubernetes_admission`; scenarios `RT-215` |
| [T1699](https://attack.mitre.org/techniques/T1699) | Direct Prompt Injection | No PantherClaw control yet | Direct prompt injection (T1699): it happens in the model's conversation; PantherClaw decides on the actions that follow. |
| [T1675](https://attack.mitre.org/techniques/T1675) | ESXi Administration Command | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1203](https://attack.mitre.org/techniques/T1203) | Exploitation for Client Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1574](https://attack.mitre.org/techniques/T1574) | Hijack Execution Flow | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1698](https://attack.mitre.org/techniques/T1698) | Indirect Prompt Injection | Mapped | prevent `prevent.content_hold`; rules `pc.tools.description_injection`; kinds `content.injection_phrase`; Hub playbooks `pc.playbook.poisoned-mcp-server`; scenarios `RT-158`, `RT-159`, `RT-163`, `RT-200`; campaigns `RT-140`, `RT-141`, `RT-142`, `RT-143`, `RT-144`, `RT-145`, `RT-146`, `RT-147` |
| [T1674](https://attack.mitre.org/techniques/T1674) | Input Injection | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1559](https://attack.mitre.org/techniques/T1559) | Inter-Process Communication | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1106](https://attack.mitre.org/techniques/T1106) | Native API | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1677](https://attack.mitre.org/techniques/T1677) | Poisoned Pipeline Execution | Mapped | prevent `prevent.consequence_rules`; scenarios `RT-017` |
| [T1053](https://attack.mitre.org/techniques/T1053) | Scheduled Task/Job | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1648](https://attack.mitre.org/techniques/T1648) | Serverless Execution | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1129](https://attack.mitre.org/techniques/T1129) | Shared Modules | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1072](https://attack.mitre.org/techniques/T1072) | Software Deployment Tools | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1569](https://attack.mitre.org/techniques/T1569) | System Services | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1127](https://attack.mitre.org/techniques/T1127) | Trusted Developer Utilities Proxy Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1204](https://attack.mitre.org/techniques/T1204) | User Execution | Outside PantherClaw: covered by security awareness | It needs a person. |
| [T1047](https://attack.mitre.org/techniques/T1047) | Windows Management Instrumentation | Outside PantherClaw: covered by EDR | It needs an endpoint. |

### Persistence (TA0003)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1098](https://attack.mitre.org/techniques/T1098) | Account Manipulation | Mapped (partly) | rules `pc.authority.self_issue`; Hub playbooks `pc.playbook.rogue-sub-agent`, `pc.playbook.rogue-sub-agent-contain`<br>T1098.001 not covered<br>T1098.002 not covered<br>T1098.003 not covered<br>T1098.004 not covered<br>T1098.005 not covered<br>T1098.006 not covered<br>T1098.007 not covered |
| [T1197](https://attack.mitre.org/techniques/T1197) | BITS Jobs | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1547](https://attack.mitre.org/techniques/T1547) | Boot or Logon Autostart Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1037](https://attack.mitre.org/techniques/T1037) | Boot or Logon Initialization Scripts | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1671](https://attack.mitre.org/techniques/T1671) | Cloud Application Integration | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1554](https://attack.mitre.org/techniques/T1554) | Compromise Host Software Binary | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1136](https://attack.mitre.org/techniques/T1136) | Create Account | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1543](https://attack.mitre.org/techniques/T1543) | Create or Modify System Process | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1546](https://attack.mitre.org/techniques/T1546) | Event Triggered Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1668](https://attack.mitre.org/techniques/T1668) | Exclusive Control | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1133](https://attack.mitre.org/techniques/T1133) | External Remote Services | Outside PantherClaw: covered by network security | It needs a network. |
| [T1525](https://attack.mitre.org/techniques/T1525) | Implant Internal Image | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1556](https://attack.mitre.org/techniques/T1556) | Modify Authentication Process | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1112](https://attack.mitre.org/techniques/T1112) | Modify Registry | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1137](https://attack.mitre.org/techniques/T1137) | Office Application Startup | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1653](https://attack.mitre.org/techniques/T1653) | Power Settings | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1542](https://attack.mitre.org/techniques/T1542) | Pre-OS Boot | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1053](https://attack.mitre.org/techniques/T1053) | Scheduled Task/Job | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1505](https://attack.mitre.org/techniques/T1505) | Server Software Component | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1176](https://attack.mitre.org/techniques/T1176) | Software Extensions | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1205](https://attack.mitre.org/techniques/T1205) | Traffic Signaling | Outside PantherClaw: covered by network security | It needs a network. |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | Mapped (partly) | T1078.001: scenarios `RT-216`<br>T1078.002 not covered<br>T1078.003 not covered<br>T1078.004 not covered |

### Privilege Escalation (TA0004)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1548](https://attack.mitre.org/techniques/T1548) | Abuse Elevation Control Mechanism | Mapped (partly) | prevent `prevent.approval_independence`; rules `pc.approvals.variant_shopping`, `pc.authority.self_approve`; Hub playbooks `pc.playbook.rogue-sub-agent`; scenarios `RT-008`, `RT-018`, `RT-024`, `RT-025`, `RT-045`<br>T1548.001 not covered<br>T1548.002 not covered<br>T1548.003 not covered<br>T1548.004 not covered<br>T1548.005 not covered<br>T1548.006 not covered |
| [T1134](https://attack.mitre.org/techniques/T1134) | Access Token Manipulation | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1098](https://attack.mitre.org/techniques/T1098) | Account Manipulation | Mapped (partly) | rules `pc.authority.self_issue`; Hub playbooks `pc.playbook.rogue-sub-agent`, `pc.playbook.rogue-sub-agent-contain`<br>T1098.001 not covered<br>T1098.002 not covered<br>T1098.003 not covered<br>T1098.004 not covered<br>T1098.005 not covered<br>T1098.006 not covered<br>T1098.007 not covered |
| [T1547](https://attack.mitre.org/techniques/T1547) | Boot or Logon Autostart Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1037](https://attack.mitre.org/techniques/T1037) | Boot or Logon Initialization Scripts | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1543](https://attack.mitre.org/techniques/T1543) | Create or Modify System Process | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1484](https://attack.mitre.org/techniques/T1484) | Domain or Tenant Policy Modification | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1611](https://attack.mitre.org/techniques/T1611) | Escape to Host | Mapped | prevent `prevent.sandbox_closure`; scenarios `RT-015`, `RT-215` |
| [T1546](https://attack.mitre.org/techniques/T1546) | Event Triggered Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1068](https://attack.mitre.org/techniques/T1068) | Exploitation for Privilege Escalation | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1055](https://attack.mitre.org/techniques/T1055) | Process Injection | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1053](https://attack.mitre.org/techniques/T1053) | Scheduled Task/Job | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | Mapped (partly) | T1078.001: scenarios `RT-216`<br>T1078.002 not covered<br>T1078.003 not covered<br>T1078.004 not covered |

### Stealth (TA0005)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1134](https://attack.mitre.org/techniques/T1134) | Access Token Manipulation | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1696](https://attack.mitre.org/techniques/T1696) | Anti-Automation Evasion | Mapped (partly) | T1696.001: prevent `prevent.browser_secret_fields`<br>T1696.002 not covered |
| [T1197](https://attack.mitre.org/techniques/T1197) | BITS Jobs | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1612](https://attack.mitre.org/techniques/T1612) | Build Image on Host | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1622](https://attack.mitre.org/techniques/T1622) | Debugger Evasion | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1678](https://attack.mitre.org/techniques/T1678) | Delay Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1140](https://attack.mitre.org/techniques/T1140) | Deobfuscate/Decode Files or Information | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1006](https://attack.mitre.org/techniques/T1006) | Direct Volume Access | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1480](https://attack.mitre.org/techniques/T1480) | Execution Guardrails | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1211](https://attack.mitre.org/techniques/T1211) | Exploitation for Stealth | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1564](https://attack.mitre.org/techniques/T1564) | Hide Artifacts | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1574](https://attack.mitre.org/techniques/T1574) | Hijack Execution Flow | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1070](https://attack.mitre.org/techniques/T1070) | Indicator Removal | Mapped (partly) | rules `pc.integrity.evidence_integrity_failed`<br>T1070.001 not covered<br>T1070.002 not covered<br>T1070.003 not covered<br>T1070.004 not covered<br>T1070.005 not covered<br>T1070.006 not covered<br>T1070.007 not covered<br>T1070.008 not covered<br>T1070.009 not covered<br>T1070.010 not covered |
| [T1202](https://attack.mitre.org/techniques/T1202) | Indirect Command Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1036](https://attack.mitre.org/techniques/T1036) | Masquerading | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1027](https://attack.mitre.org/techniques/T1027) | Obfuscated Files or Information | Mapped (partly) | scenarios `RT-197`<br>T1027.001 not covered<br>T1027.002 not covered<br>T1027.003 not covered<br>T1027.004 not covered<br>T1027.005 not covered<br>T1027.006 not covered<br>T1027.007 not covered<br>T1027.008 not covered<br>T1027.009 not covered<br>T1027.010 not covered<br>T1027.011 not covered<br>T1027.012 not covered<br>T1027.013 not covered<br>T1027.014 not covered<br>T1027.015 not covered<br>T1027.016 not covered<br>T1027.017 not covered<br>T1027.018 not covered |
| [T1542](https://attack.mitre.org/techniques/T1542) | Pre-OS Boot | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1055](https://attack.mitre.org/techniques/T1055) | Process Injection | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1620](https://attack.mitre.org/techniques/T1620) | Reflective Code Loading | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1014](https://attack.mitre.org/techniques/T1014) | Rootkit | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1679](https://attack.mitre.org/techniques/T1679) | Selective Exclusion | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1684](https://attack.mitre.org/techniques/T1684) | Social Engineering | Outside PantherClaw: covered by security awareness | It needs a person. |
| [T1218](https://attack.mitre.org/techniques/T1218) | System Binary Proxy Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1216](https://attack.mitre.org/techniques/T1216) | System Script Proxy Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1221](https://attack.mitre.org/techniques/T1221) | Template Injection | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1205](https://attack.mitre.org/techniques/T1205) | Traffic Signaling | Outside PantherClaw: covered by network security | It needs a network. |
| [T1127](https://attack.mitre.org/techniques/T1127) | Trusted Developer Utilities Proxy Execution | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1535](https://attack.mitre.org/techniques/T1535) | Unused/Unsupported Cloud Regions | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1078](https://attack.mitre.org/techniques/T1078) | Valid Accounts | Mapped (partly) | T1078.001: scenarios `RT-216`<br>T1078.002 not covered<br>T1078.003 not covered<br>T1078.004 not covered |
| [T1497](https://attack.mitre.org/techniques/T1497) | Virtualization/Sandbox Evasion | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1220](https://attack.mitre.org/techniques/T1220) | XSL Script Processing | Outside PantherClaw: covered by EDR | It needs an endpoint. |

### Defense Impairment (TA0112)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1686](https://attack.mitre.org/techniques/T1686) | Disable or Modify System Firewall | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1685](https://attack.mitre.org/techniques/T1685) | Disable or Modify Tools | Mapped (partly) | rules `pc.coverage.lost`; scenarios `RT-016`, `RT-218`<br>T1685.001 not covered<br>T1685.002 not covered<br>T1685.003 not covered<br>T1685.004 not covered<br>T1685.005 not covered<br>T1685.006 not covered<br>T1685.007 not covered |
| [T1484](https://attack.mitre.org/techniques/T1484) | Domain or Tenant Policy Modification | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1689](https://attack.mitre.org/techniques/T1689) | Downgrade Attack | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1687](https://attack.mitre.org/techniques/T1687) | Exploitation for Defense Impairment | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1222](https://attack.mitre.org/techniques/T1222) | File and Directory Permissions Modification | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1556](https://attack.mitre.org/techniques/T1556) | Modify Authentication Process | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1578](https://attack.mitre.org/techniques/T1578) | Modify Cloud Compute Infrastructure | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1666](https://attack.mitre.org/techniques/T1666) | Modify Cloud Resource Hierarchy | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1112](https://attack.mitre.org/techniques/T1112) | Modify Registry | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1601](https://attack.mitre.org/techniques/T1601) | Modify System Image | Outside PantherClaw: covered by network security | It needs a network. |
| [T1599](https://attack.mitre.org/techniques/T1599) | Network Boundary Bridging | Outside PantherClaw: covered by network security | It needs a network. |
| [T1647](https://attack.mitre.org/techniques/T1647) | Plist File Modification | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1690](https://attack.mitre.org/techniques/T1690) | Prevent Command History Logging | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1207](https://attack.mitre.org/techniques/T1207) | Rogue Domain Controller | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1688](https://attack.mitre.org/techniques/T1688) | Safe Mode Boot | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1553](https://attack.mitre.org/techniques/T1553) | Subvert Trust Controls | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1600](https://attack.mitre.org/techniques/T1600) | Weaken Encryption | Outside PantherClaw: covered by network security | It needs a network. |

### Credential Access (TA0006)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1557](https://attack.mitre.org/techniques/T1557) | Adversary-in-the-Middle | Outside PantherClaw: covered by network security | It needs a network. |
| [T1110](https://attack.mitre.org/techniques/T1110) | Brute Force | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1555](https://attack.mitre.org/techniques/T1555) | Credentials from Password Stores | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1212](https://attack.mitre.org/techniques/T1212) | Exploitation for Credential Access | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1187](https://attack.mitre.org/techniques/T1187) | Forced Authentication | Outside PantherClaw: covered by network security | It needs a network. |
| [T1606](https://attack.mitre.org/techniques/T1606) | Forge Web Credentials | Mapped (partly) | prevent `prevent.idp_assertion`; scenarios `RT-150`<br>T1606.001 not covered<br>T1606.002 not covered |
| [T1056](https://attack.mitre.org/techniques/T1056) | Input Capture | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1556](https://attack.mitre.org/techniques/T1556) | Modify Authentication Process | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1111](https://attack.mitre.org/techniques/T1111) | Multi-Factor Authentication Interception | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1621](https://attack.mitre.org/techniques/T1621) | Multi-Factor Authentication Request Generation | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1040](https://attack.mitre.org/techniques/T1040) | Network Sniffing | Outside PantherClaw: covered by network security | It needs a network. |
| [T1003](https://attack.mitre.org/techniques/T1003) | OS Credential Dumping | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1528](https://attack.mitre.org/techniques/T1528) | Steal Application Access Token | No PantherClaw control yet | Steal application access token (T1528): theft of a token happens where it is stored; PantherClaw acts only on its later use. |
| [T1697](https://attack.mitre.org/techniques/T1697) | Steal Application Specific Passwords | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1539](https://attack.mitre.org/techniques/T1539) | Steal Web Session Cookie | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1649](https://attack.mitre.org/techniques/T1649) | Steal or Forge Authentication Certificates | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1558](https://attack.mitre.org/techniques/T1558) | Steal or Forge Kerberos Tickets | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1552](https://attack.mitre.org/techniques/T1552) | Unsecured Credentials | Mapped (partly) | kinds `content.secret_format`; Hub rules `org.hub.secret_outbound_refused`; Hub playbooks `pc.playbook.leaked-key`<br>T1552.001: prevent `prevent.edge_credential_strip`, `prevent.secret_outbound`; scenarios `RT-004`, `RT-190`, `RT-193`; campaigns `RT-144`, `RT-148`, `RT-149`<br>T1552.004: prevent `prevent.sandbox_closure`, `prevent.secret_outbound`; scenarios `RT-005`<br>T1552.005: prevent `prevent.egress_guard`, `prevent.kubernetes_closure`, `prevent.sandbox_closure`; scenarios `RT-015`, `RT-031`<br>T1552.007: scenarios `RT-217`<br>T1552.002 not covered<br>T1552.003 not covered<br>T1552.006 not covered<br>T1552.008 not covered |

### Discovery (TA0007)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1087](https://attack.mitre.org/techniques/T1087) | Account Discovery | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1010](https://attack.mitre.org/techniques/T1010) | Application Window Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1217](https://attack.mitre.org/techniques/T1217) | Browser Information Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1580](https://attack.mitre.org/techniques/T1580) | Cloud Infrastructure Discovery | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1538](https://attack.mitre.org/techniques/T1538) | Cloud Service Dashboard | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1526](https://attack.mitre.org/techniques/T1526) | Cloud Service Discovery | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1619](https://attack.mitre.org/techniques/T1619) | Cloud Storage Object Discovery | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1613](https://attack.mitre.org/techniques/T1613) | Container and Resource Discovery | Mapped | prevent `prevent.kubernetes_closure` |
| [T1622](https://attack.mitre.org/techniques/T1622) | Debugger Evasion | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1652](https://attack.mitre.org/techniques/T1652) | Device Driver Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1482](https://attack.mitre.org/techniques/T1482) | Domain Trust Discovery | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1083](https://attack.mitre.org/techniques/T1083) | File and Directory Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1615](https://attack.mitre.org/techniques/T1615) | Group Policy Discovery | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1680](https://attack.mitre.org/techniques/T1680) | Local Storage Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1654](https://attack.mitre.org/techniques/T1654) | Log Enumeration | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1046](https://attack.mitre.org/techniques/T1046) | Network Service Discovery | Outside PantherClaw: covered by network security | It needs a network. |
| [T1135](https://attack.mitre.org/techniques/T1135) | Network Share Discovery | Outside PantherClaw: covered by network security | It needs a network. |
| [T1040](https://attack.mitre.org/techniques/T1040) | Network Sniffing | Outside PantherClaw: covered by network security | It needs a network. |
| [T1201](https://attack.mitre.org/techniques/T1201) | Password Policy Discovery | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1120](https://attack.mitre.org/techniques/T1120) | Peripheral Device Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1069](https://attack.mitre.org/techniques/T1069) | Permission Groups Discovery | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1057](https://attack.mitre.org/techniques/T1057) | Process Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1012](https://attack.mitre.org/techniques/T1012) | Query Registry | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1018](https://attack.mitre.org/techniques/T1018) | Remote System Discovery | Outside PantherClaw: covered by network security | It needs a network. |
| [T1518](https://attack.mitre.org/techniques/T1518) | Software Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1082](https://attack.mitre.org/techniques/T1082) | System Information Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1614](https://attack.mitre.org/techniques/T1614) | System Location Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1016](https://attack.mitre.org/techniques/T1016) | System Network Configuration Discovery | Outside PantherClaw: covered by network security | It needs a network. |
| [T1049](https://attack.mitre.org/techniques/T1049) | System Network Connections Discovery | Outside PantherClaw: covered by network security | It needs a network. |
| [T1033](https://attack.mitre.org/techniques/T1033) | System Owner/User Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1007](https://attack.mitre.org/techniques/T1007) | System Service Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1124](https://attack.mitre.org/techniques/T1124) | System Time Discovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1673](https://attack.mitre.org/techniques/T1673) | Virtual Machine Discovery | Outside PantherClaw: covered by cloud security | It needs cloud infrastructure. |
| [T1497](https://attack.mitre.org/techniques/T1497) | Virtualization/Sandbox Evasion | Outside PantherClaw: covered by EDR | It needs an endpoint. |

### Lateral Movement (TA0008)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1210](https://attack.mitre.org/techniques/T1210) | Exploitation of Remote Services | Outside PantherClaw: covered by network security | It needs a network. |
| [T1534](https://attack.mitre.org/techniques/T1534) | Internal Spearphishing | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [T1570](https://attack.mitre.org/techniques/T1570) | Lateral Tool Transfer | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1563](https://attack.mitre.org/techniques/T1563) | Remote Service Session Hijacking | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1021](https://attack.mitre.org/techniques/T1021) | Remote Services | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1091](https://attack.mitre.org/techniques/T1091) | Replication Through Removable Media | Outside PantherClaw: covered by physical security | It needs physical access. |
| [T1072](https://attack.mitre.org/techniques/T1072) | Software Deployment Tools | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1080](https://attack.mitre.org/techniques/T1080) | Taint Shared Content | No PantherClaw control yet | Taint shared content (T1080): granted writes to a shared repository are allowed; PantherClaw does not judge their content. |
| [T1550](https://attack.mitre.org/techniques/T1550) | Use Alternate Authentication Material | Mapped (partly) | T1550.001: prevent `prevent.mcp_token_binding`, `prevent.workload_proof`; rules `pc.identity.key_new_network`, `pc.identity.workload_proof_refused`, `pc.integrity.effect_without_receipt`; Hub playbooks `pc.playbook.leaked-key`; scenarios `RT-012`, `RT-013`, `RT-032`, `RT-036`, `RT-048`, `RT-151`, `RT-152`, `RT-153`, `RT-202`, `RT-260`<br>T1550.002 not covered<br>T1550.003 not covered<br>T1550.004 not covered |

### Collection (TA0009)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1557](https://attack.mitre.org/techniques/T1557) | Adversary-in-the-Middle | Outside PantherClaw: covered by network security | It needs a network. |
| [T1560](https://attack.mitre.org/techniques/T1560) | Archive Collected Data | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1123](https://attack.mitre.org/techniques/T1123) | Audio Capture | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1119](https://attack.mitre.org/techniques/T1119) | Automated Collection | Mapped | prevent `prevent.read_limits`; rules `pc.reads.enumeration` |
| [T1185](https://attack.mitre.org/techniques/T1185) | Browser Session Hijacking | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1115](https://attack.mitre.org/techniques/T1115) | Clipboard Data | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1074](https://attack.mitre.org/techniques/T1074) | Data Staged | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1530](https://attack.mitre.org/techniques/T1530) | Data from Cloud Storage | Mapped | rules `pc.reads.enumeration` |
| [T1602](https://attack.mitre.org/techniques/T1602) | Data from Configuration Repository | Outside PantherClaw: covered by network security | It needs a network. |
| [T1213](https://attack.mitre.org/techniques/T1213) | Data from Information Repositories | Mapped (partly) | prevent `prevent.grant_scope`<br>T1213.006: prevent `prevent.query_scope`; scenarios `RT-042`, `RT-043`<br>T1213.001 not covered<br>T1213.002 not covered<br>T1213.003 not covered<br>T1213.004 not covered<br>T1213.005 not covered |
| [T1005](https://attack.mitre.org/techniques/T1005) | Data from Local System | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1039](https://attack.mitre.org/techniques/T1039) | Data from Network Shared Drive | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1025](https://attack.mitre.org/techniques/T1025) | Data from Removable Media | Outside PantherClaw: covered by physical security | It needs physical access. |
| [T1114](https://attack.mitre.org/techniques/T1114) | Email Collection | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [T1056](https://attack.mitre.org/techniques/T1056) | Input Capture | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1113](https://attack.mitre.org/techniques/T1113) | Screen Capture | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1125](https://attack.mitre.org/techniques/T1125) | Video Capture | Outside PantherClaw: covered by EDR | It needs an endpoint. |

### Command and Control (TA0011)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1071](https://attack.mitre.org/techniques/T1071) | Application Layer Protocol | Mapped (partly) | T1071.004: prevent `prevent.sandbox_closure`; scenarios `RT-014`<br>T1071.001 not covered<br>T1071.002 not covered<br>T1071.003 not covered<br>T1071.005 not covered |
| [T1092](https://attack.mitre.org/techniques/T1092) | Communication Through Removable Media | Outside PantherClaw: covered by physical security | It needs physical access. |
| [T1659](https://attack.mitre.org/techniques/T1659) | Content Injection | Outside PantherClaw: covered by network security | It needs a network. |
| [T1132](https://attack.mitre.org/techniques/T1132) | Data Encoding | Outside PantherClaw: covered by network security | It needs a network. |
| [T1001](https://attack.mitre.org/techniques/T1001) | Data Obfuscation | Outside PantherClaw: covered by network security | It needs a network. |
| [T1568](https://attack.mitre.org/techniques/T1568) | Dynamic Resolution | Outside PantherClaw: covered by network security | It needs a network. |
| [T1573](https://attack.mitre.org/techniques/T1573) | Encrypted Channel | Outside PantherClaw: covered by network security | It needs a network. |
| [T1008](https://attack.mitre.org/techniques/T1008) | Fallback Channels | Outside PantherClaw: covered by network security | It needs a network. |
| [T1665](https://attack.mitre.org/techniques/T1665) | Hide Infrastructure | Outside PantherClaw: covered by network security | It needs a network. |
| [T1105](https://attack.mitre.org/techniques/T1105) | Ingress Tool Transfer | Mapped | prevent `prevent.sandbox_closure` |
| [T1104](https://attack.mitre.org/techniques/T1104) | Multi-Stage Channels | Outside PantherClaw: covered by network security | It needs a network. |
| [T1095](https://attack.mitre.org/techniques/T1095) | Non-Application Layer Protocol | Mapped | prevent `prevent.sandbox_closure` |
| [T1571](https://attack.mitre.org/techniques/T1571) | Non-Standard Port | Outside PantherClaw: covered by network security | It needs a network. |
| [T1572](https://attack.mitre.org/techniques/T1572) | Protocol Tunneling | Mapped | prevent `prevent.sandbox_closure` |
| [T1090](https://attack.mitre.org/techniques/T1090) | Proxy | Mapped (partly) | prevent `prevent.sandbox_closure`<br>T1090.001 not covered<br>T1090.002 not covered<br>T1090.003 not covered<br>T1090.004 not covered |
| [T1219](https://attack.mitre.org/techniques/T1219) | Remote Access Tools | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1205](https://attack.mitre.org/techniques/T1205) | Traffic Signaling | Outside PantherClaw: covered by network security | It needs a network. |
| [T1102](https://attack.mitre.org/techniques/T1102) | Web Service | Outside PantherClaw: covered by network security | It needs a network. |

### Exfiltration (TA0010)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1700](https://attack.mitre.org/techniques/T1700) | AI-Enabled Exfiltration | Mapped | prevent `prevent.data_flow_hold`, `prevent.destination_grant`; rules `pc.sequence.read_then_disclose`; campaigns `RT-141`, `RT-149` |
| [T1020](https://attack.mitre.org/techniques/T1020) | Automated Exfiltration | Mapped (partly) | rules `pc.exfil.scheduled_sends`<br>T1020.001 not covered |
| [T1030](https://attack.mitre.org/techniques/T1030) | Data Transfer Size Limits | Outside PantherClaw: covered by network security | It needs a network. |
| [T1048](https://attack.mitre.org/techniques/T1048) | Exfiltration Over Alternative Protocol | Mapped (partly) | prevent `prevent.sandbox_closure`<br>T1048.001 not covered<br>T1048.002 not covered<br>T1048.003 not covered |
| [T1041](https://attack.mitre.org/techniques/T1041) | Exfiltration Over C2 Channel | Mapped | prevent `prevent.sandbox_closure` |
| [T1011](https://attack.mitre.org/techniques/T1011) | Exfiltration Over Other Network Medium | Outside PantherClaw: covered by network security | It needs a network. |
| [T1052](https://attack.mitre.org/techniques/T1052) | Exfiltration Over Physical Medium | Outside PantherClaw: covered by physical security | It needs physical access. |
| [T1567](https://attack.mitre.org/techniques/T1567) | Exfiltration Over Web Service | Mapped (partly) | prevent `prevent.data_flow_hold`, `prevent.destination_grant`; rules `pc.drift.behavior`, `pc.sequence.read_then_disclose`; kinds `behavior.NEW_DESTINATION`; Hub rules `org.hub.external_disclosure_repeat`; scenarios `RT-046`, `RT-120`, `RT-191`, `RT-196`<br>T1567.001: prevent `prevent.grant_scope`, `prevent.secret_outbound`; scenarios `RT-009`, `RT-010`, `RT-011`<br>T1567.002: scenarios `RT-212`<br>T1567.003 not covered<br>T1567.004 not covered |
| [T1029](https://attack.mitre.org/techniques/T1029) | Scheduled Transfer | Outside PantherClaw: covered by network security | It needs a network. |
| [T1537](https://attack.mitre.org/techniques/T1537) | Transfer Data to Cloud Account | Mapped | prevent `prevent.share_accounts`; scenarios `RT-201` |

### Impact (TA0040)

| Technique | Name | Place | Mapped to it |
|---|---|---|---|
| [T1531](https://attack.mitre.org/techniques/T1531) | Account Access Removal | Outside PantherClaw: covered by the identity provider | It happens at the identity provider. |
| [T1485](https://attack.mitre.org/techniques/T1485) | Data Destruction | Mapped (partly) | prevent `prevent.grant_scope`<br>T1485.001 not covered |
| [T1486](https://attack.mitre.org/techniques/T1486) | Data Encrypted for Impact | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1565](https://attack.mitre.org/techniques/T1565) | Data Manipulation | Mapped (partly) | T1565.001: prevent `prevent.grant_scope`; rules `pc.integrity.evidence_integrity_failed`; scenarios `RT-044`<br>T1565.002: rules `pc.integrity.action_tampered`<br>T1565.003 not covered |
| [T1491](https://attack.mitre.org/techniques/T1491) | Defacement | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1561](https://attack.mitre.org/techniques/T1561) | Disk Wipe | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1667](https://attack.mitre.org/techniques/T1667) | Email Bombing | Outside PantherClaw: covered by email security | It needs a mailbox. |
| [T1499](https://attack.mitre.org/techniques/T1499) | Endpoint Denial of Service | Mapped (partly) | T1499.003: scenarios `RT-194`<br>T1499.001 not covered<br>T1499.002 not covered<br>T1499.004 not covered |
| [T1657](https://attack.mitre.org/techniques/T1657) | Financial Theft | Mapped | prevent `prevent.budgets`; rules `pc.budget.splitting`; kinds `behavior.SPEND_SPIKE`; Hub rules `org.hub.refund_burst`, `org.hub.refund_cap_probing`; scenarios `RT-026`, `RT-027`, `RT-040`, `RT-041` |
| [T1495](https://attack.mitre.org/techniques/T1495) | Firmware Corruption | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1490](https://attack.mitre.org/techniques/T1490) | Inhibit System Recovery | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1498](https://attack.mitre.org/techniques/T1498) | Network Denial of Service | Outside PantherClaw: covered by network security | It needs a network. |
| [T1496](https://attack.mitre.org/techniques/T1496) | Resource Hijacking | Mapped (partly) | T1496.004: scenarios `RT-192`<br>T1496.001 not covered<br>T1496.002 not covered<br>T1496.003 not covered |
| [T1489](https://attack.mitre.org/techniques/T1489) | Service Stop | Outside PantherClaw: covered by EDR | It needs an endpoint. |
| [T1529](https://attack.mitre.org/techniques/T1529) | System Shutdown/Reboot | Outside PantherClaw: covered by EDR | It needs an endpoint. |

## Techniques by abuse case

Abuse cases from [THREAT_MODEL](THREAT_MODEL.md) that no library range scenario tests, or whose scenarios map to no MITRE technique, are not listed.

| Abuse case | ATLAS | ATT&CK Enterprise |
|---|---|---|
| T-001 | AML.T0086 | T1567.001 |
| T-002 | — | T1548 |
| T-005 | — | T1548 |
| T-006 | — | T1548 |
| T-008 | AML.T0118.001 | — |
| T-010 | — | T1677 |
| T-011 | AML.T0048.000 | T1657 |
| T-014 | AML.T0050, AML.T0053, AML.T0055 | T1059.004, T1071.004, T1552.001, T1552.004 |
| T-015 | AML.T0086 | T1552.005, T1567.001 |
| T-017 | AML.T0086 | T1567.001 |
| T-019 | AML.T0109, AML.T0110.000 | — |
| T-020 | AML.T0053 | — |
| T-021 | — | T1552.005 |
| T-032 | AML.T0091.000 | T1550.001 |
| T-069 | — | T1685 |
| T-080 | — | T1685 |
| T-081 | AML.T0091.000 | T1550.001 |
| T-083 | AML.T0053 | T1548, T1677 |
| T-086 | AML.T0050, AML.T0055, AML.T0105 | T1059.004, T1071.004, T1552.001, T1552.004, T1552.005, T1611 |
| T-088 | AML.T0105, AML.T0109, AML.T0110.000 | T1552.005, T1611 |
| T-093 | AML.T0086 | T1567.001 |
| T-142 | AML.T0048.000 | T1657 |
| T-143 | AML.T0036 | T1213.006, T1565.001 |
| T-144 | AML.T0036 | T1213.006 |
| T-145 | AML.T0073 | T1548 |
| T-146 | AML.T0086 | T1567 |
| T-147 | AML.T0073, AML.T0091.000 | T1550.001 |
| T-148 | AML.T0118.001 | — |
| T-149 | AML.T0073 | — |
| T-226 | AML.T0086 | T1567 |
| T-229 | AML.T0053 | — |
| T-266 | — | T1606 |
| T-267 | AML.T0091.000 | T1550.001 |
| T-268 | AML.T0091.000 | T1550.001 |
| T-269 | AML.T0091.000 | T1550.001 |
| T-272 | AML.T0051.001, AML.T0093 | — |
| T-273 | AML.T0051.001, AML.T0093 | — |
| T-276 | AML.T0051.001 | T1698 |
| T-281 | AML.T0051.001, AML.T0099 | T1698 |
| T-310 | AML.T0024, AML.T0055 | T1552.001, T1567 |
| T-311 | AML.T0034 | T1027 |
| T-312 | AML.T0029 | T1499.003 |
| T-313 | AML.T0034 | T1496.004 |
| T-314 | AML.T0024 | T1552.001 |
| T-316 | AML.T0086 | T1567 |
| T-320 | AML.T0091.000 | T1550.001 |
| T-321 | AML.T0051.001, AML.T0068 | T1698 |
| T-324 | — | T1537 |
| T-325 | AML.T0081 | — |
| T-331 | AML.T0053 | — |
| T-332 | AML.T0053 | T1567.002 |
| T-333 | AML.T0053 | — |
| T-335 | — | T1609, T1610, T1611 |
| T-336 | — | T1078.001 |
| T-337 | — | T1199, T1552.007 |
| T-338 | — | T1685 |
| T-340 | AML.T0100, AML.T0131 | — |
| T-341 | AML.T0098 | — |
| T-343 | AML.T0053 | — |
| T-344 | AML.T0134 | — |
| T-347 | AML.T0103 | — |
| T-348 | — | T1651 |

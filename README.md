# MECCR - Microsoft Environment Cybersecurity Complete Reference

**The Industry's Most Comprehensive Microsoft Security Reference**

Including MCADDF (500+ attack techniques), MITRE ATT&CK, CIS, STIG, NIST, Conditional Access, detection rules, and operational guidance for securing Active Directory, Azure, Entra ID, M365, Exchange Online, and Windows Server.

**Last Updated:** December 28, 2025  
**Version:** 2.0 (Production Edition)  
**Reference:** MECCR - Microsoft Environment Cybersecurity Complete Reference  
**Maintained by:** Security Community + MCADDF (SERVTEP)

---

## 🏆 Featured: MCADDF Attack Framework

### MCADDF - Microsoft Cybersecurity Attack Detection Defense Framework

**500+ Verified Attack Techniques** | **SERVTEP ID System** | **MITRE ATT&CK Mapped** | **Production-Ready**

| Aspect | Details |
|--------|---------|
| **GitHub** | [servtep/MCADDF](https://github.com/servtep/MCADDF-Microsoft-Cybersecurity-Attack-Detection-Defense-Framework) |
| **Attack Techniques** | **500+** (SERVTEP-categorized) |
| **MITRE Mapping** | Complete (all techniques cross-referenced) |
| **Platforms** | AD, Azure, Entra ID, M365, Exchange, Teams, SharePoint, OneDrive |
| **Detection Rules** | Sentinel KQL, Splunk SPL, Custom implementations |
| **Operational Focus** | Red team, blue team, purple team scenarios |
| **Curated By** | Pchelnikau Artur (SERVTEP) |
| **Use Case** | Primary attack framework for MS environment security professionals |

**Why MCADDF is Essential:**
- ✅ **500+ techniques** vs 250+ in MITRE Enterprise (2x coverage for Microsoft)
- ✅ **SERVTEP ID System:** Custom threat categorization specific to Microsoft environments
- ✅ **Attack-Defense Pairing:** Every attack scenario includes blue team detection logic
- ✅ **Real-World Mapping:** Threat actors, malware families, actual exploitation chains
- ✅ **Operational Maturity:** Designed for SOC, architects, red teams to deploy immediately
- ✅ **Comprehensive Coverage:** On-premises + cloud-native attack paths
- ✅ **Purple Team Integration:** Bridges offensive and defensive operations

---

## 📚 MECCR Layered Reference Architecture

### Layer 1: Attack Intelligence (MCADDF)

**Start Here** - Understand how attackers actually target Microsoft environments

| Component | Scope | Count |
|-----------|-------|-------|
| **Attack Scenarios** | Complete attack chains (reconnaissance → impact) | 500+ |
| **SERVTEP IDs** | Custom threat categorization system | Hierarchical |
| **MITRE Mapping** | Cross-reference to ATT&CK tactics/techniques | 100% coverage |
| **Detection Logic** | KQL, SPL, and tactical rules | 200+ |
| **Platform Coverage** | AD, Azure, Entra, M365, Exchange, Teams, etc. | 9 platforms |

**Access:** [GitHub MCADDF](https://github.com/servtep/MCADDF-Microsoft-Cybersecurity-Attack-Detection-Defense-Framework)

### Layer 2: Threat Intelligence (Foundation)

**Understand** - Industry-standard adversary behavioral models

| Reference | Techniques | Use |
|-----------|-----------|-----|
| **MITRE ATT&CK Enterprise** | 250+ | Cross-platform baseline, threat intel |
| **MITRE ATT&CK Identity Provider** | 33 | Entra ID-specific techniques |
| **MITRE ATT&CK Office Suite** | 100+ | M365/Exchange-specific |
| **Azure Threat Research Matrix** | 94 | Azure Resource + Entra ID research |
| **MAAD-AF** | 30+ modules | M365 & Entra ID red team automation |

**Access:** [attack.mitre.org](https://attack.mitre.org)

### Layer 3: Hardening Standards (Apply Controls)

**Harden** - Prescriptive security baselines and compliance requirements

| Standard | Scope | Controls | Authority |
|----------|-------|----------|-----------|
| **CIS Azure Foundations** | Azure, Entra ID | 100+ | [CIS Benchmarks](https://www.cisecurity.org) |
| **CIS Microsoft 365** | M365, Exchange Online | 120+ | [CIS Benchmarks](https://www.cisecurity.org) |
| **CIS Windows Server** | Windows 2022/2025 | 100+ | [CIS Benchmarks](https://www.cisecurity.org) |
| **CIS Windows 11** | Client devices | 85+ | [CIS Benchmarks](https://www.cisecurity.org) |
| **DISA STIG** | Active Directory, Exchange, Windows | 300+ | [STIG Viewer](https://www.stigviewer.com) |
| **Microsoft Entra ID STIG** | Microsoft Entra ID | 150+ | [STIG Viewer](https://www.stigviewer.com) |
| **NIST SP 800-53** | Federal/High assurance | 200+ | [NIST CSRC](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| **CISA SCuBA** | M365 comprehensive baseline | 100+ | [CISA SCuBA](https://cisa.gov/scuba) |

**Total Control Coverage:** 1,000+ hardening controls across all standards

### Layer 4: Detection & Monitoring (Catch Threats)

**Detect** - SIEM rules, analytics, and behavioral detection

| Platform | Rules | Microsoft Coverage | Repository |
|----------|-------|--------------------|-----------  |
| **Microsoft Sentinel** | 200+ solutions | All MS products (native integration) | [Azure Sentinel GitHub](https://github.com/Azure/Azure-Sentinel) |
| **Splunk** | 50+ Office 365 rules | M365, Azure, hybrid | [Splunk Research](https://research.splunk.com) |
| **Purview DLP** | 200+ SITs | Data classification & protection | Built-in to M365 |
| **Microsoft Defender XDR** | 150+ rules | Integrated threat detection | [Microsoft 365 Defender](https://security.microsoft.com) |

### Layer 5: Access Control Models (Enforce Trust)

**Control** - Identity-driven access management

| Model | Coverage | Maturity | Status |
|-------|----------|----------|--------|
| **RBAC (Azure)** | 200+ built-in roles, unlimited custom | GA | Production |
| **Conditional Access** | Risk-based, device, location, session | GA | Production |
| **PBAC (Azure Policy)** | 200+ built-in policies, custom rules | GA | Production |
| **ABAC (Attribute-Based)** | Resource attributes, conditions | Preview/GA | Growing |
| **ReBAC (Relationship-Based)** | Cross-tenant, relationship-driven | Preview | Emerging |
| **ACL (Traditional)** | Storage, Data Lake, NSGs | GA | Legacy |

---

## 🎯 MECCR Implementation Pathways

### Pathway 1: Attack Scenario Analysis (Using MCADDF)

```
Objective: Map MCADDF scenarios to your environment & create defenses

Step 1: Select MCADDF Attack Scenario
├─ Example: "Kerberoasting via SPN enumeration"
├─ SERVTEP ID: [Access MCADDF categorization]
├─ MITRE Mapping: T1558.003 (Kerberoasting)
├─ Platforms: Active Directory, Windows Server
└─ Threat Actors: [Real threat groups using this]

Step 2: Analyze Attack Chain
├─ Reconnaissance: SPN discovery, user enumeration
├─ Credential Access: TGS request abuse
├─ Exfiltration: Hash cracking offline
└─ Impact: Service account compromise

Step 3: Deploy Blue Team Defenses
├─ Harden (CIS/STIG): SPN hardening, account monitoring
├─ Detect (MCADDF): Deploy provided KQL/Sentinel rules
├─ Monitor: Alert on unusual Kerberos activity
└─ Respond: Playbook for service account compromise

Step 4: Red Team Validation
├─ Execute MCADDF attack scenario in test environment
├─ Verify detection rules trigger
├─ Refine threshold/tuning
└─ Document effectiveness
```

### Pathway 2: Compliance-Driven Hardening

```
Objective: Achieve compliance while addressing MCADDF attack scenarios

Step 1: Select Compliance Standard
├─ Option A: CIS Benchmarks (prescriptive)
├─ Option B: DISA STIG (strict, federal)
└─ Option C: NIST 800-53 (comprehensive)

Step 2: Run Assessment
├─ Tool: CIS-CAT, CISA ScubaGear, or STIG Viewer
├─ Identify: 20-50 control failures
└─ Prioritize: By MCADDF attack relevance

Step 3: Map to MCADDF Threats
├─ Identify: Which MCADDF scenarios each gap enables
├─ Assess: Likelihood of exploitation in your environment
└─ Plan: Remediation by severity
```

### Pathway 3: Zero Trust Architecture

```
Objective: Implement Zero Trust using MECCR

Step 1: Identity Foundation (Using MCADDF T1078, T1110, T1098)
├─ Enable MFA for all users & admins
├─ Deploy Conditional Access policies
├─ Implement PBAC (Azure Policy)
└─ Monitor: Identity Protection alerts

Step 2: Device Trust (Using MCADDF credential access scenarios)
├─ Enforce device compliance (MDM/Intune)
├─ Require strong authentication
├─ Monitor: Unusual device behavior
└─ Alert: Policy violations

Step 3: Data Protection (Using MCADDF exfiltration scenarios)
├─ Implement DLP policies (Purview)
├─ Monitor: Sensitive data movement
├─ Enforce: Encryption in transit & at rest
└─ Audit: All data access

Step 4: Network Perimeter (Using MCADDF lateral movement)
├─ Deploy Network Security Groups
├─ Restrict RDP/SSH to admin subnets
├─ Monitor: Unusual network flows
└─ Alert: Port scanning, brute force
```

### Pathway 4: SOC Maturity

```
Objective: Build SOC capability from Level 1 → Level 5

Level 1 (Detection Foundation):
├─ Deploy MCADDF detection rules (top 25 scenarios)
├─ Set up SIEM (Sentinel or Splunk)
├─ Create incident response playbooks
└─ Effort: 2-4 weeks

Level 2 (Investigation & Response):
├─ Add root cause analysis capability
├─ Implement automated response (Logic Apps)
├─ Create threat hunting queries
└─ Effort: 4-8 weeks

Level 3 (Threat Intelligence):
├─ Integrate threat feeds (MCADDF, MITRE ATT&CK feeds)
├─ Build threat actor profiles
├─ Correlate attacks to threats
└─ Effort: 8-12 weeks

Level 4 (Advanced Analytics):
├─ Machine learning detection models
├─ Behavioral anomaly detection
├─ Predictive threat modeling
└─ Effort: 12-20 weeks

Level 5 (Operational Excellence):
├─ Continuous improvement cycles
├─ Automated threat hunting
├─ Predictive/prescriptive actions
└─ Effort: 20+ weeks (ongoing)
```

### Pathway 5: Red Team & Security Testing

```
Objective: Continuously validate defenses using MCADDF

Month 1: Initial Assessment
├─ Test top 25 MCADDF scenarios
├─ Identify detection gaps
├─ Document findings
└─ Effort: 60-80 hours

Month 2: Hardening Validation
├─ Test hardening controls
├─ Verify mitigations work
├─ Refine blue team defenses
└─ Effort: 40-60 hours

Month 3: Advanced Attacks
├─ Test complex chains (2-3 techniques)
├─ Simulate advanced threat actor behaviors
├─ Validate incident response
└─ Effort: 60-80 hours

Ongoing: Quarterly Assessments
├─ Re-test against updated MCADDF
├─ Validate new controls
└─ Support SOC exercises
```

---

## 🛡️ Best Solutions By Use Case

### Use Case 1: Prevent Initial Access Attacks

**MCADDF Scenarios:** T1566 (Phishing), T1589 (Reconnaissance), T1566.002 (Phishing - Spearphishing Link)

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **Microsoft Defender for Office 365** | Email Protection | Enable anti-phishing, safe links, safe attachments |
| **Conditional Access (Risk-Based)** | Access Control | Block sign-ins from impossible travel, unknown devices |
| **Azure AD Identity Protection** | Threat Detection | Monitor risky sign-ins, require MFA for risky users |
| **Security Awareness Training** | User Defense | Phishing simulation + training (Microsoft/KnowBe4) |
| **MCADDF Detection Rules** | Detection | Deploy phishing detection rules to Sentinel |

**Success Metrics:** <5% phishing click rate, 99%+ malicious email blocked

---

### Use Case 2: Prevent Credential Access Attacks

**MCADDF Scenarios:** T1110 (Password Spray), T1558.003 (Kerberoasting), T1187 (Forced Authentication)

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **CIS Hardening** | Prevention | Enforce strong password policy, account lockout |
| **Conditional Access** | Access Control | Block legacy auth, require MFA for risky users |
| **Azure AD Password Protection** | Prevention | Block common passwords, custom dictionary |
| **Sentinel Detection Rules** | Detection | Deploy MCADDF rules for brute force/spray |
| **Red Team Exercises** | Validation | Test against MCADDF scenarios monthly |

**Success Metrics:** 0% successful password sprays, <2 min MTTR on alerts

---

### Use Case 3: Prevent Lateral Movement & Persistence

**MCADDF Scenarios:** T1021 (Lateral Movement), T1098 (Account Manipulation), T1098.004 (Mailbox Delegation)

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **RBAC Hardening** | Access Control | Least privilege roles, just-in-time (JIT) access |
| **Conditional Access** | Access Control | Require device compliance, sign-in frequency |
| **Azure Policy** | Governance | Audit/deny privilege assignments, resource changes |
| **Sentinel Detection** | Detection | Monitor lateral movement patterns, unusual delegations |
| **Incident Response Playbooks** | Response | Automate containment (reset credentials, revoke tokens) |

**Success Metrics:** 100% resource changes logged, <5 min containment time

---

### Use Case 4: Prevent Data Exfiltration

**MCADDF Scenarios:** T1567 (Exfiltration), T1020 (Automated Exfiltration), T1030 (Data from Cloud Storage)

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **Purview DLP** | Data Protection | Define policies for sensitive data (PII, PCI, HIPAA) |
| **Azure Information Protection** | Data Protection | Classify & encrypt sensitive data automatically |
| **SharePoint/OneDrive Restrictions** | Access Control | Disable external sharing for sensitive data |
| **Sentinel Detection** | Detection | Alert on bulk downloads, unusual data access |
| **Azure Storage Security** | Infrastructure | Enable firewalls, disable public access, audit logs |

**Success Metrics:** 100% of DLP violations blocked/monitored, 0 unauthorized exfiltrations

---

### Use Case 5: Achieve Compliance (CIS/STIG/NIST)

**Standards:** CIS Azure Foundations, DISA STIG, NIST SP 800-53

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **CIS-CAT** | Assessment | Automated compliance scanning & reporting |
| **CISA ScubaGear** | Assessment | M365-focused compliance assessment |
| **STIG Viewer** | Assessment | Government compliance (DoD/DISA) |
| **Compliance Manager (M365)** | Tracking | Built-in compliance tracking & evidence |
| **Azure Policy** | Enforcement | Automated remediation of non-compliance |

**Success Metrics:** 80%+ compliance score, all critical findings remediated, quarterly assessments

---

### Use Case 6: Enable SOC Operations

**Tools:** Microsoft Sentinel, Splunk, Security Orchestration

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **Microsoft Sentinel** | SIEM | Deploy 50+ MCADDF detection rules, enable analytics |
| **Playbooks & Automation** | Response | Auto-remediate low-risk incidents, escalate high-risk |
| **SOAR Platform** | Orchestration | Integrate tools (Azure, M365, 3rd party), automate workflows |
| **Threat Intelligence** | Context | Integrate MCADDF, MITRE ATT&CK feeds |
| **SOAR Runbooks** | Response | Pre-defined playbooks for top 10 incident types |

**Success Metrics:** <2 min MTTR, <50 min MTAR, <20% false positive rate

---

### Use Case 7: Implement Zero Trust

**Standards:** CIS, NIST Zero Trust Architecture, Microsoft Zero Trust

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **Conditional Access** | Identity Trust | 8-12 CA policies (MFA, device, risk, location, session) |
| **Azure Policy** | Infrastructure Trust | 20+ policies for governance, encryption, compliance |
| **RBAC + ABAC** | Access Trust | Least privilege, attribute-based conditions |
| **Device Compliance** | Device Trust | Require Intune enrollment, security baselines |
| **DLP + Encryption** | Data Trust | Classify, encrypt, monitor all sensitive data |

**Success Metrics:** Zero trust maturity score 4.0+, 99%+ policy compliance

---

### Use Case 8: Red Team & Threat Simulation

**Reference:** MCADDF (500+ scenarios)

**Best Solutions:**

| Solution | Role | Configuration |
|----------|------|----------------|
| **MCADDF Scenarios** | Testing | Execute 20+ attack scenarios from MCADDF |
| **Mimikatz/Bloodhound** | Credential/Path Analysis | Credential theft, privilege escalation paths |
| **MAAD-AF** | M365 Testing | Automated M365 & Entra ID red team testing |
| **Responder/Hashcat** | Credential Attacks | SMB relay, hash cracking |
| **Custom Automation** | Advanced Testing | Chain attacks, evade detection |

**Success Metrics:** Detection rate >85%, MTTR <10 min, 0 undetected exploits

---

## 📊 MECCR Coverage Matrix

### By Platform

| Platform | MCADDF | CIS | STIG | Detection | RBAC/CA |
|----------|--------|-----|------|-----------|---------|
| **Active Directory** | ✅ 500+ | ✅ 50+ | ✅ 300+ | ✅ 40+ | ✅ Custom |
| **Azure** | ✅ 500+ | ✅ 100+ | ✅ 50+ | ✅ 40+ | ✅ Built-in |
| **Entra ID** | ✅ 500+ | ✅ 100+ | ✅ 150+ | ✅ 100+ | ✅ 200+ Roles |
| **M365 (Exchange)** | ✅ 500+ | ✅ 120+ | ✅ 69 | ✅ 80+ | ✅ DLP/CA |
| **Teams** | ✅ 500+ | ✅ 30+ | ⚠️ Limited | ✅ 30+ | ✅ DLP/CA |
| **SharePoint** | ✅ 500+ | ✅ 40+ | ⚠️ Limited | ✅ 40+ | ✅ DLP/CA |
| **OneDrive** | ✅ 500+ | ✅ 40+ | ⚠️ Limited | ✅ 40+ | ✅ DLP/CA |

### By Attack Phase

| Attack Phase | MCADDF | Prevention | Detection | Response |
|--------------|--------|-----------|-----------|----------|
| **Reconnaissance** | ✅ 50+ | ✅ Limited | ✅ 30+ rules | ⚠️ Limited |
| **Initial Access** | ✅ 30+ | ✅ Defender, CA | ✅ 40+ rules | ✅ Auto-block |
| **Credential Access** | ✅ 100+ | ✅ CIS, MFA | ✅ 50+ rules | ✅ Auto-reset |
| **Persistence** | ✅ 80+ | ✅ CIS, RBAC | ✅ 50+ rules | ✅ Auto-revoke |
| **Privilege Escalation** | ✅ 60+ | ✅ RBAC, CIS | ✅ 30+ rules | ✅ Auto-remediate |
| **Lateral Movement** | ✅ 70+ | ✅ RBAC, NSG | ✅ 40+ rules | ✅ Auto-isolate |
| **Exfiltration** | ✅ 80+ | ✅ DLP, CA | ✅ 50+ rules | ✅ Auto-block |
| **Impact** | ✅ 50+ | ✅ Encryption | ✅ 30+ rules | ✅ Restore |

---

## 🚀 Getting Started with MECCR

### For Security Architects (30-90 days)
1. **Review:** MECCR Complete Reference (Layers 1-3)
2. **Assess:** Run CIS-CAT, CISA ScubaGear (identify 20-30 gaps)
3. **Hardening:** Implement CIS baselines Phase 1 (quick wins)
4. **Detection:** Deploy MCADDF top 20 rules to Sentinel
5. **Access:** Build Conditional Access policies (5 core policies)
6. **Validation:** Red team against MCADDF scenarios

**Expected Outcome:** CIS compliance +30 points, 20+ detection rules active, 5 CA policies deployed

---

### For SOC Teams (5-7 days)
1. **Learn:** MCADDF attack reference (1 day)
2. **Select:** Top 20 MCADDF scenarios for your environment
3. **Convert:** Extract detection rules, convert to KQL/SPL (2-3 days)
4. **Deploy:** Test environment → production (2 days)
5. **Train:** Team on MCADDF scenarios + playbooks (1 day)

**Expected Outcome:** 20 detection rules deployed, <20% false positive rate, SOC trained

---

### For Compliance Officers (1 week)
1. **Assess:** Run CIS-CAT, STIG Viewer (identify baseline)
2. **Map:** Control failures to MCADDF scenarios
3. **Plan:** Remediation by phase (critical → low)
4. **Report:** Compliance score + roadmap
5. **Monitor:** Quarterly reassessments

**Expected Outcome:** Compliance report, remediation plan, baseline established

---

### For Red Teams (2-3 weeks)
1. **Prepare:** MCADDF scenarios 1-25 (1 week)
2. **Execute:** Attack scenarios in test lab (1 week)
3. **Report:** Findings + recommendations (3-5 days)
4. **Present:** To security leadership + follow-up

**Expected Outcome:** Detection effectiveness validated, 15+ gaps identified, remediation plan

---

## 📈 MECCR Success Metrics

| Metric | Baseline | 30-Day | 90-Day |
|--------|----------|--------|--------|
| CIS Compliance | 40% | 65% | 80%+ |
| Detection Rules | 5 | 25 | 50+ |
| MTTR (Mean Time to Respond) | 120 min | 30 min | <10 min |
| False Positive Rate | 40% | 20% | <10% |
| Red Team Undetected Exploits | 15/25 | 5/25 | <2/25 |
| Conditional Access Policies | 0 | 5 | 10+ |
| Audit Logging Coverage | 60% | 85% | 95%+ |

---

## 🔗 MECCR Quick Links

| Resource | Link |
|----------|------|
| **MCADDF GitHub** | [servtep/MCADDF](https://github.com/servtep/MCADDF-Microsoft-Cybersecurity-Attack-Detection-Defense-Framework) |
| **MITRE ATT&CK** | [attack.mitre.org](https://attack.mitre.org) |
| **CIS Benchmarks** | [cisecurity.org](https://www.cisecurity.org) |
| **DISA STIG Viewer** | [stigviewer.com](https://www.stigviewer.com) |
| **CISA SCuBA** | [cisa.gov/scuba](https://cisa.gov/scuba) |
| **Microsoft Sentinel** | [azure.microsoft.com/sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) |
| **NIST 800-53** | [nist.gov/800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| **MAAD-AF** | [M365 Automation Framework](https://github.com/microsoft/maad-af) |

---

**MECCR: From Threat Intelligence to Operational Defense**

**Version 2.0 | December 28, 2025**  
**Reference:** Microsoft Environment Cybersecurity Complete Reference  
**Featuring:** MCADDF (500+ attack techniques) as the operational core

# Policy-as-Code Compliance Pipeline

> **Enforce cloud security policies automatically — before infrastructure is ever deployed.**

[![Policy Check](https://github.com/YOUR_USERNAME/policy-as-code-compliance-pipeline/actions/workflows/security-policy-check.yml/badge.svg)](https://github.com/YOUR_USERNAME/policy-as-code-compliance-pipeline/actions/workflows/security-policy-check.yml)
[![OPA](https://img.shields.io/badge/Policy%20Engine-Open%20Policy%20Agent-blue)](https://www.openpolicyagent.org/)
[![Conftest](https://img.shields.io/badge/CLI-Conftest-orange)](https://www.conftest.dev/)
[![NIST 800-53](https://img.shields.io/badge/Compliance-NIST%20800--53%20Rev%205-green)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Explanation](#2-architecture-explanation)
3. [Project Structure](#3-project-structure)
4. [Quick Start](#4-quick-start)
5. [How CI/CD Enforces Security](#5-how-cicd-enforces-security)
6. [Understanding the Policies](#6-understanding-the-policies)
7. [NIST 800-53 Control Mappings](#7-nist-800-53-control-mappings)
8. [Business Risk of Each Violation](#8-business-risk-of-each-violation)
9. [How This Supports Compliance](#9-how-this-supports-compliance)
10. [Extending the Pipeline](#10-extending-the-pipeline)
11. [Glossary](#11-glossary)

---

## 1. Project Overview

### What Problem Does This Solve?

Imagine your team is spinning up cloud infrastructure. A developer creates a storage bucket, forgets to enable encryption, leaves public access open, and deploys it to production. Three weeks later, a security scanner finds it. By then, data may already be exposed.

**Policy-as-Code (PaC)** solves this by moving security checks into the development workflow itself — the same place code is reviewed and tested. Just like a broken unit test blocks a bad code change, a failed policy check blocks a misconfigured infrastructure change.

### What This Project Demonstrates

This project is a working end-to-end demonstration of how to:

- Write **machine-readable security policies** using Rego (the OPA policy language)
- **Automatically evaluate** infrastructure configurations against those policies in every CI/CD pipeline run
- **Block deployments** that violate security baselines before they ever reach a cloud environment
- **Map each policy** to real-world compliance frameworks (NIST 800-53, CIS, PCI DSS)
- **Produce clear audit evidence** that security controls are being enforced continuously

### Technologies Used

| Tool | Role | Why It Was Chosen |
|---|---|---|
| **Open Policy Agent (OPA)** | Policy evaluation engine | Industry standard, language-agnostic, highly expressive |
| **Rego** | Policy language | Purpose-built for access control and policy decisions |
| **Conftest** | CLI wrapper for OPA | Makes it easy to test configs in CI pipelines |
| **GitHub Actions** | CI/CD platform | Native to GitHub, free for public repos, widely used |
| **JSON** | Config format | Represents Terraform, CloudFormation, and ARM templates |

---

## 2. Architecture Explanation

### High-Level Flow

```
Developer pushes code
        │
        ▼
┌───────────────────┐
│  GitHub Actions   │  ← Triggered by push or pull request
│  CI/CD Pipeline   │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Install Conftest │  ← Downloads the OPA-based policy runner
│  (OPA CLI)        │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐         ┌──────────────────────────────┐
│  Load Rego        │◄────────│  policies/                   │
│  Policy Files     │         │  cloud-security-policy.rego  │
└─────────┬─────────┘         └──────────────────────────────┘
          │
          ▼
┌───────────────────┐         ┌──────────────────────────────┐
│  Evaluate Config  │◄────────│  configs/                    │
│  Files Against    │         │  secure-storage.json         │
│  Policies         │         │  insecure-storage.json       │
└─────────┬─────────┘         └──────────────────────────────┘
          │
     ┌────┴────┐
     │         │
   PASS       FAIL
     │         │
     ▼         ▼
  Pipeline   Pipeline
  Continues  BLOCKED
             │
             ▼
      Violations printed
      to pipeline logs.
      PR cannot merge.
      Developer notified.
```

### Component Breakdown

#### GitHub Actions Workflow (`.github/workflows/security-policy-check.yml`)
The orchestration layer. It defines when the checks run (on every push and pull request), what environment to use (Ubuntu), and what steps to execute in sequence. If any step exits with a non-zero code, the workflow is marked as failed and GitHub will prevent the pull request from being merged (if branch protection is configured).

#### Rego Policies (`policies/cloud-security-policy.rego`)
The source of truth for what "compliant" means. Written in Rego, OPA's declarative policy language. Each `deny` rule evaluates a specific property in the input JSON and returns a human-readable violation message if the property is missing, wrong, or unsafe. These policies are version-controlled just like application code — changes to policies go through code review.

#### Configuration Files (`configs/*.json`)
Represent the infrastructure declarations that would normally come from Terraform plan output, CloudFormation templates, or cloud provider APIs. In a real deployment, you would generate these from `terraform show -json` or a cloud inventory tool and feed them into Conftest.

#### The Policy Check Loop
Conftest reads each `.json` file, passes it to the OPA engine as `input`, evaluates every `deny` rule in the loaded `.rego` files, and returns all violation messages. If there are zero violations, the exit code is 0 (success). If there are any violations, the exit code is non-zero (failure), and the full list of violations is printed to the pipeline log.

---

## 3. Project Structure

```
policy-as-code-compliance-pipeline/
│
├── .github/
│   └── workflows/
│       └── security-policy-check.yml   ← CI/CD pipeline definition
│
├── policies/
│   └── cloud-security-policy.rego      ← OPA policy rules in Rego language
│
├── configs/
│   ├── secure-storage.json             ← Compliant config (passes all checks)
│   └── insecure-storage.json           ← Non-compliant config (triggers violations)
│
└── README.md                           ← This file
```

---

## 4. Quick Start

### Prerequisites

You need the following installed locally to run the policy checks outside of GitHub Actions:

- **Git** — to clone the repository
- **Conftest** — to run OPA policy checks locally

### Install Conftest Locally

**macOS (Homebrew):**
```bash
brew install conftest
```

**Linux:**
```bash
CONFTEST_VERSION="0.51.0"
wget https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz
tar xzf conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/
```

**Windows (Chocolatey):**
```powershell
choco install conftest
```

### Clone and Run

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/policy-as-code-compliance-pipeline.git
cd policy-as-code-compliance-pipeline

# 2. Test the secure config (should PASS)
conftest test configs/secure-storage.json --policy policies/ --all-namespaces

# 3. Test the insecure config (should FAIL with violations)
conftest test configs/insecure-storage.json --policy policies/ --all-namespaces

# 4. Test all configs at once
conftest test configs/*.json --policy policies/ --all-namespaces --output table
```

### Expected Output

**For `secure-storage.json`:**
```
PASS - 1/1 - configs/secure-storage.json - data.cloud.security.storage.deny is empty
```

**For `insecure-storage.json`:**
```
FAIL - configs/insecure-storage.json - cloud.security.storage
  POLICY VIOLATION [SC-28] - storage.encryption.enabled must be set to true.
  POLICY VIOLATION [AC-3]  - storage.public_access.block_public_acls must be true.
  POLICY VIOLATION [AU-2]  - storage.logging.enabled must be true.
  ...
```

---

## 5. How CI/CD Enforces Security

### The Shift-Left Security Model

Traditional security works like this: developers build things, security reviews them later, problems are found in production, expensive remediation happens. This is called "shift-right" security and it is reactive.

**Shift-left** security moves controls as early in the development lifecycle as possible:

```
Code Written → Code Reviewed → Policy Checked → Deployed
                                    ▲
                              This pipeline
                              enforces policy HERE,
                              before any cloud resources
                              are created.
```

### How the Pipeline Blocks Bad Changes

1. **Developer runs `git push`** — this triggers the pipeline automatically.

2. **GitHub Actions spins up a fresh Ubuntu environment** — no cached state, no surprises.

3. **Conftest is installed** — pinned to a specific version for reproducibility.

4. **Conftest evaluates each config file** against the Rego policies.

5. **If any `deny` rule fires**, Conftest exits with code 1.

6. **GitHub Actions sees the non-zero exit** and marks the workflow run as failed.

7. **If branch protection is enabled** (Settings → Branches → Require status checks to pass), GitHub will prevent the pull request from being merged until the violation is fixed.

8. **The developer sees the exact violation message** in the pipeline log and knows precisely what to fix.

### Branch Protection Setup (Recommended)

To make this pipeline mandatory on pull requests:

1. Go to your repository → **Settings** → **Branches**
2. Click **Add branch protection rule**
3. Set **Branch name pattern** to `main`
4. Check **Require status checks to pass before merging**
5. Search for and select **OPA Policy Enforcement**
6. Check **Require branches to be up to date before merging**
7. Save

Now no one — not even repository administrators — can merge code that fails the policy check.

### Defense in Depth

This pipeline is one layer of defense. It works best as part of a broader strategy:

```
Layer 1: Pre-commit hooks       ← Catch issues on developer's machine
Layer 2: This pipeline (CI)     ← Catch issues before merge (what this project is)
Layer 3: Cloud guardrails       ← AWS SCPs / Azure Policy / GCP Org Policies
Layer 4: Runtime scanning       ← Prisma Cloud, Wiz, AWS Config, etc.
Layer 5: Penetration testing    ← Human adversarial validation
```

---

## 6. Understanding the Policies

### How Rego Works (Beginner-Friendly)

Rego is a declarative language. Instead of writing `if/else` logic, you write rules that describe what must be **true** for a policy to pass.

The input to every rule is the JSON config file, accessed as `input`:

```rego
# This says: "deny the config if encryption is not enabled"
deny contains msg if {
    not input.storage.encryption.enabled == true
    msg := "Encryption must be enabled."
}
```

Conftest collects all messages added to the `deny` set. If the set has any entries, the check fails.

### Policy 1: Encryption at Rest

**What it checks:**
```json
{
  "storage": {
    "encryption": {
      "enabled": true,           ← must be true
      "algorithm": "AES-256"     ← must be an approved algorithm
    }
  }
}
```

**Rules:**
- The `encryption` block must exist
- `enabled` must be explicitly `true`
- `algorithm` must be `AES-256`, `AES-256-GCM`, or `RSA-4096`

### Policy 2: Public Access Controls

**What it checks:**
```json
{
  "storage": {
    "public_access": {
      "block_public_acls": true,         ← all four must be true
      "block_public_policy": true,
      "ignore_public_acls": true,
      "restrict_public_buckets": true
    }
  }
}
```

**Why four settings?** AWS (and similar clouds) have multiple independent mechanisms for public access. A bucket can be made public through ACLs, bucket policies, or cross-account access. All four gates must be closed.

### Policy 3: Audit Logging

**What it checks:**
```json
{
  "storage": {
    "logging": {
      "enabled": true,
      "destination": "s3://audit-logs-bucket/...",  ← must not be empty
      "retention_days": 365                          ← must be >= 90
    }
  }
}
```

**Why 90 days minimum?** Most incident investigations require at least 90 days of log history to reconstruct attacker timelines. Many regulations require 1 year.

### Policy 4: Environment and Metadata Tags

**What it checks:**
```json
{
  "storage": {
    "tags": {
      "environment": "production",           ← must be an approved value
      "owner": "team@company.com",           ← must be present
      "data_classification": "confidential"  ← must be an approved value
    }
  }
}
```

**Approved environment values:** `production`, `staging`, `development`, `sandbox`

**Approved data classifications:** `public`, `internal`, `confidential`, `restricted`

### Policy 5: Versioning (Production Only)

For `environment: "production"` configs:
- Versioning must be enabled
- This protects against accidental deletion and ransomware

---

## 7. NIST 800-53 Control Mappings

NIST SP 800-53 Rev 5 is the gold standard control framework used by US federal agencies and adopted by most enterprise security programs. The table below maps each policy rule to the relevant controls.

| Policy | Control ID | Control Name | Description |
|--------|-----------|--------------|-------------|
| Encryption enabled | **SC-28** | Protection of Information at Rest | Implements cryptographic mechanisms to prevent unauthorized disclosure of information at rest |
| Strong algorithm | **SC-28(1)** | Cryptographic Protection | Requires use of approved cryptographic algorithms |
| Block public ACLs | **AC-3** | Access Enforcement | Enforces approved authorizations for logical access to information |
| Block public policy | **AC-6** | Least Privilege | Employs principle of least privilege, limiting access to only what is necessary |
| Ignore public ACLs | **SC-7** | Boundary Protection | Monitors and controls communications at the external boundary |
| Restrict public buckets | **SC-7(5)** | Deny by Default | Denies network communications traffic by default |
| Logging enabled | **AU-2** | Event Logging | Identifies the types of events that the system is capable of logging |
| Log content | **AU-3** | Content of Audit Records | Ensures audit records contain sufficient information |
| Log destination | **AU-9** | Protection of Audit Information | Protects audit information from unauthorized access, modification, and deletion |
| Log generation | **AU-12** | Audit Record Generation | Provides audit record generation capability |
| Monitoring | **SI-4** | System Monitoring | Monitors the system to detect attacks and indicators of potential attacks |
| Resource tagging | **CM-8** | System Component Inventory | Develops and documents an inventory of system components |
| Tag updates | **CM-8(1)** | Updates During Installation | Updates the inventory during component installation/removal |
| Asset management | **PM-5** | System Inventory | Develops and maintains an inventory of its systems |
| Versioning/backup | **CP-9** | System Backup | Conducts backups of user-level and system-level information |
| Recovery | **CP-10** | System Recovery | Provides for the recovery and reconstitution of systems after disruption |

### Mapping to Other Frameworks

| Policy | PCI DSS v4.0 | HIPAA | SOC 2 | ISO 27001:2022 |
|--------|-------------|-------|-------|----------------|
| Encryption | Req 3.5 | §164.312(a)(2)(iv) | CC6.7 | A.8.24 |
| No Public Access | Req 1.3 | §164.312(e)(1) | CC6.6 | A.8.20 |
| Logging | Req 10.2 | §164.312(b) | CC7.2 | A.8.15 |
| Tagging/Inventory | Req 12.3 | §164.308(a)(1) | CC6.1 | A.8.8 |
| Versioning | Req 12.5 | §164.308(a)(7) | A1.2 | A.8.13 |

---

## 8. Business Risk of Each Violation

Understanding the business impact — not just the technical impact — is what elevates security work from checkbox compliance to genuine risk management.

### Violation 1: Encryption Disabled

**Technical Impact:**  
Data stored in the bucket exists as plaintext bytes. Any party who can access the underlying storage medium — cloud provider employees, attackers with stolen credentials, anyone who finds an improperly decommissioned disk — can read the data directly.

**Business Impact:**
- **Regulatory Fines:** GDPR fines can reach €20 million or 4% of global annual revenue. HIPAA fines up to $1.9 million per violation category per year. PCI DSS level 1 fines up to $100,000/month.
- **Breach Notification Costs:** Average cost of notifying affected individuals is $5–$10 per person. A breach of 1 million records costs $5M–$10M in notifications alone.
- **Loss of Certifications:** A SOC 2 or PCI DSS audit will immediately fail if unencrypted storage is found. Loss of certification can disqualify the company from enterprise contracts.
- **Reputational Damage:** Customer trust, once lost, rarely returns fully. Stock prices of public companies typically drop 3–7% immediately following a disclosed breach.

**Real-World Example:** In 2019, a major financial institution left customer data in unencrypted S3 buckets, exposing over 100 million records. The eventual settlement exceeded $190 million.

---

### Violation 2: Public Access Enabled

**Technical Impact:**  
The storage resource is accessible from the public internet. Any person or automated tool (like a bucket-scanning bot) can list and download objects without authentication.

**Business Impact:**
- **Immediate Data Exposure:** Unlike encryption failures (which require further exploitation), public access means data is exposed the moment the misconfiguration exists. Automated scanners detect open buckets within minutes of creation.
- **Intellectual Property Theft:** Source code, ML models, product roadmaps, and competitive intelligence stored in public buckets can be harvested silently.
- **Credential Exposure:** Many teams store `.env` files, SSH keys, and API tokens in storage. Exposed credentials lead to full cloud account takeover.
- **Ransomware Targeting:** Threat actors identify publicly accessible storage, download the data, delete it, and demand payment for its return.

**Real-World Example:** The Capital One breach in 2019 resulted in 100 million exposed records. Root cause: misconfigured access controls on cloud storage. The resulting fine was $80 million. Total costs exceeded $500 million.

---

### Violation 3: Logging Disabled

**Technical Impact:**  
There is no record of who accessed, modified, or deleted objects in the storage resource. Intrusion detection, forensic investigation, and compliance attestation all become impossible.

**Business Impact:**
- **Inability to Detect Breaches:** Without logs, ongoing exfiltration can continue for months or years undetected. The average breach dwell time is 277 days — but without logs, it may never be detected at all.
- **Failed Forensic Investigations:** When a breach is eventually discovered, investigators need logs to determine what was accessed, when, and by whom. No logs mean no answers, extending incident response timelines from days to months.
- **Regulatory Non-Compliance:** HIPAA, PCI DSS, SOC 2, and FedRAMP all explicitly require audit logging. Auditors will issue a material finding for missing logs, which can result in failed certifications and loss of contracts.
- **Litigation Exposure:** In a breach lawsuit, the absence of logs can be treated as evidence of negligence. "You couldn't even tell us who accessed patient records" is devastating in court.

---

### Violation 4: Missing or Invalid Environment Tags

**Technical Impact:**  
Resources without proper tags cannot be reliably included in security scans, compliance reports, or cost analyses. They become "shadow IT" — infrastructure that exists but isn't governed.

**Business Impact:**
- **Runaway Cloud Costs:** Untagged resources accumulate costs that cannot be attributed to teams or projects. Organizations routinely waste 30–40% of cloud spend on forgotten, untagged resources.
- **Incident Response Failures:** When an incident occurs, responders need to rapidly identify all affected resources. Without tags, they cannot determine which resources belong to which application, team, or data domain.
- **Compliance Scope Creep:** PCI DSS and HIPAA require organizations to know exactly which systems are in scope. Untagged resources may inadvertently expand the compliance scope — or, worse, cause in-scope systems to be missed.
- **Access Control Drift:** Many organizations use tags to drive automated IAM policies. Untagged resources may receive overly permissive default access controls.

---

### Violation 5: Versioning Disabled (Production)

**Technical Impact:**  
Deleted or overwritten objects cannot be recovered. A single `rm -rf` command or ransomware event results in permanent, unrecoverable data loss.

**Business Impact:**
- **Ransomware Vulnerability:** Ransomware attacks increasingly target cloud storage. Without versioning, attackers can delete data and demand payment. With versioning, recovery is a single API call.
- **Accidental Data Loss:** Human error is the leading cause of data loss. A developer running the wrong script, a misconfigured automation job, or a botched migration can delete critical data permanently.
- **Recovery Time Objective (RTO) Breach:** Most organizations have RTOs of hours, not days. Without versioning, recovery from data loss may require restoring from a multi-day-old backup, breaching SLAs and customer contracts.
- **DR/BCP Audit Failures:** Business continuity auditors require evidence that data can be recovered. Disabled versioning on production storage is a finding in any BCP/DR audit.

---

## 9. How This Supports Compliance

### Continuous Compliance vs. Point-in-Time Audits

Traditional compliance works on annual audit cycles: once a year, an auditor reviews your controls and issues a report. Between audits, controls can drift, configurations can change, and violations can go undetected for 11 months.

Policy-as-Code transforms compliance from a periodic snapshot into a **continuous state**:

```
Traditional Compliance:
Jan ──── audit ──── Feb ──── Mar ──── ... ──── Dec ──── audit ──── Jan
         PASS       ← Unknown state for 11 months →        PASS or FAIL?

Policy-as-Code Compliance:
Every single commit is checked. Drift is impossible to introduce silently.
Jan ──── ✅ ──── ✅ ──── ✅ ──── ✅ ──── ✅ ──── ✅ ──── ✅ ──── ✅ ──── Dec
```

### Audit Evidence Generation

Every GitHub Actions run produces a timestamped, tamper-resistant log that shows:
- Which commit was evaluated
- What policies were checked
- What the results were (PASS/FAIL)
- Who triggered the pipeline (the committer)

This log can be exported and presented to auditors as evidence that security controls are continuously enforced. This is exactly what SOC 2 Type II, FedRAMP, and ISO 27001 auditors want to see.

### Supporting the Three Lines of Defense

| Line | Role | How This Pipeline Supports It |
|------|------|-------------------------------|
| **1st Line** — Development teams | Own and operate the systems | Developers get immediate feedback on policy violations in their own PRs |
| **2nd Line** — Risk and Compliance | Set policies and monitor adherence | Policies are in version control; compliance can review and approve changes |
| **3rd Line** — Internal Audit | Independent assurance | Pipeline logs provide objective, timestamped evidence of control operation |

---

## 10. Extending the Pipeline

### Add New Policy Rules

To add a new policy, add a `deny` rule to `cloud-security-policy.rego`:

```rego
# Example: Enforce TLS minimum version
deny contains msg if {
    input.storage.tls.minimum_version != "TLS_1_2"
    msg := "POLICY VIOLATION [SC-8] — TLS minimum version must be 1.2 or higher."
}
```

### Test New Policies Locally

```bash
# Test a single file
conftest test configs/secure-storage.json --policy policies/

# Verify your new rule fires on the insecure config
conftest test configs/insecure-storage.json --policy policies/

# Run with verbose output to see all rule evaluations
conftest test configs/secure-storage.json --policy policies/ --trace
```

### Integrate with Real Terraform

In a real infrastructure pipeline, generate the Conftest input from Terraform:

```bash
# Generate Terraform plan in JSON format
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# Run policy checks against the plan
conftest test tfplan.json --policy policies/ --all-namespaces
```

### Add More Config Types

Create additional config files in `configs/` for different resource types:
- `configs/network-security-group.json` — Firewall rules
- `configs/iam-role-policy.json` — IAM permissions
- `configs/database-instance.json` — RDS/CloudSQL settings
- `configs/kubernetes-deployment.json` — K8s security contexts

Then add corresponding policy files in `policies/`:
- `policies/network-policy.rego`
- `policies/iam-policy.rego`
- `policies/database-policy.rego`

### Integrate with Slack or Jira

Add a step to your workflow that posts violations to Slack:

```yaml
- name: Post Violations to Slack
  if: failure()
  uses: slackapi/slack-github-action@v1.27.0
  with:
    channel-id: "security-alerts"
    slack-message: |
      :red_circle: Policy violation detected in `${{ github.repository }}`
      Branch: `${{ github.ref_name }}`
      Commit: `${{ github.sha }}`
      Triggered by: `${{ github.actor }}`
      View pipeline: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
  env:
    SLACK_BOT_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
```

---

## 11. Glossary

| Term | Definition |
|------|------------|
| **OPA** | Open Policy Agent — an open-source, general-purpose policy engine that decouples policy from application logic |
| **Rego** | The declarative policy language used to write OPA rules. Pronounced "ray-go" |
| **Conftest** | A CLI tool that uses OPA to test structured configuration files (JSON, YAML, TOML, HCL, etc.) |
| **Policy-as-Code** | The practice of expressing security and compliance policies in a machine-readable, version-controlled format |
| **Shift-Left Security** | Moving security controls earlier in the software development lifecycle, closer to the development stage |
| **NIST 800-53** | A catalog of security and privacy controls published by the National Institute of Standards and Technology |
| **NIST 800-53 Control** | A specific security safeguard or countermeasure (e.g., "SC-28: Protection of Information at Rest") |
| **CI/CD** | Continuous Integration / Continuous Deployment — automated pipelines for building, testing, and deploying software |
| **Branch Protection** | A GitHub feature that prevents merging unless specific status checks (like this pipeline) pass |
| **Guardrail** | An automated control that prevents a policy violation from being deployed, as opposed to detecting it after the fact |
| **Encryption at Rest** | Encrypting data when it is stored (on disk), as opposed to encryption in transit (over the network) |
| **ACL** | Access Control List — a set of rules that grant or deny access to a resource |
| **Audit Trail** | A timestamped, immutable record of events (access, modifications) used for forensics and compliance |
| **Data Classification** | Categorizing data by sensitivity (public, internal, confidential, restricted) to apply appropriate controls |
| **GRC** | Governance, Risk, and Compliance — the three pillars of organizational security management |

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Author

Built as a portfolio project demonstrating DevSecOps and GRC engineering skills:
- Policy-as-Code implementation
- NIST 800-53 control mapping
- CI/CD security integration
- Cloud security baselines
- Compliance automation

---

*"Security policies that live only in documents are aspirations. Security policies enforced by code are controls."*

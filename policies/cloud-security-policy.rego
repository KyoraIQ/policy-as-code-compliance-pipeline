# ==============================================================================
# FILE: policies/cloud-security-policy.rego
# PURPOSE: Open Policy Agent (OPA) rules that enforce mandatory cloud storage
#          security controls. Each rule is mapped to NIST 800-53 Rev 5 controls.
#
# HOW REGO WORKS:
#   - Rules evaluate to `true` (allowed) or `undefined/false` (denied)
#   - `deny` rules accumulate violation messages
#   - Conftest collects all `deny` messages and reports them
#   - If any `deny` rule fires, the policy check fails
#
# PACKAGE NAMING:
#   The package name is the namespace Conftest uses.
#   `conftest test --all-namespaces` runs all packages.
# ==============================================================================

package cloud.security.storage

# ──────────────────────────────────────────────────────────────────────────────
# METADATA — describes this policy set
# ──────────────────────────────────────────────────────────────────────────────

# METADATA
# title: Cloud Storage Security Policy
# description: Enforces baseline security controls for cloud storage resources
# authors:
#   - DevSecOps Team
# custom:
#   compliance_frameworks:
#     - NIST SP 800-53 Rev 5
#     - CIS Benchmark for Cloud Storage
#     - ISO/IEC 27001:2022

# ──────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ──────────────────────────────────────────────────────────────────────────────

import rego.v1

# ──────────────────────────────────────────────────────────────────────────────
# HELPER: default_deny
# Establishes a safe default — deny everything unless explicitly allowed.
# This follows the security principle of "deny by default, allow by exception."
# ──────────────────────────────────────────────────────────────────────────────

default allow := false

allow if {
    # All deny rules must be empty (no violations) for allow to be true
    count(deny) == 0
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 1: ENCRYPTION AT REST MUST BE ENABLED
#
# RATIONALE:
#   Encryption at rest protects stored data from unauthorized access in the
#   event of physical media theft, improper decommissioning, or cloud provider
#   compromise. Without encryption, a leaked storage bucket exposes plaintext
#   data directly.
#
# NIST 800-53 CONTROLS:
#   SC-28   — Protection of Information at Rest
#   SC-28(1) — Cryptographic Protection (enhancement)
#   SI-12   — Information Management and Retention
#
# BUSINESS RISK:
#   Unencrypted storage is a direct violation of PCI DSS, HIPAA, SOC 2, and
#   most data protection regulations. A breach involving unencrypted customer
#   data can result in regulatory fines, breach notification costs, and
#   irreparable reputational damage.
# ══════════════════════════════════════════════════════════════════════════════

# Rule 1a: encryption object must exist in the config
deny contains msg if {
    not input.storage.encryption
    msg := "POLICY VIOLATION [SC-28] — 'storage.encryption' block is missing. Encryption configuration is required for all storage resources."
}

# Rule 1b: encryption must be explicitly enabled (not just present)
deny contains msg if {
    input.storage.encryption
    not input.storage.encryption.enabled == true
    msg := "POLICY VIOLATION [SC-28] — 'storage.encryption.enabled' must be set to true. Data at rest must be encrypted."
}

# Rule 1c: encryption algorithm must be AES-256 or better
deny contains msg if {
    input.storage.encryption.enabled == true
    algo := input.storage.encryption.algorithm
    not _strong_algorithm(algo)
    msg := sprintf("POLICY VIOLATION [SC-28(1)] — Encryption algorithm '%v' is not approved. Use AES-256, AES-256-GCM, or RSA-4096.", [algo])
}

# Helper: approved encryption algorithms
_strong_algorithm(algo) if algo == "AES-256"
_strong_algorithm(algo) if algo == "AES-256-GCM"
_strong_algorithm(algo) if algo == "RSA-4096"

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 2: PUBLIC ACCESS MUST BE DISABLED
#
# RATIONALE:
#   Publicly accessible storage is one of the most common causes of cloud data
#   breaches. Misconfigured S3 buckets, Azure Blob containers, or GCS buckets
#   have exposed billions of sensitive records. Public access should be
#   explicitly blocked at the resource level, independent of IAM policies.
#
# NIST 800-53 CONTROLS:
#   AC-3    — Access Enforcement
#   AC-6    — Least Privilege
#   SC-7    — Boundary Protection
#   SC-7(5) — Deny by Default / Allow by Exception
#
# BUSINESS RISK:
#   A single misconfigured public storage resource can expose entire customer
#   databases, application secrets, backups, or PII. This is the root cause of
#   numerous high-profile breaches. Regulatory penalties under GDPR, CCPA, and
#   HIPAA can reach hundreds of millions of dollars.
# ══════════════════════════════════════════════════════════════════════════════

# Rule 2a: public_access block must exist
deny contains msg if {
    not input.storage.public_access
    msg := "POLICY VIOLATION [AC-3, SC-7] — 'storage.public_access' configuration block is missing. Public access settings are required."
}

# Rule 2b: block_public_acls must be true
deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.block_public_acls == true
    msg := "POLICY VIOLATION [AC-3] — 'storage.public_access.block_public_acls' must be true. Public ACLs must be blocked."
}

# Rule 2c: block_public_policy must be true
deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.block_public_policy == true
    msg := "POLICY VIOLATION [AC-6] — 'storage.public_access.block_public_policy' must be true. Public bucket policies must be blocked."
}

# Rule 2d: ignore_public_acls must be true
deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.ignore_public_acls == true
    msg := "POLICY VIOLATION [SC-7] — 'storage.public_access.ignore_public_acls' must be true. Existing public ACLs must be ignored."
}

# Rule 2e: restrict_public_buckets must be true
deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.restrict_public_buckets == true
    msg := "POLICY VIOLATION [SC-7(5)] — 'storage.public_access.restrict_public_buckets' must be true. Cross-account public access must be restricted."
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 3: AUDIT LOGGING MUST BE ENABLED
#
# RATIONALE:
#   Logging creates an immutable audit trail of who accessed or modified data,
#   when, and from where. Without logs, incident response and forensic
#   investigation are impossible. Logs are also required for compliance
#   attestation and anomaly detection.
#
# NIST 800-53 CONTROLS:
#   AU-2    — Event Logging
#   AU-3    — Content of Audit Records
#   AU-9    — Protection of Audit Information
#   AU-12   — Audit Record Generation
#   SI-4    — System Monitoring
#
# BUSINESS RISK:
#   Without logging, organizations cannot detect data exfiltration, insider
#   threats, or unauthorized access. Most compliance frameworks (SOC 2, PCI DSS,
#   HIPAA, FedRAMP) require audit logging as a mandatory control. Absence of
#   logs can result in failed audits and loss of certifications.
# ══════════════════════════════════════════════════════════════════════════════

# Rule 3a: logging block must exist
deny contains msg if {
    not input.storage.logging
    msg := "POLICY VIOLATION [AU-2, AU-12] — 'storage.logging' configuration block is missing. Audit logging configuration is required."
}

# Rule 3b: logging must be explicitly enabled
deny contains msg if {
    input.storage.logging
    not input.storage.logging.enabled == true
    msg := "POLICY VIOLATION [AU-2] — 'storage.logging.enabled' must be true. Access and event logging must be enabled."
}

# Rule 3c: a log destination (bucket/sink) must be specified
deny contains msg if {
    input.storage.logging.enabled == true
    not input.storage.logging.destination
    msg := "POLICY VIOLATION [AU-9] — 'storage.logging.destination' must be set. Logs must be shipped to a dedicated audit destination (e.g., a centralized logging bucket or SIEM)."
}

# Rule 3d: log destination must not be empty string
deny contains msg if {
    input.storage.logging.enabled == true
    input.storage.logging.destination == ""
    msg := "POLICY VIOLATION [AU-9] — 'storage.logging.destination' must not be empty. Specify a valid log destination bucket or sink."
}

# Rule 3e: log retention period must be set and meet minimum (90 days)
deny contains msg if {
    input.storage.logging.enabled == true
    not input.storage.logging.retention_days
    msg := "POLICY VIOLATION [AU-3] — 'storage.logging.retention_days' must be set. Log retention period is required for incident response and forensics."
}

deny contains msg if {
    input.storage.logging.enabled == true
    input.storage.logging.retention_days < 90
    msg := sprintf("POLICY VIOLATION [AU-3] — Log retention is set to %v days. Minimum required retention is 90 days to support incident investigation.", [input.storage.logging.retention_days])
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 4: ENVIRONMENT TAG MUST EXIST AND BE VALID
#
# RATIONALE:
#   Tags are the primary mechanism for asset inventory, cost attribution,
#   policy scoping, and blast-radius control during incidents. An untagged
#   resource cannot be reliably identified, classified, or governed.
#   Environment tags also drive automated policy enforcement (e.g., stricter
#   controls in production vs. development).
#
# NIST 800-53 CONTROLS:
#   CM-8    — System Component Inventory
#   CM-8(1) — Updates During Installation and Removal
#   PM-5    — System Inventory
#   SA-9    — External System Services (cloud asset tracking)
#
# BUSINESS RISK:
#   Untagged resources lead to shadow IT, runaway cloud costs, and inability
#   to determine asset ownership during incidents. In a breach scenario,
#   untagged resources may be overlooked during forensics. Tagging also enables
#   automated compliance scanning, cost chargebacks, and data classification.
# ══════════════════════════════════════════════════════════════════════════════

# Rule 4a: tags object must exist
deny contains msg if {
    not input.storage.tags
    msg := "POLICY VIOLATION [CM-8] — 'storage.tags' block is missing. All resources must have metadata tags for inventory and governance."
}

# Rule 4b: environment tag must be present
deny contains msg if {
    input.storage.tags
    not input.storage.tags.environment
    msg := "POLICY VIOLATION [CM-8] — 'storage.tags.environment' is missing. All resources must be tagged with their deployment environment."
}

# Rule 4c: environment tag must be one of the approved values
deny contains msg if {
    input.storage.tags.environment
    env := input.storage.tags.environment
    not _valid_environment(env)
    msg := sprintf("POLICY VIOLATION [CM-8] — Environment tag value '%v' is not recognized. Allowed values: production, staging, development, sandbox.", [env])
}

# Helper: approved environment tag values
_valid_environment(env) if env == "production"
_valid_environment(env) if env == "staging"
_valid_environment(env) if env == "development"
_valid_environment(env) if env == "sandbox"

# Rule 4d: owner tag must be present (accountability)
deny contains msg if {
    input.storage.tags
    not input.storage.tags.owner
    msg := "POLICY VIOLATION [CM-8(1)] — 'storage.tags.owner' is missing. Every resource must have an owner tag to establish accountability."
}

# Rule 4e: data_classification tag must be present
deny contains msg if {
    input.storage.tags
    not input.storage.tags.data_classification
    msg := "POLICY VIOLATION [PM-5] — 'storage.tags.data_classification' is missing. Resources must be classified (e.g., public, internal, confidential, restricted)."
}

# Rule 4f: data_classification must use approved values
deny contains msg if {
    input.storage.tags.data_classification
    classification := input.storage.tags.data_classification
    not _valid_classification(classification)
    msg := sprintf("POLICY VIOLATION [PM-5] — Data classification '%v' is not an approved value. Use: public, internal, confidential, or restricted.", [classification])
}

# Helper: approved data classification values
_valid_classification(c) if c == "public"
_valid_classification(c) if c == "internal"
_valid_classification(c) if c == "confidential"
_valid_classification(c) if c == "restricted"

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 5: VERSIONING AND BACKUP CONTROLS (BONUS)
#
# RATIONALE:
#   Object versioning protects against accidental deletion and ransomware
#   attacks. Without versioning, data loss events are unrecoverable.
#
# NIST 800-53 CONTROLS:
#   CP-9    — System Backup
#   CP-10   — System Recovery and Reconstitution
#   SI-12   — Information Management and Retention
# ══════════════════════════════════════════════════════════════════════════════

# Rule 5a: versioning must be enabled (warn if not set; enforced for production)
deny contains msg if {
    input.storage.tags.environment == "production"
    not input.storage.versioning
    msg := "POLICY VIOLATION [CP-9] — 'storage.versioning' is missing for a production resource. Versioning is mandatory in production to support recovery from accidental deletion or ransomware."
}

deny contains msg if {
    input.storage.tags.environment == "production"
    input.storage.versioning
    not input.storage.versioning.enabled == true
    msg := "POLICY VIOLATION [CP-9] — 'storage.versioning.enabled' must be true for production resources. Versioning is required to meet backup and recovery objectives."
}

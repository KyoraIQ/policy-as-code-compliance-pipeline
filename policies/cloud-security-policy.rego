package cloud.security.storage

import rego.v1

# ==============================================================================
# POLICY: Cloud Storage Security
# FRAMEWORK: NIST SP 800-53 Rev 5
# ==============================================================================

default allow := false

allow if {
    count(deny) == 0
}

# ==============================================================================
# POLICY 1: ENCRYPTION AT REST (NIST SC-28)
# ==============================================================================

deny contains msg if {
    not input.storage.encryption
    msg := "POLICY VIOLATION [SC-28] - storage.encryption block is missing. Encryption configuration is required."
}

deny contains msg if {
    input.storage.encryption
    not input.storage.encryption.enabled == true
    msg := "POLICY VIOLATION [SC-28] - storage.encryption.enabled must be true. Data at rest must be encrypted."
}

deny contains msg if {
    input.storage.encryption.enabled == true
    algo := input.storage.encryption.algorithm
    not _strong_algorithm(algo)
    msg := sprintf("POLICY VIOLATION [SC-28(1)] - Encryption algorithm '%v' is not approved. Use AES-256, AES-256-GCM, or RSA-4096.", [algo])
}

_strong_algorithm(algo) if algo == "AES-256"
_strong_algorithm(algo) if algo == "AES-256-GCM"
_strong_algorithm(algo) if algo == "RSA-4096"

# ==============================================================================
# POLICY 2: PUBLIC ACCESS MUST BE DISABLED (NIST AC-3, SC-7)
# ==============================================================================

deny contains msg if {
    not input.storage.public_access
    msg := "POLICY VIOLATION [AC-3, SC-7] - storage.public_access block is missing. Public access settings are required."
}

deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.block_public_acls == true
    msg := "POLICY VIOLATION [AC-3] - storage.public_access.block_public_acls must be true."
}

deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.block_public_policy == true
    msg := "POLICY VIOLATION [AC-6] - storage.public_access.block_public_policy must be true."
}

deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.ignore_public_acls == true
    msg := "POLICY VIOLATION [SC-7] - storage.public_access.ignore_public_acls must be true."
}

deny contains msg if {
    input.storage.public_access
    not input.storage.public_access.restrict_public_buckets == true
    msg := "POLICY VIOLATION [SC-7(5)] - storage.public_access.restrict_public_buckets must be true."
}

# ==============================================================================
# POLICY 3: AUDIT LOGGING MUST BE ENABLED (NIST AU-2, AU-12)
# ==============================================================================

deny contains msg if {
    not input.storage.logging
    msg := "POLICY VIOLATION [AU-2] - storage.logging block is missing. Audit logging configuration is required."
}

deny contains msg if {
    input.storage.logging
    not input.storage.logging.enabled == true
    msg := "POLICY VIOLATION [AU-2] - storage.logging.enabled must be true. Access logging must be enabled."
}

deny contains msg if {
    input.storage.logging.enabled == true
    not input.storage.logging.destination
    msg := "POLICY VIOLATION [AU-9] - storage.logging.destination must be set. Logs must go to a centralized audit destination."
}

deny contains msg if {
    input.storage.logging.enabled == true
    input.storage.logging.destination == ""
    msg := "POLICY VIOLATION [AU-9] - storage.logging.destination must not be empty."
}

deny contains msg if {
    input.storage.logging.enabled == true
    not input.storage.logging.retention_days
    msg := "POLICY VIOLATION [AU-3] - storage.logging.retention_days must be set."
}

deny contains msg if {
    input.storage.logging.enabled == true
    input.storage.logging.retention_days < 90
    msg := sprintf("POLICY VIOLATION [AU-3] - Log retention is %v days. Minimum required is 90 days.", [input.storage.logging.retention_days])
}

# ==============================================================================
# POLICY 4: TAGS MUST EXIST AND BE VALID (NIST CM-8)
# ==============================================================================

deny contains msg if {
    not input.storage.tags
    msg := "POLICY VIOLATION [CM-8] - storage.tags block is missing. All resources must be tagged."
}

deny contains msg if {
    input.storage.tags
    not input.storage.tags.environment
    msg := "POLICY VIOLATION [CM-8] - storage.tags.environment is missing. All resources must have an environment tag."
}

deny contains msg if {
    input.storage.tags.environment
    env := input.storage.tags.environment
    not _valid_environment(env)
    msg := sprintf("POLICY VIOLATION [CM-8] - Environment tag value '%v' is not valid. Allowed: production, staging, development, sandbox.", [env])
}

_valid_environment(env) if env == "production"
_valid_environment(env) if env == "staging"
_valid_environment(env) if env == "development"
_valid_environment(env) if env == "sandbox"

deny contains msg if {
    input.storage.tags
    not input.storage.tags.owner
    msg := "POLICY VIOLATION [CM-8(1)] - storage.tags.owner is missing. Every resource must have an owner tag."
}

deny contains msg if {
    input.storage.tags
    not input.storage.tags.data_classification
    msg := "POLICY VIOLATION [PM-5] - storage.tags.data_classification is missing. Resources must be classified."
}

deny contains msg if {
    input.storage.tags.data_classification
    classification := input.storage.tags.data_classification
    not _valid_classification(classification)
    msg := sprintf("POLICY VIOLATION [PM-5] - Data classification '%v' is not valid. Use: public, internal, confidential, or restricted.", [classification])
}

_valid_classification(c) if c == "public"
_valid_classification(c) if c == "internal"
_valid_classification(c) if c == "confidential"
_valid_classification(c) if c == "restricted"

# ==============================================================================
# POLICY 5: VERSIONING REQUIRED IN PRODUCTION (NIST CP-9)
# ==============================================================================

deny contains msg if {
    input.storage.tags.environment == "production"
    not input.storage.versioning
    msg := "POLICY VIOLATION [CP-9] - storage.versioning is missing for a production resource. Versioning is mandatory in production."
}

deny contains msg if {
    input.storage.tags.environment == "production"
    input.storage.versioning
    not input.storage.versioning.enabled == true
    msg := "POLICY VIOLATION [CP-9] - storage.versioning.enabled must be true for production resources."
}

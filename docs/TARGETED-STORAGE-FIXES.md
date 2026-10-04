# Targeted storage and interface fixes — 2026-10-04

The latest run failed to save observations with EACCES while creating /workspace/.security-results. This is a mount ownership/permission failure, not a missing mkdir call. The model also guessed eth0 and passed empty map inputs.

- Deployment resolves the Security service runtime UID/GID through Compose. A one-off provisioning container creates/sets ownership on only .security-results and its observations directory. It rejects symlinks and does not recursively chown the workspace. CHOWN/FOWNER/DAC_OVERRIDE capabilities are granted only to that one-off process; normal service capabilities remain unchanged.
- Deployment then tests a file write using the normal configured runtime identity. Read-only mounts, inaccessible ancestors and filesystem restrictions fail explicitly.
- Host operations preflight observation storage before delegation. A failure names the repair script and stops before an expensive scan. A race-time save failure preserves observations, returns observation_path:null and map_ready:false, and explains the error.
- Interface schemas request automatic selection when omitted; invalid-interface errors list actual physical host interfaces and recommend get_host_interface_info({}). Pi container sysfs is not used as laptop evidence.
- Map schema guidance requests a nonempty path list and exactly one input form. Empty path arrays remain correctly rejected. Prompts request storage-error checks and device-specific evidence for connections, ports, DNS and host identity.
- The prior ESM verifier fix and Docker build-time SDK check are included.

Validation: 56 gateway tests passed, one UID-switch test skipped because this executor rejects child UID/GID switching. Directory provisioning, unrelated file preservation, symlink rejection and pre-scan failure tests passed. Native Pi checks passed all 132 names, 18 intents and settings replay. No Docker daemon or target model is available here, so the live Compose permission repair and model behavior require host validation.

Install with the complete bundle installer. For an already-updated source tree, rebuild the Security image and run bash scripts/prepare-security-results.sh from the gateway repository. Use a new Pi conversation after the full installer updates prompts.

Commit subjects:
- Gateway: fix(recon): provision writable results and preflight observation storage
- Pi: fix(prompt): recover host interfaces and ground network claims

#!/usr/bin/env bash
set -euo pipefail

# One-time trust bootstrap for the fixed, disposable Sentinel Blue Azure range.
# Run from an authenticated Azure Cloud Shell. It creates no client secret and
# does not start, restart, or otherwise mutate a virtual machine.

readonly GITHUB_REPOSITORY="joshua08271/Sentinel-Blue"
readonly GITHUB_ENVIRONMENT="azure-lab"
readonly GITHUB_BRANCH="main"
readonly RESOURCE_GROUP="sentinel-blue-range-wus2"
readonly IDENTITY_NAME="sb-github-oidc"
readonly FEDERATED_CREDENTIAL_NAME="github-azure-lab"
readonly ROLE_NAME="Sentinel Blue Private Lab Operator"
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly OIDC_AUDIENCE="api://AzureADTokenExchange"
readonly OIDC_SUBJECT="repo:${GITHUB_REPOSITORY}:environment:${GITHUB_ENVIRONMENT}"
readonly EXPECTED_VMS="sb-controller sb-linux-target sb-redsim sb-windows-target"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

for executable in az python3; do
  command -v "${executable}" >/dev/null 2>&1 || fail "${executable} is required"
done

account_json="$(az account show --output json 2>/dev/null)" || \
  fail "authenticate to Azure before running this bootstrap"
subscription_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"${account_json}")"
tenant_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["tenantId"])' <<<"${account_json}")"
[[ -n "${subscription_id}" && -n "${tenant_id}" ]] || fail "Azure account identifiers are missing"

group_json="$(az group show --name "${RESOURCE_GROUP}" --output json 2>/dev/null)" || \
  fail "resource group ${RESOURCE_GROUP} is unavailable in the selected subscription"
group_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"${group_json}")"
expected_group_id="/subscriptions/${subscription_id}/resourceGroups/${RESOURCE_GROUP}"
[[ "${group_id,,}" == "${expected_group_id,,}" ]] || fail "resource-group ID does not match the fixed scope"

mapfile -t actual_vms < <(
  az vm list \
    --resource-group "${RESOURCE_GROUP}" \
    --query "[].name" \
    --output tsv | LC_ALL=C sort
)
read -r -a expected_vms <<<"${EXPECTED_VMS}"
[[ "${actual_vms[*]}" == "${expected_vms[*]}" ]] || \
  fail "VM inventory differs from the exact four-host allowlist"
for vm in "${expected_vms[@]}"; do
  mapfile -t nic_ids < <(
    az vm show \
      --resource-group "${RESOURCE_GROUP}" \
      --name "${vm}" \
      --query "networkProfile.networkInterfaces[].id" \
      --output tsv
  )
  [[ "${#nic_ids[@]}" -gt 0 ]] || fail "${vm} has no readable network interface"
  for nic_id in "${nic_ids[@]}"; do
    public_id="$(az network nic show \
      --ids "${nic_id}" \
      --query "ipConfigurations[?publicIPAddress != null].publicIPAddress.id | [0]" \
      --output tsv)"
    [[ -z "${public_id}" ]] || fail "${vm} has a public-IP attachment"
  done
done

if identity_json="$(az identity show \
  --resource-group "${RESOURCE_GROUP}" \
  --name "${IDENTITY_NAME}" \
  --output json 2>/dev/null)"; then
  identity_group="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["resourceGroup"])' <<<"${identity_json}")"
  [[ "${identity_group}" == "${RESOURCE_GROUP}" ]] || fail "existing identity is outside the fixed resource group"
else
  identity_json="$(az identity create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${IDENTITY_NAME}" \
    --output json)"
fi

client_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["clientId"])' <<<"${identity_json}")"
principal_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["principalId"])' <<<"${identity_json}")"
identity_tenant_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["tenantId"])' <<<"${identity_json}")"
[[ -n "${client_id}" && -n "${principal_id}" ]] || fail "managed identity identifiers are missing"
[[ "${identity_tenant_id,,}" == "${tenant_id,,}" ]] || fail "managed identity belongs to an unexpected tenant"

role_json="$(az role definition list \
  --name "${ROLE_NAME}" \
  --scope "${group_id}" \
  --query "[0]" \
  --output json)"
if [[ -z "${role_json}" || "${role_json}" == "null" ]]; then
  role_definition="$(ROLE_DISPLAY_NAME="${ROLE_NAME}" GROUP_ID="${group_id}" python3 - <<'PY'
import json
import os

print(json.dumps({
    "Name": os.environ["ROLE_DISPLAY_NAME"],
    "IsCustom": True,
    "Description": "Operate only the fixed private Sentinel Blue VM lab through protected GitHub OIDC workflows.",
    "Actions": [
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/instanceView/read",
        "Microsoft.Compute/virtualMachines/start/action",
        "Microsoft.Compute/virtualMachines/deallocate/action",
        "Microsoft.Compute/virtualMachines/restart/action",
        "Microsoft.Compute/virtualMachines/runCommand/action",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/publicIPAddresses/read",
    ],
    "NotActions": [],
    "DataActions": [],
    "NotDataActions": [],
    "AssignableScopes": [os.environ["GROUP_ID"]],
}, sort_keys=True))
PY
)"
  az role definition create --role-definition "${role_definition}" --output none
  role_json="$(az role definition list \
    --name "${ROLE_NAME}" \
    --scope "${group_id}" \
    --query "[0]" \
    --output json)"
fi

ROLE_JSON="${role_json}" EXPECTED_SCOPE="${group_id}" EXPECTED_ROLE_NAME="${ROLE_NAME}" python3 - <<'PY'
import json
import os

expected_actions = {
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/instanceView/read",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/restart/action",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/publicIPAddresses/read",
}
role = json.loads(os.environ["ROLE_JSON"])
permissions = role.get("permissions") or []
if role.get("roleName") != os.environ["EXPECTED_ROLE_NAME"] or role.get("roleType") != "CustomRole":
    raise SystemExit("existing Azure role does not match the dedicated custom role")
if len(permissions) != 1 or set(permissions[0].get("actions") or []) != expected_actions:
    raise SystemExit("existing Azure role actions differ from the fixed least-privilege set")
for field in ("notActions", "dataActions", "notDataActions"):
    if permissions[0].get(field):
        raise SystemExit(f"existing Azure role has unexpected {field}")
scopes = [value.lower() for value in role.get("assignableScopes") or []]
if scopes != [os.environ["EXPECTED_SCOPE"].lower()]:
    raise SystemExit("existing Azure role has an unexpected assignable scope")
PY
role_definition_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"${role_json}")"
[[ -n "${role_definition_id}" ]] || fail "custom Azure role ID is missing"

validate_assignment_set() {
  ASSIGNMENTS_JSON="$1" \
  EXPECTED_SCOPE="${group_id}" \
  EXPECTED_ROLE_NAME="${ROLE_NAME}" \
  EXPECTED_ROLE_ID="${role_definition_id}" \
  python3 - <<'PY'
import json
import os

assignments = json.loads(os.environ["ASSIGNMENTS_JSON"])
if not assignments:
    print(0)
    raise SystemExit
if len(assignments) != 1:
    raise SystemExit("managed identity has unexpected additional role assignments")
assignment = assignments[0]
if assignment.get("scope", "").lower() != os.environ["EXPECTED_SCOPE"].lower():
    raise SystemExit("managed identity role assignment is outside the fixed resource group")
if assignment.get("roleDefinitionName") != os.environ["EXPECTED_ROLE_NAME"]:
    raise SystemExit("managed identity has an unexpected Azure role")
if assignment.get("roleDefinitionId", "").lower() != os.environ["EXPECTED_ROLE_ID"].lower():
    raise SystemExit("managed identity role-definition ID is unexpected")
print(1)
PY
}

assignments_json="$(az role assignment list \
  --assignee-object-id "${principal_id}" \
  --all \
  --include-inherited \
  --fill-role-definition-name true \
  --output json)"
assignment_count="$(validate_assignment_set "${assignments_json}")"
if [[ "${assignment_count}" -eq 0 ]]; then
  created=false
  for _attempt in $(seq 1 12); do
    if az role assignment create \
      --assignee-object-id "${principal_id}" \
      --assignee-principal-type ServicePrincipal \
      --role "${role_definition_id}" \
      --scope "${group_id}" \
      --output none 2>/dev/null; then
      created=true
      break
    fi
    sleep 10
  done
  [[ "${created}" == true ]] || fail "could not create the scoped role assignment"
fi

assignments_json="$(az role assignment list \
  --assignee-object-id "${principal_id}" \
  --all \
  --include-inherited \
  --fill-role-definition-name true \
  --output json)"
[[ "$(validate_assignment_set "${assignments_json}")" -eq 1 ]] || \
  fail "the exact Azure role assignment was not created"

validate_federated_set() {
  FEDERATED_CREDENTIALS_JSON="$1" \
  EXPECTED_NAME="${FEDERATED_CREDENTIAL_NAME}" \
  EXPECTED_ISSUER="${OIDC_ISSUER}" \
  EXPECTED_SUBJECT="${OIDC_SUBJECT}" \
  EXPECTED_AUDIENCE="${OIDC_AUDIENCE}" \
  python3 - <<'PY'
import json
import os

credentials = json.loads(os.environ["FEDERATED_CREDENTIALS_JSON"])
if not credentials:
    print(0)
    raise SystemExit
if len(credentials) != 1:
    raise SystemExit("managed identity has unexpected additional federated credentials")
credential = credentials[0]
if credential.get("name") != os.environ["EXPECTED_NAME"]:
    raise SystemExit("managed identity has an unexpected federated credential")
if credential.get("issuer") != os.environ["EXPECTED_ISSUER"]:
    raise SystemExit("federated credential has an unexpected issuer")
if credential.get("subject") != os.environ["EXPECTED_SUBJECT"]:
    raise SystemExit("federated credential has an unexpected subject")
if credential.get("audiences") != [os.environ["EXPECTED_AUDIENCE"]]:
    raise SystemExit("federated credential has an unexpected audience")
print(1)
PY
}

federated_credentials_json="$(az identity federated-credential list \
  --resource-group "${RESOURCE_GROUP}" \
  --identity-name "${IDENTITY_NAME}" \
  --output json)"
federated_count="$(validate_federated_set "${federated_credentials_json}")"
if [[ "${federated_count}" -eq 0 ]]; then
  az identity federated-credential create \
    --resource-group "${RESOURCE_GROUP}" \
    --identity-name "${IDENTITY_NAME}" \
    --name "${FEDERATED_CREDENTIAL_NAME}" \
    --issuer "${OIDC_ISSUER}" \
    --subject "${OIDC_SUBJECT}" \
    --audiences "${OIDC_AUDIENCE}" \
    --output none
fi

federated_credentials_json="$(az identity federated-credential list \
  --resource-group "${RESOURCE_GROUP}" \
  --identity-name "${IDENTITY_NAME}" \
  --output json)"
[[ "$(validate_federated_set "${federated_credentials_json}")" -eq 1 ]] || \
  fail "the exact federated credential was not created"

if command -v gh >/dev/null 2>&1 && gh auth status --hostname github.com >/dev/null 2>&1; then
  if environment_json="$(gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "repos/${GITHUB_REPOSITORY}/environments/${GITHUB_ENVIRONMENT}" \
    2>/dev/null)"; then
    ENVIRONMENT_JSON="${environment_json}" python3 - <<'PY'
import json
import os

environment = json.loads(os.environ["ENVIRONMENT_JSON"])
policy = environment.get("deployment_branch_policy") or {}
if policy.get("protected_branches") is not False or policy.get("custom_branch_policies") is not True:
    raise SystemExit("existing GitHub environment does not enforce selected deployment branches")
PY
  else
    gh api \
      --method PUT \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "repos/${GITHUB_REPOSITORY}/environments/${GITHUB_ENVIRONMENT}" \
      -F "deployment_branch_policy[protected_branches]=false" \
      -F "deployment_branch_policy[custom_branch_policies]=true" \
      >/dev/null
  fi

  branch_policies_json="$(gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    "repos/${GITHUB_REPOSITORY}/environments/${GITHUB_ENVIRONMENT}/deployment-branch-policies")"
  branch_policy_count="$(BRANCH_POLICIES_JSON="${branch_policies_json}" EXPECTED_BRANCH="${GITHUB_BRANCH}" python3 - <<'PY'
import json
import os

policies = json.loads(os.environ["BRANCH_POLICIES_JSON"]).get("branch_policies") or []
expected = os.environ["EXPECTED_BRANCH"]
if policies and not (
    len(policies) == 1
    and policies[0].get("name") == expected
    and policies[0].get("type") == "branch"
):
    raise SystemExit("GitHub environment deployment policies are not restricted to main")
print(len(policies))
PY
)"
  if [[ "${branch_policy_count}" -eq 0 ]]; then
    gh api \
      --method POST \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "repos/${GITHUB_REPOSITORY}/environments/${GITHUB_ENVIRONMENT}/deployment-branch-policies" \
      -f "name=${GITHUB_BRANCH}" \
      -f "type=branch" \
      >/dev/null
  fi

  gh variable set AZURE_CLIENT_ID \
    --repo "${GITHUB_REPOSITORY}" \
    --env "${GITHUB_ENVIRONMENT}" \
    --body "${client_id}"
  gh variable set AZURE_TENANT_ID \
    --repo "${GITHUB_REPOSITORY}" \
    --env "${GITHUB_ENVIRONMENT}" \
    --body "${tenant_id}"
  gh variable set AZURE_SUBSCRIPTION_ID \
    --repo "${GITHUB_REPOSITORY}" \
    --env "${GITHUB_ENVIRONMENT}" \
    --body "${subscription_id}"
  gh variable set AZURE_RESOURCE_GROUP \
    --repo "${GITHUB_REPOSITORY}" \
    --env "${GITHUB_ENVIRONMENT}" \
    --body "${RESOURCE_GROUP}"
  github_status="configured"
else
  github_status="manual"
fi

printf '\nAzure OIDC trust is ready. No client secret was created and no VM was started.\n'
printf 'GitHub repository: %s\n' "${GITHUB_REPOSITORY}"
printf 'GitHub environment: %s\n' "${GITHUB_ENVIRONMENT}"
printf 'Federated subject: %s\n' "${OIDC_SUBJECT}"
if [[ "${github_status}" == "configured" ]]; then
  printf 'GitHub environment, main-branch policy, and variables: configured\n'
else
  printf '\nGitHub CLI was not authenticated. Restrict environment %s to branch %s, then add these environment variables:\n' "${GITHUB_ENVIRONMENT}" "${GITHUB_BRANCH}"
  printf 'AZURE_CLIENT_ID=%s\n' "${client_id}"
  printf 'AZURE_TENANT_ID=%s\n' "${tenant_id}"
  printf 'AZURE_SUBSCRIPTION_ID=%s\n' "${subscription_id}"
  printf 'AZURE_RESOURCE_GROUP=%s\n' "${RESOURCE_GROUP}"
fi

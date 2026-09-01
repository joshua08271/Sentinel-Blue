# GitHub Actions access to the private Azure lab

Sentinel Blue uses GitHub Actions OpenID Connect (OIDC) for passwordless access
to the disposable Azure range. A job receives a short-lived Azure token only
when GitHub's signed identity matches this exact trust boundary:

- repository: `joshua08271/Sentinel-Blue`
- environment: `azure-lab`
- environment deployment branch: `main`
- Azure resource group: `sentinel-blue-range-wus2`
- VMs: `sb-controller`, `sb-linux-target`, `sb-redsim`, and
  `sb-windows-target`

No client secret is created or stored in GitHub. OIDC does not disable or work
around Microsoft account MFA; it removes interactive Azure sign-in from later
GitHub jobs after an authorized administrator creates the trust once.

The design follows the official guidance for [connecting GitHub Actions to
Azure with OIDC](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect),
[GitHub deployment environments](https://docs.github.com/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments),
and [Azure custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles).

## One-time bootstrap

Use Azure Cloud Shell from a browser where the Azure account signs in normally.
The account needs Owner permission, or both User Access Administrator and
Managed Identity Contributor permission, on the existing resource group.
Configuring the GitHub environment automatically also requires GitHub
repository-admin access through an authenticated `gh` CLI.

```bash
git clone https://github.com/joshua08271/Sentinel-Blue.git
cd Sentinel-Blue
bash tools/bootstrap_azure_oidc.sh
```

The script fails closed unless the selected subscription contains the exact
resource group and exactly the four expected VMs. It then creates or verifies:

1. the user-assigned identity `sb-github-oidc`;
2. the federated credential `github-azure-lab` with audience
   `api://AzureADTokenExchange`;
3. the custom role `Sentinel Blue Private Lab Operator`, assignable only at the
   exact resource-group scope; and
4. one role assignment for that identity, rejecting unexpected additional
   assignments.

The role can read the lab inventory and VM state, start/restart/deallocate only
those scoped VMs, and invoke Azure VM Run Command for later checksum-bound
deployment and defensive acceptance tests. Run Command is effectively
administrator access inside these disposable lab VMs, so do not widen the
role's scope or reuse the identity elsewhere.

The bootstrap never starts, restarts, or runs a command on a VM.

If `gh` is authenticated, the script creates the `azure-lab` environment,
restricts deployments to `main`, and writes four non-secret environment
variables. If it is not, the script prints the values. In GitHub, create the
`azure-lab` environment, select only branch `main` as a deployment branch, and
add the printed values as environment variables:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP`

These identifiers are not credentials. Never create or paste an Azure client
secret for this workflow.

## First verification

In GitHub, open **Actions → azure-lab-oidc → Run workflow**, keep branch `main`,
and select `verify`. The job authenticates with OIDC, validates the subscription
and exact resource-group ID, rejects any unexpected VM, and rejects every VM
with a public-IP attachment. It does not start the range.

`inventory` adds the four VM power states to the job summary. `deallocate` is
the only initial mutating operation and requires the exact phrase
`DEALLOCATE sentinel-blue-range-wus2`. It exists as a cost-stop control; there
is intentionally no generic Azure CLI or command input.

After `verify` passes, add a separate checksum-bound native acceptance workflow
before restarting the live campaign. That workflow must keep the same fixed
resource inventory, serialize range use, deallocate in an `always()` cleanup,
and publish only sanitized defensive results. Do not put credentials, event
topology, or offensive procedures in this public repository.

## Revocation

Deleting the federated credential immediately prevents new GitHub OIDC logins
without changing the VM deployment:

```bash
az identity federated-credential delete \
  --resource-group sentinel-blue-range-wus2 \
  --identity-name sb-github-oidc \
  --name github-azure-lab
```

Existing job tokens are short-lived. Also cancel any running workflow and
deallocate the range when access is no longer required.

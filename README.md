# Egress FQDN to DCF Migration Quickstart

This quickstart covers the steps required to migrate from Aviatrix Egress FQDN to Distributed Cloud Firewall (DCF). The migration involves exporting existing FQDN rules, translating them to DCF policies, and switching egress traffic from standalone gateways to spoke gateways.

## Before You Begin

### Software Requirements

- Python 3
- virtualenv

This code has been tested on macOS and Linux. See Python and virtualenv documentation if you need help installing either component.

### Spoke Gateway Requirements

While Egress FQDN is enforced on standalone gateways, DCF is enforced on spoke gateways.

- If your VPC/VNet already has spoke gateways, they can be used for DCF.
- If your VPC/VNet doesn't have any spoke gateways, you will need to deploy them.
- Confirm the spoke gateways meet the required sizing for DCF: [https://docs.aviatrix.com/documentation/latest/security/dcf-overview.html#spoke-gateway-sizing](https://docs.aviatrix.com/documentation/latest/security/dcf-overview.html#spoke-gateway-sizing)

### IP Allowlist Updates

- If you previously added the standalone gateway IP to an allowlist, you'll need to update your configuration to allow the spoke gateway IPs instead.

## Step 1 - Download the Code

**Note:** The instructions assume you're working in `~/aviatrix`. If using a different directory, adjust the paths accordingly in all commands.

Create a directory to work in.

```
mkdir ~/aviatrix
```

Clone the repository.

```
cd ~/aviatrix/
git clone https://github.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator
```

If `git` is not installed, the code can be downloaded directly from the GitHub page.

- [https://github.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator](https://github.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator)
- Click on Code > Download ZIP.

## Step 2 - Export FQDN Configuration

Create a Python virtual environment.

```
python3 -m venv venv
```

Activate the virtualenv.

```
source venv/bin/activate
```

Switch to the exporter directory.

```
cd ~/aviatrix/avx-fqdn-to-dcf-policy-translator/exporter/
```

Install exporter requirements.

```
pip install -r requirements.txt
```

Run the exporter script and provide Aviatrix Controller credentials. Press `Enter` for the default options which are typically sufficient.

```
python3 export_legacy_policy_bundle.py
```

The exporter script creates a zip file (`legacy_policy_bundle.zip` by default).

## Step 3 - Translate FQDN Rules to DCF Policies

Unzip `legacy_policy_bundle.zip` to an empty directory which will be referred to as `<input-dir>` in the following commands.

```
unzip legacy_policy_bundle.zip -d <input-dir>
```

Create an empty directory which will be referred to as `<output-dir>` in the following commands.

```
mkdir <output-dir>
```

Install requirements for translator.

```
cd ~/aviatrix/avx-fqdn-to-dcf-policy-translator/
pip install -r requirements.txt
```

Switch to the translator directory.

```
cd ~/aviatrix/avx-fqdn-to-dcf-policy-translator/translator/
```

Run the translator script.

```
python3 src/main.py --input-dir <input-dir> --output-dir <output-dir>
```

The output of the translation will be in `<output-dir>`.

## Step 4 - Stage DCF Policies

### Update Aviatrix Provider Version

Switch to the output directory.

```
cd <output-dir>
```

Update the Aviatrix provider version in `main.tf` to the appropriate version based on the Aviatrix Controller version: [https://registry.terraform.io/providers/AviatrixSystems/aviatrix/latest/docs/guides/release-compatibility](https://registry.terraform.io/providers/AviatrixSystems/aviatrix/latest/docs/guides/release-compatibility)

```
terraform {
  required_providers {
    aviatrix = {
      source  = "AviatrixSystems/aviatrix"
      version = "<UPDATE_THIS>"
    }
  }
}

provider "aviatrix" {
  skip_version_validation = true
}
```

### Apply Terraform Configuration

Use Terraform to stage the DCF policies. Provide the Aviatrix Controller IP, username and password when prompted.

```
terraform init
terraform plan
terraform apply
```

**Note:** This step only stages the policies and does NOT activate filtering yet. Traffic continues to use FQDN rules until SNAT is enabled on the spoke gateways in a later step.

### Review DCF Policies

From CoPilot, go to Security > Distributed Cloud Firewall > Policies.

- Review the translated DCF Policies.

From CoPilot, go to Groups.

- Review the SmartGroups & WebGroups.

## Step 5 - Deploy Spoke Gateways

### Sizing

- If your VPC/VNet doesn't already have spoke gateways, deploy them now: [https://docs.aviatrix.com/documentation/latest/network/gateway-spoke-create.html](https://docs.aviatrix.com/documentation/latest/network/gateway-spoke-create.html)
- Confirm the spoke gateways meet the required sizing for DCF and resize them if needed: [https://docs.aviatrix.com/documentation/latest/security/dcf-overview.html#spoke-gateway-sizing](https://docs.aviatrix.com/documentation/latest/security/dcf-overview.html#spoke-gateway-sizing)

### Update DNS Settings

- From CoPilot, go to Cloud Fabric > Gateways > Spoke Gateways and click on the relevant spoke.
- Go to the Settings tab and expand the General section.
- Under Gateway Management DNS Server, select Cloud VPC/VNet DNS Server if it isn't already set to that.

## Step 6 - Verify Current Egress Filtering

From an instance in the VPC/VNet:

- Verify that it can access domains/ports that are allowed.
- Verify that it CANNOT access domains/ports that are not allowed.

## Step 7 - Disable SNAT on Standalone Gateway

### Detach Gateway from FQDN Tags

- From the Controller UI, go to Security > Egress Control, scroll to Egress FQDN Filter.
- For each tag that the gateway is attached to, detach the gateway.

### Disable Single IP SNAT on Egress Gateway

- From the Controller UI, go to Gateway and select the appropriate egress gateway and click Edit.
- Scroll to Source NAT and click on Disable SNAT.

## Step 8 - Enable SNAT on Spoke Gateways

- From CoPilot, go to Security > Egress and click on the Egress VPC/VNets tab.
- Verify that the VPC/VNet you are migrating shows the Point of Egress as `Native Cloud Egress`.
- Click on Enable Local Egress on VPC/VNets, select the VPC/VNet that is being migrated and click Add.
- Verify that Point of Egress now shows as `Local Egress`.

## Step 9 - Verify DCF Filtering

Perform the same tests as in Step 6 to verify that the DCF policies are functioning correctly.

- Verify that it can access domains/ports that are allowed.
- Verify that it CANNOT access domains/ports that are not allowed.

## Rollback

If you encounter issues during or after migration, you can rollback by performing the steps below. This will restore FQDN-based egress filtering.

### 1. Disable Local Egress

- From CoPilot, go to Security > Egress and click on the Egress VPC/VNets tab.
- Select the particular VPC/VNet and click on the Remove button (all the way to the right).

### 2. Re-enable Single IP SNAT

- From the Controller UI, go to Gateway and select the appropriate egress gateway and click Edit.
- Scroll to Source NAT and click on Enable Single IP SNAT.

### 3. Re-attach Gateways to FQDN Tags

- From the Controller UI, go to Security > Egress Control, scroll to Egress FQDN Filter.
- Reattach the gateway to FQDN tags.

## Post-Migration Cleanup

After confirming the migration is successful:

- The standalone gateway can be decommissioned.
- FQDN tags can be deleted from Security > Egress Control.

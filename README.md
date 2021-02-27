# Azure config validation

This script performs validation pre-checks to validate the correct conditions for a successful Azure -> ACI migration.

## Getting Started

- Azure CLI
- Python 3.8+
- Python dependencies in `requirements.txt`
- Authenticate via AZ CLI
- Run the tool

#### Azure CLI

Azure CLI is used for authentication. Per-platform installation instructions are available here:

https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

**NOTE:** Do not attempt to install Azure CLI through pip. Azure CLI depends on older Azure API libraries and will conflict with installing the newer versions from `requirements.txt`. Installing it as per Microsoft's instructions (above) will use isolated Python dependencies and will not cause a conflict.

Once the Azure CLI is installed, run `az login` to authenticate or `az login --help` to view other authentication options.

#### Python libraries

Install Python dependences in the `requirements.txt` file:

`pip install -r requirements.txt`

## Usage

Once prerequisites are complete, run the scripts with `-h` or `--help` to see usage.

#### Run against all resource groups in a subscription:

`python validation.py -s {subscription}`

#### Run against a specific group:

`python validation.py -s {subscription} -g {group}`

#### Run against a specific vnet:

`python validation.py -s {subscription} ---vnet {vnet}`

#### List available subscriptions:

`python validation.py --list-subscriptions`

#### List available Resource Groups:

`python validation.py -s {subscription} --list-groups`

#### List available VNets (also lists containing resource group):

`python validation.py -s {subscription} --list-vnets`


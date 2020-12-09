#!/bin/bash

# Provisions and configures the OpenEduAnalytics base architecture, as well as the Contoso package.
if [ $# -ne 1 ]; then
    echo "This setup script will install the Open Edu Analytics base architecture along with the ContosoISD package and test data into a newly created resource group."
    echo "Invoke this script like this:  setup.sh <OrgId>"
    echo "where OrgId is an id for the env (eg, CISD3)"
    exit 1
fi

org_id=$1
org_id_lowercase=${org_id,,}
resource_group="EduAnalytics${org_id}"
synapse_workspace="syeduanalytics${org_id_lowercase}"

# The assumption here is that this script is in the base path of the OpenEduAnalytics project.
oea_path=$(dirname $(realpath $0))

# setup the base architecture
$oea_path/setup_base_architecture.sh $org_id
# install the ContosoISD package
$oea_path/packages/ContosoISD/setup.sh $org_id

# Setup is complete. Provide a link for user to jump to synapse studio.
workspace_url=$(az synapse workspace show --name $synapse_workspace --resource-group $resource_group | jq -r '.connectivityEndpoints | .web')
echo "--> Setup of the test environment is complete."
echo "Click on this url to open your Synapse Workspace: $workspace_url"

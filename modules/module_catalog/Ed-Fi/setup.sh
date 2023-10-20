#!/bin/bash

# Installs the Ed-Fi module
# This script can be invoked directly to install the Ed-Fi module assets into an existing Synapse Workspace.
if [ $# -ne 2 ]; then
    echo "This setup script will install the Ed-Fi module assets into an existing Synapse workspace with version support."
    echo "Invoke this script like this:"
    echo "    setup.sh <synapse_workspace_name> <version>"
    exit 1
fi

synapse_workspace=$1
version=$2
this_file_path=$(dirname $(realpath $0))

# Create a directory for the specified version
version_dir="$this_file_path/src/$version"
if [ ! -d "$version_dir" ]; then
    echo "Version '$version' does not exist. Please make sure the version directory exists at: $version_dir"
    exit 1
fi

echo "--> Setting up the Ed-Fi module assets for version $version."

# 2) Install notebooks
eval "az synapse notebook import --workspace-name $synapse_workspace --name EdFi_Land --spark-pool-name spark3p3sm --file @$version_dir/notebook/EdFi_Land.ipynb --only-show-errors"
eval "az synapse notebook import --workspace-name $synapse_workspace --name EdFi_Ingest --spark-pool-name spark3p3sm --file @$version_dir/notebook/EdFi_Ingest.ipynb --only-show-errors"
eval "az synapse notebook import --workspace-name $synapse_workspace --name EdFi_Refine --spark-pool-name spark3p3sm --file @$version_dir/notebook/EdFi_Refine.ipynb --only-show-errors"

# 3) Setup pipelines
# Note that the ordering below matters because pipelines that are referred to by other pipelines must be created first.
eval "az synapse pipeline create --workspace-name $synapse_workspace --name 1_land_edfi --file @$version_dir/pipeline/1_land_edfi.json"
eval "az synapse pipeline create --workspace-name $synapse_workspace --name 2_ingest_edfi --file @$version_dir/pipeline/2_ingest_edfi.json"
eval "az synapse pipeline create --workspace-name $synapse_workspace --name 3_refine_edfi --file @$version_dir/pipeline/3_refine_edfi.json"
eval "az synapse pipeline create --workspace-name $synapse_workspace --name 0_main_edfi --file @$version_dir/pipeline/0_main_edfi.json"

echo "--> Setup complete. The Ed-Fi module assets for version $version have been installed in the specified synapse workspace: $synapse_workspace"
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

# Create a version_marker by replacing dots with underscores and adding an underscore at the end
version_marker="${version//./_}_"

echo "--> Setting up the Ed-Fi module assets for version $version."

# 2) Install notebooks
notebook_dir="$version_dir/notebook"
# Rename and install notebooks with version_marker prefix
for notebook in "EdFi_Land.ipynb" "EdFi_Ingest.ipynb" "EdFi_Refine.ipynb" "edfi_fetch_urls.ipynb" "edfi_py.ipynb"; do
    eval "az synapse notebook import --workspace-name $synapse_workspace --name ${version_marker}${notebook%.*} --spark-pool-name spark3p3sm --file @$notebook_dir/$notebook --only-show-errors"
done

# 3) Setup pipelines
# Note that the ordering below matters because pipelines that are referred to by other pipelines must be created first.
pipeline_dir="$version_dir/pipeline"
# Rename and create pipelines with version_marker prefix
for pipeline_json in "1_land_edfi.json" "2_ingest_edfi.json" "3_refine_edfi.json" "0_main_edfi.json"; do
    eval "az synapse pipeline create --workspace-name $synapse_workspace --name ${version_marker}${pipeline_json%.*} --file @$pipeline_dir/$pipeline_json"
done

echo "--> Setup complete. The Ed-Fi module assets for version $version have been installed in the specified synapse workspace: $synapse_workspace"
echo "Version marker: $version_marker"
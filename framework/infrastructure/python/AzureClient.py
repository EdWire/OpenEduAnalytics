# need to run "pip install -r requirements.txt"
import secrets
import string
import os, random
import json
import logging
from base64 import b64encode
from uuid import uuid4
from datetime import datetime
from azure.identity import AzureCliCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.v2018_09_01_preview import models as authorization_model
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.synapse import SynapseManagementClient
from azure.mgmt.synapse.models import Workspace, DataLakeStorageAccountDetails, ManagedIdentity, IpFirewallRuleInfo
from azure.mgmt.synapse.models import BigDataPoolResourceInfo, AutoScaleProperties, AutoPauseProperties, LibraryRequirements, NodeSizeFamily, NodeSize, BigDataPoolPatchInfo
from azure.synapse.artifacts import ArtifactsClient
from azure.storage.filedatalake import DataLakeServiceClient
from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import HttpResponseError, ResourceExistsError

logger = logging.getLogger('AzureClient')

class AzureClient:
    """ todo: consider removing self.resource_group_name - it should probably be passed in as needed """
    def __init__(self, tenant_id, subscription_id, location = 'eastus', default_tags = None, resource_group_name = None):
        self.credential = AzureCliCredential()
        self.default_credential = DefaultAzureCredential()
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.location = location
        self.tags = default_tags if default_tags else {}
        self.resource_group_name = resource_group_name
        self.datalake_client = None
        self.resource_group = None
        self.secret_client = None
        self.key_vault_client = None
        self.resource_client = None
        self.graph_rbac_client = None
        self.authorization_client = None
        self.storage_client = None
        self.artifacts_client = {}
        self.synapse_client = None

    def get_authorization_client(self):
        # Note that we need to use at least version 2018-01-01-preview in order to be able to set the role assignments later,
        # otherwise we'll get an exception of type UnsupportedApiVersionForRoleDefinitionHasDataActions
        if not self.authorization_client: self.authorization_client = AuthorizationManagementClient(self.credential, self.subscription_id, api_version='2018-01-01-preview')
        return self.authorization_client

    def get_resource_client(self):
        if not self.resource_client: self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        return self.resource_client

    def get_key_vault_client(self):
        if not self.key_vault_client: self.key_vault_client = KeyVaultManagementClient(self.credential, self.subscription_id)
        return self.key_vault_client

    def get_secret_client(self, keyvault_name):
        if not self.secret_client: self.secret_client = SecretClient(f"https://{keyvault_name}.vault.azure.net", self.default_credential)
        return self.secret_client

    def get_datalake_client(self, account_key):
        if not self.datalake_client: self.datalake_client = DataLakeServiceClient(account_url=f"https://{self.storage_account_name}.dfs.core.windows.net", credential={"account_name":self.storage_account_name, "account_key": account_key})
        return self.datalake_client

    def get_storage_client(self):
        if not self.storage_client: self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
        return self.storage_client

    def get_synapse_client(self):
        if not self.synapse_client: self.synapse_client = SynapseManagementClient(self.credential, self.subscription_id)
        return self.synapse_client

    def get_artifacts_client(self, synapse_workspace_name):
        if not synapse_workspace_name in self.artifacts_client:
            self.artifacts_client[synapse_workspace_name] = ArtifactsClient(self.credential, f"https://{synapse_workspace_name}.dev.azuresynapse.net")
        return self.artifacts_client[synapse_workspace_name]

    def get_role(self, role_name, resource_id):
        auth_client = AuthorizationManagementClient(self.credential, self.subscription_id)
        # Get built-in role as a RoleDefinition object
        roles = list(auth_client.role_definitions.list(resource_id, filter="roleName eq '{}'".format(role_name)))
        return roles[0]

    def create_key_vault(self, key_vault_name, access_policies):
        """ Creates a keyvault with the given name and access policies, waits for the creation to finish an returns the keyvault object """
        poller = self.get_key_vault_client().vaults.begin_create_or_update(self.resource_group_name, key_vault_name,
            {
                'location': self.location,
                'properties': {
                    'sku': { 'name': 'standard', 'family': 'A' },
                    'tenant_id': self.tenant_id,
                    'access_policies': access_policies
                }
            }
        )
        return poller.result()

    def create_secret_in_keyvault(self, keyvault_name, secret_name, secret_value):
        """ Creates or updates a secret in the keyvault with the given value """
        self.get_secret_client(keyvault_name).set_secret(secret_name, secret_value)

    def create_or_update_dataflow(self, synapse_workspace, dataflow_file_path):
        """ Creates or updates the Dataflow in the given Synapse studio.
            Expects the dataflow configuration file in JSON format.
        """
        with open(dataflow_file_path) as f: dataflow_dict = json.load(f)
        poller = self.get_artifacts_client(synapse_workspace).data_flow.begin_create_or_update_dataflow(dataflow_dict['name'], dataflow_dict)
        return poller

    def create_or_update_pipeline(self, synapse_workspace, pipeline_file_path, pipeline_name):
        """ Creates or updates the Pipeline in the given Synapse studio.
            Expects the pipeline configuration file in JSON format.
        """
        with open(pipeline_file_path) as f: pipeline_dict = json.load(f)
        if '$schema' not in pipeline_dict.keys():
            poller = self.get_artifacts_client(synapse_workspace).pipeline.begin_create_or_update_pipeline(pipeline_name, pipeline_dict)
            return poller

    def create_notebook(self, notebook_filename, synapse_workspace_name):
        """ Creates or updates the Notebook in the given Synapse studio.
            Expects the dataflow configuration file in JSON or ipynb format.
        """
        artifacts_client = self.get_artifacts_client(synapse_workspace_name)
        with open(notebook_filename) as f:
            if(notebook_filename.split('.')[-1] == 'json'):
                notebook_dict = json.load(f)
                notebook_name = notebook_dict['name']
            elif(notebook_filename.split('.')[-1] == 'ipynb'):
                notebook_dict = json.loads(f.read())
                notebook_name = notebook_filename.split('/')[-1].split('.')[0]
            else:
                raise ValueError('Notebook format not supported.')
        self.validate_notebook_json(notebook_dict)
        logger.info(f"Creating notebook: {notebook_name}")
        poller = artifacts_client.notebook.begin_create_or_update_notebook(notebook_name, notebook_dict)
        return poller #AzureOperationPoller

    def validate_notebook_json(self, nb_json):
        """ These attributes must exist for the call to begin_create_or_update_notebook to pass validation """
        if not 'nbformat' in nb_json['properties']: nb_json['properties']['nbformat'] = 4
        if not 'nbformat_minor' in nb_json['properties']: nb_json['properties']['nbformat_minor'] = 2
        for cell in nb_json['properties']['cells']:
            if not 'metadata' in cell: cell['metadata'] = {}
        if 'bigDataPool' in nb_json['properties']:
            nb_json['properties'].pop('bigDataPool', None) #Remove bigDataPool if it's there

    def delete_notebook(self, notebook_name, synapse_workspace_name):
        """ Deletes the synapse notebook from the workspace."""
        poller = self.get_artifacts_client(synapse_workspace_name).notebook.delete_notebook(notebook_name)
        return poller

    def delete_pipeline(self, pipeline_name, synapse_workspace_name):
        """ Deletes the Synapse pipeline from the workspace."""
        poller = self.get_artifacts_client(synapse_workspace_name).pipeline.delete_pipeline(pipeline_name)
        return poller

    def delete_dataflow(self, dataflow_name, synapse_workspace_name):
        """ Deletes the Synapse pipeline from the workspace."""
        poller = self.get_artifacts_client(synapse_workspace_name).data_flow.delete_dataflow(dataflow_name)
        return poller

    def delete_linked_service(self, linked_service_name, synapse_workspace_name):
        """ Deletes the Synapse Linked Service from the workspace."""
        poller = self.get_artifacts_client(synapse_workspace_name).linked_service.delete_linked_service(linked_service_name)
        return poller

    def delete_dataset(self, dataset_name, synapse_workspace_name):
        """ Deletes the Synapse Dataset from the workspace."""
        poller = self.get_artifacts_client(synapse_workspace_name).dataset.delete_dataset(dataset_name)
        return poller

    def delete_resource_group(self, name):
        """ Deletes the given resource group from the subscription. """
        self.get_resource_client().resource_groups.begin_delete(name)
        self.resource_group_name = None
        self.resource_group = None

    def create_resource_group(self, resource_group_name, tags=None):
        """ Creates an empty resource group in the Azure Subscription """
        if not tags: tags = {}
        result = self.get_resource_client().resource_groups.create_or_update(resource_group_name, {'location': self.location, 'tags': tags})
        self.resource_group = result
        self.resource_group_name = result.name

    def list_resources_in_resource_group(self, resource_group_name):
        """ Retuns a csv string listing all of the resources in the given resource group. """
        resource_list = self.get_resource_client().resources.list_by_resource_group(resource_group_name, expand = 'createdTime,changedTime')
        resources = "name,resource_type,created_time,changed_time\n"
        for resource in list(resource_list):
            resources += f"{resource.name},{resource.type},{str(resource.created_time)}{str(resource.changed_time)}\n"
        return resources

    def create_synapse_workspace(self, synapse_workspace_name, storage_account_name):
        """ Creates a Synapse workspace, waits for the creation to finish and returns the synapse workspace object """
        default_data_lake_storage = DataLakeStorageAccountDetails(account_url=f"https://{storage_account_name}.dfs.core.windows.net", filesystem="oea")

        poller = self.get_synapse_client().workspaces.begin_create_or_update(self.resource_group_name, synapse_workspace_name,
            {
                "location" : self.location,
                "tags" : self.tags,
                "identity" : ManagedIdentity(type="SystemAssigned"),
                "default_data_lake_storage" : default_data_lake_storage,
                "sql_administrator_login" : "eduanalyticsuser",
                "sql_administrator_login_password" : AzureClient.create_random_password(),
            }
        )

        return poller.result()

    def create_storage_account(self, storage_account_name):
        """ Create a storage account, waits for the creation to complete and returns the storage account object """
        storage_client = self.get_storage_client()
        poller = storage_client.storage_accounts.begin_create(self.resource_group_name, storage_account_name,
            {
                "location" : self.location,
                "tags" : self.tags,
                "kind": "StorageV2",
                "sku": {"name": "Standard_RAGRS"},
                "is_hns_enabled": True,
                "access-tier": "Hot",
                "default-action": "Allow"
            }
        )
        account_result = poller.result()
        self.storage_account_name = storage_account_name
        return account_result

    def create_containers_and_directories(self, storage_account_name, container_names, directory_list):
        """ Creates the given containers and directories in a given storage account """
        storage_client = self.get_storage_client()
        keys = storage_client.storage_accounts.list_keys(self.resource_group_name, storage_account_name)
        conn_string = f"DefaultEndpointsProtocol=https;EndpointSuffix=core.windows.net;AccountName={storage_account_name};AccountKey={keys.keys[0].value}"
        # Provision the containers in the account (this call is synchronous)
        for name in container_names:
            container = storage_client.blob_containers.create(self.resource_group_name, storage_account_name, name, {})
            for directory_path in ['/'.join(x.split('/')[1:]) for x in directory_list if x.split('/')[0] == name]:
                logger.info(directory_path)
                self.get_datalake_client(keys.keys[0].value).get_file_system_client(name).create_directory(directory_path)

    def create_linked_service(self, workspace_name, linked_service_name, file_path):
        """ Creates a linked service in the Synapse studio.
            Expects a linked service configuration file in JSON format
        """
        # This currently uses Azure CLI, need to modify this to use Python SDK
        os.system(f"az synapse linked-service create --workspace-name {workspace_name} --name {linked_service_name} --file @{file_path} -o none")

    def create_dataset(self, workspace_name, dataset_name, file_path):
        """ Creates a dataset in the Synapse studio.
            Expects a dataset configuration file in JSON format
        """
        # This currently uses Azure CLI, need to modify this to use Python SDK
        os.system(f"az synapse dataset create --workspace-name {workspace_name} --name {dataset_name} --file @{file_path} -o none")

    def create_role_assignment(self, role_name, resource_id, principal_id):
        """ Creates a role assignment for an Azure resource for a given Service Principal """
        role = self.get_role(role_name, resource_id)
        try:
            self.get_authorization_client().role_assignments.create(resource_id, uuid4(),
                authorization_model.RoleAssignmentCreateParameters(
                    role_definition_id=role.id,
                    principal_id=principal_id)
            )
        except ResourceExistsError as e:
            logger.info(f"The {role_name} role assignment already exists for {principal_id} on resource {resource_id}.")

    def add_firewall_rule_for_synapse(self, rule_name, start_ip_address, end_ip_address, synapse_workspace_name):
        """ Create a Firewall rule for the Azure Synapse Studio """
        ip_firewall_rule_info = IpFirewallRuleInfo(name=rule_name, start_ip_address=start_ip_address, end_ip_address=end_ip_address)
        poller = self.get_synapse_client().ip_firewall_rules.begin_create_or_update(self.resource_group_name, synapse_workspace_name, rule_name,
            {
                "name" : rule_name,
                "start_ip_address" : start_ip_address,
                "end_ip_address" : end_ip_address
            }
        )
        return poller

    def create_spark_pool(self, synapse_workspace_name, spark_pool_name, options=None):
        """ Creates the Spark Pool based on the options parameter and updates the pool with the required library requirements.

            :param node_size: size of the spark node. Defaulted to small
            :type node_size: str
            :param min_node_count: minimum node count for the spark pool
            :param min_node_count: int
            :param max_node_count: minimum node count for the spark pool
            :param max_node_count: int
            https://docs.microsoft.com/en-us/python/api/azure-mgmt-synapse/azure.mgmt.synapse.aio.operations.bigdatapoolsoperations?view=azure-python """
        if not options: options = {}
        min_node_count = options.pop('min_node_count', 3)
        max_node_count = options.pop('max_node_count', 5)
        node_size = options.pop('node_size', 'small')
        if node_size == 'small': node_size = NodeSize.SMALL
        elif node_size == 'medium': node_size = NodeSize.MEDIUM
        elif node_size == 'large': node_size = NodeSize.LARGE
        elif node_size == 'xlarge': node_size = NodeSize.X_LARGE
        elif node_size == 'xxlarge': node_size = NodeSize.XX_LARGE
        else: raise ValueError('Invalid Node Size.')

        poller = self.get_synapse_client().big_data_pools.begin_create_or_update(self.resource_group_name, synapse_workspace_name, spark_pool_name,
            BigDataPoolResourceInfo(
                tags = self.tags,
                location = self.location,
                auto_scale = AutoScaleProperties(enabled=True, min_node_count=min_node_count, max_node_count=max_node_count),
                auto_pause = AutoPauseProperties(delay_in_minutes=15, enabled=True),
                spark_version = '3.2',
                node_size = node_size,
                node_size_family = NodeSizeFamily.MEMORY_OPTIMIZED,
            )
        )
        result = poller.result() # wait for completion of spark pool
        library_requirements = f"{os.path.dirname(__file__)}/requirements.txt"
        self.update_spark_pool_with_requirements(synapse_workspace_name, spark_pool_name, library_requirements)
        return result

    def update_spark_pool_with_requirements(self, synapse_workspace_name, spark_pool_name, library_requirements_path_and_filename):
        """ Update the existing Spark pool by installing the required library requirements.
            Expects a path to the text file containing the list of library requirements"""
        with open(library_requirements_path_and_filename, 'r') as f: lib_contents = f.read()
        poller = self.get_synapse_client().big_data_pools.update(self.resource_group_name, synapse_workspace_name, spark_pool_name,
            BigDataPoolPatchInfo (
                library_requirements = LibraryRequirements(filename=os.path.basename(library_requirements_path_and_filename), content=lib_contents)
            )
        )
        return poller.result()

    def create_random_password():
        """ Creates a random password using secrets module """
        password = secrets.choice(string.ascii_uppercase) + secrets.choice(string.digits) + secrets.choice(['*', '%', '#', '@'])
        for _ in range(9): password += secrets.choice(string.ascii_lowercase)
        return password
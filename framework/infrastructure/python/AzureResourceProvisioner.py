# need to run "pip install -r requirements.txt"
from base64 import b64encode
import secrets
import os
from AzureClient import AzureClient
from msrest.exceptions import ValidationError

class AzureResourceProvisioner:
    """ This is class is used to Provision all the resources required for setting up OEA framework in your Azure Subscription.
        This class is instantiated by the setup.py and calls the provision_resources method of this class.

        Required parameters:
            1) azure_client: AzureClient object used to interact with the Azure tenant.
            2) oea_suffix: OEA suffix value entered by the customer while running the setup script.
            3) oea_version: The version of OEA currently being installed.
            4) include_groups: Boolean parameter to include creating security groups or not.
            5) logger: logger object
    """
    def __init__(self, azure_client:AzureClient, oea_suffix, oea_version, include_groups, logger):
        self.tenant_id = azure_client.tenant_id
        self.azure_client = azure_client
        self.subscription_id = azure_client.subscription_id
        self.oea_suffix = oea_suffix
        self.oea_version = oea_version
        self.location = azure_client.location
        self.logger = logger
        self.include_groups = include_groups
        self.containers = ['stage1', 'stage2', 'stage3', 'oea']
        self.dirs = ['stage1/Transactional','stage2/Ingested','stage2/Refined','oea/sandboxes/sandbox1/stage1/Transactional',\
            'oea/sandboxes/sandbox1/stage2/Ingested','oea/sandboxes/sandbox1/stage2/Refined','oea/sandboxes/sandbox1/stage3',\
                'oea/dev/stage1/Transactional','oea/dev/stage2/Ingested','oea/dev/stage2/Refined','oea/dev/stage3']
        self.keyvault = 'kv-oea-' + oea_suffix
        self.synapse_workspace_name = 'syn-oea-' + oea_suffix
        self.resource_group = 'rg-oea-' + oea_suffix
        self.storage_account = 'stoea' + oea_suffix
        self.app_insights = 'appi-oea-' + oea_suffix
        self.global_admins_name = 'Edu Analytics Global Admins'
        self.ds_group_name = 'Edu Analytics Data Scientists'
        self.eds_group_name = 'Edu Analytics External Data Scientists'
        self.de_group_name = 'Edu Analytics Data Engineers'
        self.user_object_id = os.popen("az ad signed-in-user show --query id -o tsv").read()[:-1] # the last char is a newline, so we strip that off
        self.tags = azure_client.tags
        self.storage_account_id = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Storage/storageAccounts/{self.storage_account}"
        self.synapse_workspace_object = None
        self.storage_account_object = None
        self.external_data_scientists_id = None
        self.data_engineers_id = None
        self.data_scientists_id = None
        self.global_admins_id = None

    def env_prep(self):
        # 0) Ensure that the resource providers are registered in the subscription (more info about this here: https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/error-register-resource-provider )
        os.system("az provider register --namespace 'Microsoft.Sql'")
        os.system("az provider register --namespace 'Microsoft.ManagedIdentity'")
        os.system("az provider register --namespace 'Microsoft.Storage'")
        os.system("az provider register --namespace 'Microsoft.KeyVault'")
        os.system("az provider register --namespace 'Microsoft.DataShare'")
        os.system("az provider register --namespace 'Microsoft.Synapse'")
        os.system("az provider register --namespace 'Microsoft.MachineLearningServices'")

        # and allow for az extensions to be installed as needed without prompting (extensions like azure-cli-ml and application-insights end up being installed)
        os.system("az config set extension.use_dynamic_install=yes_without_prompt")

    def get_container_resourceId(self, container):
        """ Returns the Resource Id of the given container """
        return f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Storage/storageAccounts/{self.storage_account}/blobServices/default/containers/{container}"

    def verify_permissions(self):
        """ Check if user has "Owner" Permission on the subscription, fail if not """
        owner_role_def = self.azure_client.get_role('Owner', f"/subscriptions/{self.subscription_id}")
        owner_role_assignments = [role_assignment for role_assignment in self.azure_client.get_authorization_client().role_assignments.list(filter=f'principalId eq \'{self.user_object_id}\'') if role_assignment.role_definition_id == owner_role_def.id]
        if(len(owner_role_assignments) == 0):
            self.logger.error("--> Setup failed! The user does not have the \"Owner\" Permission on the Azure subscription")
            raise PermissionError("User does not enough permissions.")

    def create_resource_group(self):
        """ Creates a resource group in the Azure subscription """
        try:
            self.azure_client.create_resource_group(self.resource_group)
            self.azure_client.resource_group_name = self.resource_group
        except ValidationError as e:
            self.logger.error('Validation Error - failed to create resource group: ' + str(e))
            raise ValidationError("Validation Failed.")

    def setup_storage_account(self):
        """ Creates the storage account, containers and file system as required by the latest version of OEA """
        try:
            self.storage_account_object = self.azure_client.create_storage_account(self.storage_account)
            self.logger.info("\t--> Creating storage account containers.")
            self.azure_client.create_containers_and_directories(self.storage_account, self.containers, self.dirs)
        except Exception as e:
            raise Exception(f'Error creating storage account : {str(e)}')

    def create_synapse_architecture(self):
        """ Creates the synapse workspace, configures the firewall policies, creates spark pools (small and medium) and
            updates them by installing the required library requirements as per the latest version of OEA"""
        try:
            self.synapse_workspace_object = self.azure_client.create_synapse_workspace(self.synapse_workspace_name, self.storage_account)
            # This permission is necessary to allow a data pipeline in Synapse to invoke notebooks.
            self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.storage_account_object.id, self.synapse_workspace_object.identity.principal_id)

            self.logger.info("\t--> Creating firewall rule for accessing Synapse Workspace.")
            self.azure_client.add_firewall_rule_for_synapse('allowAll', '0.0.0.0', '255.255.255.255', self.synapse_workspace_name)

            self.logger.info("\t--> Creating spark pools.")
            self.azure_client.create_spark_pool(self.synapse_workspace_name, "spark3p2sm",
                    {
                        "node_size": "small",
                        "max_node_count": 5
                    }
                )
            self.azure_client.create_spark_pool(self.synapse_workspace_name, "spark3p2med",
                    {
                        "node_size": "medium",
                        "max_node_count": 10
                    }
                )
        except Exception as e:
            raise Exception(f'Error while creating synapse architecture: {str(e)}')

    def create_keyvault_and_appinsights(self):
        """ Creates a keyvault and appinsights component in the Azure Subscription """
        try:
            access_policy_for_synapse = { 'tenant_id': self.tenant_id, 'object_id': self.synapse_workspace_object.identity.principal_id,
                                            'permissions': { 'secrets': ['get'] }
                                        }
            access_policy_for_user = { 'tenant_id': self.tenant_id, 'object_id': self.user_object_id,
                                        'permissions': { 'keys': ['all'], 'secrets': ['all'] }
                                    }
            self.azure_client.create_key_vault(self.keyvault, [access_policy_for_synapse, access_policy_for_user])
            self.azure_client.create_secret_in_keyvault(self.keyvault, 'oeaSalt', b64encode(secrets.token_bytes(16)).decode())
            self.logger.info(f"--> Creating app-insights: {self.app_insights}")
            os.system(f"az monitor app-insights component create --app {self.app_insights} --resource-group {self.resource_group} --location {self.location} --tags {self.tags} -o none")
        except Exception as e:
            raise Exception(f'Error while creating keyvault and app insights: {str(e)}')


    def create_security_groups(self):
        """ Creates the security groups for data scientists, data engineers and external data scientists according to the latest version of OEA.
            This method is executed only of the include_groups parameter is set to true.
        """
        os.system(f"az ad group create --display-name \"{self.global_admins_name}\" --mail-nickname 'EduAnalyticsGlobalAdmins'")
        os.system(f"az ad group owner add --group \"{self.global_admins_name}\" --owner-object-id {self.user_object_id}")
        self.global_admins_id = os.popen(f"az ad group show --group \"{self.global_admins_name}\" --query id --output tsv").read()[:-1]


        os.system(f"az ad group create --display-name \"{self.ds_group_name}\" --mail-nickname 'EduAnalyticsDataScientists'")
        os.system(f"az ad group owner add --group \"{self.ds_group_name}\" --owner-object-id {self.user_object_id}")
        self.data_scientists_id = os.popen(f"az ad group show --group \"{self.ds_group_name}\" --query id --output tsv").read()[:-1]


        os.system(f"az ad group create --display-name \"{self.de_group_name}\" --mail-nickname 'EduAnalyticsDataEngineers' -o none")
        os.system(f"az ad group owner add --group \"{self.de_group_name}\" --owner-object-id {self.user_object_id} -o none")
        self.data_engineers_id = os.popen(f"az ad group show --group \"{self.de_group_name}\" --query id --output tsv").read()[:-1]


        os.system(f"az ad group create --display-name \"{self.eds_group_name}\" --mail-nickname 'EduAnalyticsExternalDataScientists' -o none")
        os.system(f"az ad group owner add --group \"{self.eds_group_name}\" --owner-object-id {self.user_object_id} -o none")
        self.external_data_scientists_id = os.popen(f"az ad group show --group \"{self.eds_group_name}\" --query id --output tsv").read()[:-1]

    def create_role_assignemnts(self):
        """ Creates role assignments for the security groups created when include_groups is true. """
        self.azure_client.create_role_assignment('Owner', f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/", self.global_admins_id)

        # Assign "Storage Blob Data Contributor" to security groups to allow users to query data via Synapse studio
        self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.storage_account_id, self.global_admins_id)
        self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.storage_account_id, self.data_scientists_id)
        self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.storage_account_id, self.data_engineers_id)

        # Assign limited access to specific containers for the external data scientists
        self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.get_container_resourceId('stage2'), self.external_data_scientists_id)
        self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.get_container_resourceId('stage3'), self.external_data_scientists_id)
        self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.get_container_resourceId('oea'), self.external_data_scientists_id)
        self.azure_client.create_role_assignment('Reader', self.storage_account_id, self.data_engineers_id)

    def provision_resources(self):
        """ Main function which triggers all the methods to provision resources in the Azure subscription """

        self.logger.info("--> Checking if the user has \"Owner\" Permission on the Azure Subscription.")
        self.verify_permissions()

        self.logger.info(f"--> 1) Creating resource group: {self.resource_group}")
        self.create_resource_group()

        self.logger.info(f"--> 2) Creating storage account: {self.storage_account}")
        self.create_storage_account()

        self.logger.info(f"--> 3) Creating Synapse Workspace: {self.synapse_workspace_name} (this is usually the longest step - it may take 5 to 10 minutes to complete)")
        self.create_synapse_architecture()

        self.logger.info(f"--> 4) Creating key vault: {self.keyvault}")
        self.create_keyvault_and_appinsights()

        if self.include_groups is True:
            self.logger.info("--> 5) Creating security groups in Azure Active Directory.")
            self.create_security_groups()

            self.logger.info("--> 6) Creating role assignments for Edu Analytics Global Admins, Edu Analytics Data Scientists, and Edu Analytics Data Engineers.")
            self.create_role_assignemnts()

        else:
            self.logger.info(f"--> 5) Creating \"Storage Blob Data Contributor\" role assignment for User to the storage account.")
            self.azure_client.create_role_assignment('Storage Blob Data Contributor', self.storage_account_id, self.user_object_id)






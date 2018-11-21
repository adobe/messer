[Documentation Home](docs.md)

Messer Azure
=============

TODO: Write Azure specific documentation here.

Messer requires the AZURE_CLIENT_SECRET to be exported as an environment variable.

***BEFORE YOU START***
Create an app which allows access to the created Key Vault. Obtain the required details
TENANT_ID, CLIENT_ID, AZURE_CLIENT_SECRET and SUBSCRIPTION_ID. You then need to create a Azure Vault and obtain its
https URL. For example: https://messerpoc.vault.azure.net/

Cryptographic Key Details In Azure
-------

|   Key         |   Used in Algorithm   |   Generated Via               |   Stored At       |   Key Length  |
|   :---:       |   :-:                 |   :-:                         |   :-:             |   :-:         |   
| Master Key    |   RSA-OAEP-256        |   API call to Azure Key Vault |   Azure Key Vault |   256 bits    |
| Data Key      |   AES with GCM mode   |   os.urandom                  |   Azure Key Vault |   256 bits    |
 

Azure Code Workflow
-------
1. [Encryption Key Creation](/docs/graphics/messer_encryption_create_azure.png)
1. [Encrypted Data Bag Creation](/docs/graphics/messer_data_bag_from_file_azure.png)
1. [Encryption Key Retrieval](/docs/graphics/messer_data_bag_show_azure.png)

#### Running Tests

1. Tests are run using [pytest](https://pytest.org/). Make sure pytest is installed (preferably in your virtulenv)
1. Make sure you install messer as instructed [here.](/README.md#installation)
1. [Configure Messer](#before-you-start) for Azure after you have create the required supporting infra on your Azure subscription.
1. From the root of this repo, run the following command:
```bash
pytest -v
```    

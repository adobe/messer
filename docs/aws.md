[Documentation Home](docs.md)

Messer in AWS
=============

On AWS, Messer leverages 3 AWS services: S3, KMS, and IAM.  Messer leverages the `boto` library and therefore needs
access to AWS credentials either via IAM role, or dedicated credentials.   However in any case, before you begin to work
with Messer there is some setup that needs to be done.

**Caveat**: Messer itself provides no security for your credentials, but rather facilitates encryption best practices,
and provides a simple mechanism for injecting secrets into instances.  If your IAM roles are poorly configured, you're
not buying yourself much by using it.

#### Cryptographic Key Details In AWS

|   Key         |   Used in Algorithm   |   Generated Via               |   Stored At   |   Key Length  |
|   :---:       |   :-:                 |   :-:                         |   :-:         |   :-:         |   
| Master Key    |   AES with GCM mode   |   API call to AWS KMS         |   S3          |   256 bits    |
| Data Key      |   AES with GCM mode   |   os.urandom                  |   S3          |   256 bits    |


#### PRE-INSTALL STEPS

1. Messer requires credentials to be available either as `environment variables`, `~/.boto` config file, or
`~/.aws/credentials` file.
1. You need to create a series of S3 Buckets, KMS Master Keys, IAM Roles and Policies. At a minimum you should define 1
bucket per region for secrets, a 2nd bucket per region and tier for envelope encryption keys, and 1 KMS master key
per region and tier you intend to deploy services to.  Then you need to define (at a minimum) an `admin policy` and a
`common service policy` for each tier of service you intent to offer (ie Dev, Stage, Prod). Ideally each webservice
should have it's own policy in each tier, but at a minimum use these 2.
1. Once you have your policies in place you need to define roles and attach the appropriate policies to the role and
setup cross account access where desired.


#### MESSER CONFIGURATION
Before you run Messer you need to setup a `config.ini`.  During installation, an empty default `config.ini`
is placed in your operating systems default location application configuration files and can be configured using
`configure` command, or use the same to create additional configuration files.

When running Messer on AWS, there are some specific configuration options you should be aware of.

- ***`--region`*** This is the literal name of the region, and is used by KMS to ensure Messer accesses the master key  in
the correct region.
- ***`--secrets-bucket`*** This is the name of the secrets bucket that Messer should store and retrieve it's encrypted
secrets from. Again, this should be region specific.
- ***`--tier`*** If you set this, Messer will store and retrieve secrets from this folder within the bucket as a prefix.  
- ***`--secrets_folder`*** If you like, you can specify and additional folder or path for the secrets to be stored in, but this will
be appended to `--tier` if specified.
- ***`--role_session_name`*** If you will be assuming a role (highly recommended) you'll need to set this value.  It's
the name of the session that will be appended in the AWS access logs.
- ***`--role_arn`*** This is the ARN of the AWS role Messer should assume when making API calls.  If this value is not
set, no assume role calls are made.
- ***`--keys-bucket`*** This is the name of the S3 bucket (again should be region specific) where you wish to store
your envelope encryption keys.
- ***`--master-key`*** This is the alias to the KMS Master key (again region specific) that will be used to generate
all of your envelope encryption keys.
- ***`--silent`*** Setting this value to `True` will mute all output from commands with the EXCEPTION of the `bulk`
command.

Azure Code Workflow
-------
1. [Encryption Key Creation](/docs/graphics/messer_encryption_create_aws.png)
1. [Encrypted Data Bag Creation](/docs/graphics/messer_data_bag_from_file_aws.png)
1. [Encryption Key Retrieval](/docs/graphics/messer_data_bag_show_aws.png)

#### Running Tests

1. Tests are run using [pytest](https://pytest.org/). Make sure pytest is installed (preferably in your virtulenv)
1. Make sure you install messer as instructed [here.](/README.md#installation)
1. You will need to create the following resources before running the tests:
    1. An AWS S3 bucket to store keys. In this example, we have named it as `adobe-envelope-keys-bucket-useast1`
    1. An AWS S3 bucket to store secrets encrypted with the key(s) created by messer. In this example, we have named it as `adobe-secrets-bucket-useast1`
    1. An AWS KMS Key. This key will be used to encrypt the data keys and is referred to as the master key. While creating the key, make sure that the policy for the key is set as follows:
    ```json
    {
        "Id": "Appropriate-Key-Id",
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789101:root"
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow access for Key Administrators",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789101:user/<your aws IAM User>"
                },
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:TagResource",
                    "kms:UntagResource",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow use of the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789101:user/<your aws IAM User>"
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow attachment of persistent resources",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789101:user/<your aws IAM User>"
                },
                "Action": [
                    "kms:CreateGrant",
                    "kms:ListGrants",
                    "kms:RevokeGrant"
                ],
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "kms:GrantIsForAWSResource": "true"
                    }
                }
            }
        ]
    }
    ```
    1. An AWS IAM Role to be assumed by messer to access the KMS Key and the S3 Buckets created before. Here is a sample of the policy attached to this role:
    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::adobe-secrets-bucket-useast1",
                    "arn:aws:s3:::adobe-envelope-keys-bucket-useast1"
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "true"
                    }
                }
            },
            {
                "Sid": "AdobeMesserUnittest",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion"
                ],
                "Resource": [
                    "arn:aws:s3:::adobe-secrets-bucket-useast1/unittest*",
                    "arn:aws:s3:::adobe-envelope-keys-bucket-useast1/adobe-messer-unittest*/*"
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "true"
                    }
                }
            },
            {
                "Sid": "AdobeMesserKMSAdmin",
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:ListAliases"
                ],
                "Resource": [
                    "arn:aws:kms:*:123456789101:alias/adobe-messer-unittest",
                    "arn:aws:kms:*:123456789101:key/092c5d92-faea-42ec-9d37-6961b2dc2693"
                ]
            }
        ]
    }
    ```
1. [Configure Messer](#messer-configuration) for AWS after you have create the required supporting infra on your AWS account.
1. Now you will need to create a test Messer Encryption key and a sample data bag and data bag item. From the root of this, run the following commands
```bash
# create a key to be used for encryption
messer encryption create aws adobe-messer-unittest -c tests/tests.ini
# create a sample data bag
messer data bag create aws unittest -c tests/tests.ini
# create a sample data bag item
messer data bag from file aws unittest tests/resources/secret3.json  --secret-file adobe-messer-unittest -c tests/tests.ini
```
1. From the root of this repo, run the following command:
```bash
python -m pytest
```    

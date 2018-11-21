[Documentation Home](docs.md)

Messer in AWS
=============

On AWS, Messer leverages 3 AWS services: S3, KMS, and IAM.  Messer leverages the `boto` library and therefore needs
access to AWS credentials either via IAM role, or dedicated credentials.   However in any case, before you begin to work
with Messer there is some setup that needs to be done.

**Caveat**: Messer itself provides no security for your credentials, but rather facilitates encryption best practices,
and provides a simple mechanism for injecting secrets into instances.  If your IAM roles are poorly configured, you're
not buying yourself much by using it.

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

#### Running Tests

1. Tests are run using [pytest](https://pytest.org/). Make sure pytest is installed (preferably in your virtulenv)
1. Make sure you install messer as instructed [here.](/README.md#installation)
1. [Configure Messer](#messer-configuration) for AWS after you have create the required supporting infra on your AWS account.
1. From the root of this repo, run the following command:
```bash
pytest -v
```    
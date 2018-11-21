[Documentation Home](docs.md)

Bulk Commands
==============

Messer can be used to perform bulk operations to make certain tasks easier.  Below are some samples of what can be done
using the bulk commmands.  However, before performing any bulk operation you should consider backing up your secrets & encryption keys.


#### Encryption Key Rotation
Encryption keys which are used for encrypting and decrypting secrets need to be rotated every 90 days as per PCI Requirements.
Messer simplifies this task by allowing you to run a bulk operation which will generate a new key, and re-encrypt all the secrets with this new secret.

Bulk operations internally call other messer methods repeatedly, so it's useful to configure messer to run in silent mode to mute all output except from the bulk command.

Consider the following `messer.ini`:

    [aws]
    secrets_bucket = adobe-secrets-bucket-useast1
    secrets_folder = secrets
    keys_bucket = adobe-envelope-keys-bucket-useast1
    role_arn = arn:aws:iam::123456789101:role/adobe-messer-admin
    role_session_name = adobe-messer-list-data-bags
    aws_profile = secure
    region = us-east-1

    [messer]
    master_key = adobe-messer-master-key
    tier = dev
    aws_profile = secure
    silent = true

With this config you must have:
 - an s3 secrets bucket named `adobe-secrets-bucket-useast1` exists where all secrets will be stored
 - the secrets bucket has a folder structure of `/dev/secrets/`
 - an S3 bucket named `adobe-envelope-keys-bucket-useast1` where all your envelope encryption keys are stored
 - both the `adobe-secrets-bucket-useast1`, and `adobe-envelope-keys-bucket-useast1` are in the `us-east-1` region
 - there is a KMS master key with an alias of `adobe-messer-master-key` in the `us-east-1` region
 - you have an AWS credentials file in `~/.aws/credentials` or `~/.boto` that defines a profile named `secure`
 - the `secure` profile can assume the `arn:aws:iam::123456789101:role/adobe-messer-admin` role
 - the role can read/write from the S3 buckets, and use the KMS key for encrypt and decrypt operations.

If we use this configuration to execute `messer bulk rotate-keys aws messer.ini` we can assume the following operations
will happen:

1. Create an internal map of keys/versions
1. Based on the above config, Messer will get a list of all of the sub-folders (data bags) under `/dev/secrets/` in the `adobe-secrets-bucket-useast1` bucket.
1. For each folder (data bag) in the list, it will then list the name of each secret within the folder (data bag).
1. Messer will then download and decrypt each secret one at a time
1. Generate a new version of the envelope key used to encrypt (if not already done), and re-encrypt the secret using this key
1. Re-upload the secret overwriting the previous secret.

#### Copy to Cloud/Region

If you want to copy all of the secrets from one cloud region to another, or even from cloud to cloud you can do
this easily with the `bulk copy` command.  The command will first attempt to download and decrypt all of the secrets from the source cloud/region, and then re-encrypt and upload them to the destination cloud/region using the destination key.

You can specify more than one destination config if you decide you want to copy the secrets to multiple destinations.

# IPv4 Usage Monitoring for AWS

This script allows customers to iterate through all regions and all accounts in an organization to enumerate all public IPs and flag certain IPs that may be unnecessary for further investigation. 

## Requirements

 - Linux or Mac
 - Python3 with Boto3 AWS SDK
 - IAM access to either the local account and/or to assume role into other accounts in the organization

## Considerations

 - This script is a **BEST EFFORT** to identify all resources with public IPs however it is dependent on a number of API calls that can fail for a variety of reasons (eg. insufficient permissions, throttling, etc.). This should only be used to inform users of a means to prioritize which resources to look at first for considerations of reduction or elimination of public IPv4 address usage. For billing estimations, please use Cost and Usage Reports to estimate data as discussed [here](https://aws.amazon.com/blogs/aws/new-aws-public-ipv4-address-charge-public-ip-insights/).
 - This assumes that any IP in a security group that is not a Bogon network is a public IP. Thus, if you are using non-bogon networks as VPC CIDRs and allowing those CIDRs in a security group, it may not flag an ENI with a public IP that is only open to "Internal" resources.

## Permissions required

There are two role types, the role of the "local user" which is running the script, if you are running in an organization, use a role from the management account. The other role is an "assumed role" which the local user assumes in other accounts to run against them. The following are the permissions needed for each:

#### Local User:
 
 - ec2:DescribeAddresses
 - ec2:DescribeSecurityGroupRules
 - ec2:DescribeRouteTables
 - ec2:DescribePrefixLists
 - ec2:DescribeNetworkInterfaces
 - ec2:DescribeSubnets
 - ec2:DescribeVpnConnections
 - ec2:DescribeRegions
 - globalaccelerator:ListAccelerators 
 - organizations:ListAccounts (Only applicable if using multi-account)
 - sts:AssumeRole (Only applicable if using multi-account)

#### Assumed Role

 - ec2:DescribeAddresses
 - ec2:DescribeSecurityGroupRules
 - ec2:DescribeRouteTables
 - ec2:DescribePrefixLists
 - ec2:DescribeNetworkInterfaces
 - ec2:DescribeSubnets
 - ec2:DescribeVpnConnections
 - ec2:DescribeRegions
 - globalaccelerator:ListAccelerators 

## Usage

### Single Account (local) mode

This runs against the local account, without any assumption of roles outside the provided boto3 profile/default profile. 

`python3 IPv4UsageMonitoringforAWS.py run-single-account <options>`

#### Options

 - #### Profile

[Optional] Specify the AWS CLI/Boto3 profile you wish to use. If not specified the default profile, or attached role will be used.

`--profile <profile>`

 - #### Regions

[Optional] Specify the AWS regions you wish to iterate through in a comma delineated list without spaces. if not specified all regions that are opted-in (either manually or by default) will be iterated through.

`--regions <region,region,>`

- #### AWS Access Key ID

[Optional] Specify the AWS IAM access key you wish to use. If not specified the profile specified or default profile, or attached role will be used.

`--access-key-id <access key id>`

- #### AWS Secret Key

[Optional] Specify the AWS IAM secret key you wish to use. If not specified the profile specified or default profile, or attached role will be used.

`--secret-key <secret key>`

- #### AWS STS Token

[Optional] Specify the AWS STS session token you wish to use. If not specified the profile specified or default profile, or attached role will be used.

`--session-token <session token>`

- #### File output path

[Optional] Specify the output path you wish to write the result files to (eg. "example/" or "/home/ec2-user/"). If not specified the files will be output to the directory which the script context is run from. 

`--output-path <file output path>`


### Multi-Account (Organizations) mode

This runs against the specified accounts or all accounts within an AWS organization, using STS to assume a role in each account. 

`python3 IPv4UsageMonitoringforAWS.py run-multi-account <options>`

#### Options

- #### STS External ID

[Optional] Specify the External ID you wish to use for STS assume role. This must be the same for all accounts. If not specified no External ID is used.

`--external-id <externalID>`

- #### Role Name

[Optional] Specify the IAM role name you wish to use for STS assume role. This must be the same for all accounts. If not specified the default `OrganizationAccountAccessRole` is used.

`--role-name <roleName>`

- #### Accounts

[Optional] Specify the AWS accounts you wish to iterate through. If not specified this will iterate through all accounts in the AWS organization. This must be run from the AWS Organization Management account if accounts aren't specified. 

`--accounts`


 - #### Profile

[Optional] Specify the AWS CLI/Boto3 profile you wish to use. If not specified the default profile, or attached role will be used.

`--profile <profile>`

 - #### Regions

[Optional] Specify the AWS regions you wish to iterate through in a comma delineated list without spaces. if not specified all regions that are opted-in (either manually or by default) will be iterated through.

`--regions <region,region,>`

- #### AWS Access Key ID

[Optional] Specify the AWS IAM access key you wish to use. If not specified the profile specified or default profile, or attached role will be used.

`--access-key-id <access key id>`

- #### AWS Secret Key

[Optional] Specify the AWS IAM secret key you wish to use. If not specified the profile specified or default profile, or attached role will be used.

`--secret-key <secret key>`

- #### AWS STS Token

[Optional] Specify the AWS STS session token you wish to use. If not specified the profile specified or default profile, or attached role will be used.

`--session-token <session token>`

- #### File output path

[Optional] Specify the output path you wish to write the result files to (eg. "example/" or "/home/ec2-user/"). If not specified the files will be output to the directory which the script context is run from. 

`--output-path <file output path>`


## Output

All file outputs are prepended with the Epoch timestamp when they were run followed by an underscore (eg. 1695071739_vpn_connections.csv). Note there may be duplicates in these files due to resources shared across accounts such as shared subnets.

#### {Epoch}_associated_eips.csv

This file enumerates all EIPs that are associated to a resource, what region they are in and if run against multi-account, what account they are in.

#### {Epoch}_unassociated_eips.csv

This file enumerates all EIPs that are NOT associated to a resource, what region they are in and if run against multi-account, what account they are in.

#### {Epoch}_eni_public_ips.csv

This file enumerates all public IPs and EIPs that are associated to ENIs. It will output the following:

 - ENI owner account
 - Region
 - ENI Id
 - Public IP address (including EIP)
 - VPC Id
 - Subnet Id
 - Interface type (eg. Network Load Balancer, NAT Gateway, EC2 Instance, Etc)
 - Type of IP address (Public IP or Elastic IP)
 - The level of suspicion that the IP is unnecessary (Please confirm yourself before deleting)
 - The reason for the suspicion

#### {Epoch}_private_subnets_with_auto_assign.csv

This file enumerates all subnets that have Public IP auto-assignment enabled but no route to an Internet Gateway. NOTE: It does not flag the subnet if auto-assignment is disabled but ENIs still have public IPs manually assigned, those ENIs are flagged as high suspicion in `{Epoch}_eni_public_ips.csv`. It will output the subnet owner account ID, region, VPC Id and Subnet Id.

#### {Epoch}_global_accelerators.csv

This file enumerates all global accelerators, the owner account and associated public IPs

#### {Epoch}_vpn_connections.csv

This file enumerates all public VPN connections, associated public IPs. The owner account is identified if run in multi-account mode. 


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import getopt
import ipaddress
import json
import os
import sys
import time
from multiprocessing import Process

import boto3


def describe_eips(region: str, access_key_id: str, secret_key: str, session_token: str) -> dict:
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name=region)

    ec2_client = session.client('ec2', region_name=region)
    unassociated_eips = list()
    associated_eips = list()
    addresses = ec2_client.describe_addresses()
    for address in addresses['Addresses']:
        if 'CustomerOwnedIpv4Pool' in address.keys():
            # BYoIP address
            pass
        elif 'AssociationId' not in address.keys():
            # Amazon Owned Public IP that isn't associated to anything
            unassociated_eips.append(address['PublicIp'])
        else:
            # Amazon Owned Public IP that is associated to something
            associated_eips.append(address['PublicIp'])
    return {'associated': associated_eips, 'unassociated': unassociated_eips}


def parse_interface_type(interface_data: dict) -> str:
    if interface_data['InterfaceType'] == 'network_load_balancer':
        return 'Network Load Balancer'
    elif interface_data['InterfaceType'] == 'nat_gateway':
        return 'NAT Gateway'
    elif interface_data['InterfaceType'] == 'efa':
        return 'Elastic Fabric Adapter'
    elif interface_data['InterfaceType'] == 'trunk':
        return 'Trunk ENI'
    elif interface_data['InterfaceType'] == 'load_balancer':
        return 'Application Load Balancer'
    elif interface_data['InterfaceType'] == 'vpc_endpoint':
        return 'PrivateLink Endpoint'
    elif interface_data['InterfaceType'] == 'branch':
        return 'Branch ENI'
    elif interface_data['InterfaceType'] == 'transit_gateway':
        return 'Transit Gateway Attachment ENI'
    elif interface_data['InterfaceType'] == 'lambda':
        return 'Lambda Function Interface'
    elif interface_data['InterfaceType'] == 'quicksight':
        return 'Quicksight Interface'
    elif interface_data['InterfaceType'] == 'global_accelerator_managed':
        return 'Global Accelerator Private Access Interface'
    elif interface_data['InterfaceType'] == 'api_gateway_managed':
        return 'API Gateway'
    elif interface_data['InterfaceType'] == 'gateway_load_balancer':
        return 'Gateway Load Balancer'
    elif interface_data['InterfaceType'] == 'gateway_load_balancer_endpoint':
        return 'Gateway Load Balancer Endpoint'
    elif interface_data['InterfaceType'] == 'iot_rules_managed':
        return 'IoT'
    elif interface_data['InterfaceType'] == 'aws_codestar_connections_managed':
        return 'CodeStar'
    # The following is basically a catch all
    elif 'Attachment' in interface_data.keys():
        if 'InstanceId' in interface_data['Attachment'].keys():
            if len(interface_data['Attachment']['InstanceId']) > 8:
                return 'EC2 Instance'
        elif 'Association' in interface_data.keys():
            if interface_data['Association']['IpOwnerId'] == 'amazon-elb':
                if 'ELB app/' in interface_data['Description']:
                    return 'Application Load Balancer'
                else:
                    return 'Classic Load Balancer'
            else:
                if 'Description' in interface_data.keys():
                    if str(interface_data['Description'])[:4] == 'arn:':
                        assumed_type = ' '.join(interface_data['Description'].split(':')[2])
                        return assumed_type
                    elif ' ' in interface_data['Description']:
                        assumed_type = ' '.join(interface_data['Description'].split(' ')[:2])
                        return assumed_type
                    else:
                        return 'Unknown Resource Type'
                else:
                    return 'Unknown Resource Type'
    elif interface_data['InterfaceType'] == 'interface':
        return 'Unattached ENI'
    else:
        return 'Unknown Resource Type'


def parse_security_group_cidrs(security_group_ids: list, region: str, access_key_id: str, secret_key: str,
                               session_token: str) -> dict:
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name=region)

    ec2_client = session.client('ec2', region_name=region)
    egress_prefixes = list()
    ingress_prefixes = list()
    paginator = ec2_client.get_paginator('describe_security_group_rules')
    iterator = paginator.paginate(Filters=[{'Name': 'group-id', 'Values': security_group_ids}])
    for page in iterator:
        for rule in page['SecurityGroupRules']:
            # Get direct IPv4 references in security group and look for SSH port
            if 'CidrIpv4' in rule.keys():
                is_ssh = False
                if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == 22 and rule['ToPort'] == 22:
                    is_ssh = True
                if rule['IsEgress']:
                    egress_prefixes.append({'cidr': rule['CidrIpv4'], 'is_ssh': is_ssh})
                else:
                    ingress_prefixes.append({'cidr': rule['CidrIpv4'], 'is_ssh': is_ssh})
            # Get IPv4 references from a prefix list in security group and look for SSH port
            elif 'PrefixListId' in rule.keys():
                is_ssh = False
                if rule['IpProtocol'] == 'tcp' and rule['FromPort'] == 22 and rule['ToPort'] == 22:
                    is_ssh = True
                prefix_list_info = ec2_client.describe_prefix_lists(PrefixListIds=[rule['PrefixListId']])
                for prefix_list in prefix_list_info['PrefixLists']:
                    for cidr in prefix_list['Cidrs']:
                        if ipaddress.ip_network(cidr).version == 4:
                            if rule['IsEgress']:
                                egress_prefixes.append({'cidr': cidr, 'is_ssh': is_ssh})
                            else:
                                ingress_prefixes.append({'cidr': cidr, 'is_ssh': is_ssh})
    return {'egress': egress_prefixes, 'ingress': ingress_prefixes}


def parse_subnet_routes(vpc_id: str, subnet_id: str, region: str, access_key_id: str, secret_key: str,
                        session_token: str) -> bool:
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name=region)

    ec2_client = session.client('ec2', region_name=region)
    has_public_route = False
    subnet_route_table = None
    main_rt = None
    paginator = ec2_client.get_paginator('describe_route_tables')
    iterator = paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    # Determine the subnet route table by looking for route tables with direct assignment and if not found using
    # the default VPC route table
    for page in iterator:
        for route_table in page['RouteTables']:
            for association in route_table['Associations']:
                if association['Main']:
                    main_rt = route_table
                elif association['SubnetId'] == subnet_id:
                    subnet_route_table = route_table
    if not subnet_route_table:
        subnet_route_table = main_rt
    # Look for routes to the Internet Gateway in the associated subnet route table
    for route in subnet_route_table['Routes']:
        if 'DestinationCidrBlock' in route.keys():
            if is_public_address(route['DestinationCidrBlock']) and 'GatewayId' in route.keys():
                if 'igw-' in route['GatewayId']:
                    has_public_route = True
        elif 'DestinationPrefixListId' in route.keys():
            if 'GatewayId' in route.keys():
                if 'igw-' in route['GatewayId']:
                    prefix_list_info = ec2_client.describe_prefix_lists(
                        PrefixListIds=[route['DestinationPrefixListId']])
                    for prefix_list in prefix_list_info['PrefixLists']:
                        for cidr in prefix_list['Cidrs']:
                            if ipaddress.ip_network(cidr).version == 4:
                                if is_public_address(cidr):
                                    has_public_route = True
                                    break
    return has_public_route


def is_public_address(cidr_input: str) -> bool:
    # Build a more custom way to look for Public IPv4 addresses by ruling out that an IP is not equal to or a subnet of
    # a known bogon network. This is an assumption that may be error-prone and mark something a public IP because it is
    # not a known bogon network but still being used inside the VPC space
    result = True
    non_public_networks = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                           "169.254.0.0/16", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
                           "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"]
    for non_public_network in non_public_networks:
        if ipaddress.ip_network(cidr_input).subnet_of(ipaddress.ip_network(non_public_network)):
            result = False
            break
    return result


def describe_public_ips(associated_eip_list: list, region: str, access_key_id: str, secret_key: str,
                        session_token: str) -> list:
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name=region)

    ec2_client = session.client('ec2', region_name=region)
    known_subnets = dict()
    public_ips = list()
    paginator = ec2_client.get_paginator('describe_network_interfaces')
    iterator = paginator.paginate()
    for page in iterator:
        for network_interface in page['NetworkInterfaces']:
            eni_pub_ips = list()
            primary_pub_ip = None

            # Get the primary IP and if associated Public/EIP
            if 'Association' in network_interface.keys():
                if 'PublicIp' in network_interface['Association']:
                    if network_interface['Association']['PublicIp'] in associated_eip_list:
                        ip_type = 'Elastic IP'
                    else:
                        ip_type = 'Public IP'
                    eni_pub_ips.append({'Address': network_interface['Association']['PublicIp'], 'IP_type': ip_type})
                    primary_pub_ip = network_interface['Association']['PublicIp']

            # Get any secondary IPs and if associated Public/EIPs
            if 'PrivateIpAddresses' in network_interface.keys():
                for private_ip in network_interface['PrivateIpAddresses']:
                    if 'Association' in private_ip.keys():
                        if 'PublicIp' in private_ip['Association']:
                            if network_interface['Association']['PublicIp'] != primary_pub_ip:
                                if network_interface['Association']['PublicIp'] in associated_eip_list:
                                    ip_type = 'Elastic IP'
                                else:
                                    ip_type = 'Public IP'
                                eni_pub_ips.append(
                                    {'Address': network_interface['Association']['PublicIp'], 'IP_type': ip_type})

            # Enrich the data only if there are public IPs on the interface
            if eni_pub_ips:

                # Set the initial suspicion level and reason in case of no findings
                suspicion = 'LOW'
                reason = str()

                # Determine what type of service the interface belongs to

                interface_type = parse_interface_type(network_interface)

                # Get some standard information about the interface
                vpc_id = network_interface['VpcId']
                subnet_id = network_interface['SubnetId']
                owner_account_id = network_interface['OwnerId']
                interface_id = network_interface['NetworkInterfaceId']

                # Parse the Security groups on the interface and look for reasons to suspect necessity or not
                security_groups = list()
                for security_group in network_interface['Groups']:
                    security_groups.append(security_group['GroupId'])
                if security_groups:
                    sg_cidrs = parse_security_group_cidrs(security_groups, region, access_key_id, secret_key,
                                                          session_token)
                    has_public_ingress_cidr = False
                    for cidr in sg_cidrs['ingress']:
                        if is_public_address(cidr['cidr']):
                            has_public_ingress_cidr = True

                    has_public_egress_cidr = False
                    for cidr in sg_cidrs['egress']:
                        if is_public_address(cidr['cidr']):
                            has_public_egress_cidr = True

                    if not has_public_egress_cidr and not has_public_ingress_cidr:
                        suspicion = 'HIGH'
                        reason += (' There are no public IPs allowed in either ingress or egress security group '
                                   'rules on the interface.')
                    elif not has_public_ingress_cidr:
                        suspicion = 'MODERATE'
                        reason += (' There are no public IP addresses allowed for ingress in the security '
                                   'groups attached.')
                    elif has_public_ingress_cidr:
                        has_not_port_22 = False
                        has_port_22 = False
                        for cidr in sg_cidrs['ingress']:
                            if is_public_address(cidr['cidr']):
                                if cidr['is_ssh']:
                                    has_port_22 = True
                                else:
                                    has_not_port_22 = True
                        if has_port_22 and not has_not_port_22:
                            suspicion = 'MODERATE'
                            reason += 'Only port 22 is allowed inbound, consider EC2 Instance connect.'

                # Parse the subnets and look for reasons to suspect public IPs aren't needed
                if subnet_id in known_subnets.keys():
                    if known_subnets[subnet_id] == 'NOROUTE':
                        suspicion = 'HIGH'
                        reason += ' There is no route to an Internet Gateway for the subnet the ENI resides.'
                else:
                    has_public_route = parse_subnet_routes(vpc_id, subnet_id, region, access_key_id, secret_key,
                                                           session_token)
                    if not has_public_route:
                        known_subnets[subnet_id] = 'NOROUTE'
                        suspicion = 'HIGH'
                        reason += ' There is no route to an Internet Gateway for the subnet the ENI resides.'
                    else:
                        known_subnets[subnet_id] = 'PUBLICROUTE'
                for pub_ip in eni_pub_ips:
                    pub_ip['VpcId'] = vpc_id
                    pub_ip['SubnetId'] = subnet_id
                    pub_ip['OwnerAccountId'] = owner_account_id
                    pub_ip['InterfaceId'] = interface_id
                    pub_ip['InterfaceType'] = interface_type
                    pub_ip['Suspicion'] = suspicion
                    pub_ip['Reason'] = reason
                    public_ips.append(pub_ip)
    return public_ips


def private_subnets_with_public_ips(region: str, access_key_id: str, secret_key: str, session_token: str) -> list:
    suspicious_subnets = list()
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name=region)

    ec2_client = session.client('ec2', region_name=region)
    paginator = ec2_client.get_paginator('describe_subnets')
    iterator = paginator.paginate(Filters=[{'Name': 'map-public-ip-on-launch', 'Values': ['true']}])
    for page in iterator:
        for subnet in page['Subnets']:
            subnet_id = subnet['SubnetId']
            vpc_id = subnet['VpcId']
            owner_id = subnet['OwnerId']
            if not parse_subnet_routes(vpc_id, subnet_id, region, access_key_id, secret_key, session_token):
                suspicious_subnets.append({"SubnetId": subnet_id, "VpcId": vpc_id, "OwnerId": owner_id})

    return suspicious_subnets


def describe_vpn_connections(region: str, access_key_id: str, secret_key: str, session_token: str) -> list:
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name=region)

    ec2_client = session.client('ec2', region_name=region)
    vpn_connections = list()
    vpns = ec2_client.describe_vpn_connections()
    for vpn_connection in vpns['VpnConnections']:
        outside_ip_1 = vpn_connection['Options']['TunnelOptions'][0]['OutsideIpAddress']
        outside_ip_2 = vpn_connection['Options']['TunnelOptions'][1]['OutsideIpAddress']
        if is_public_address(outside_ip_1) or is_public_address(outside_ip_2):
            vpn_connections.append({'ConnectionID': vpn_connection['VpnConnectionId'], 'OutsideIP1': outside_ip_1,
                                    'OutsideIP2': outside_ip_2})
    return vpn_connections


def describe_global_accelerators(region: str, access_key_id: str, secret_key: str, session_token: str) -> list:
    session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                    aws_session_token=session_token, region_name='us-west-2')

    aga_client = session.client('globalaccelerator', region_name='us-west-2')
    global_accelerators = list()
    accelerators = aga_client.list_accelerators()
    for accelerator in accelerators['Accelerators']:
        aga_ip_list = list()
        for ip in accelerator['IpSets']:
            if ip['IpAddressFamily'] == 'IPv4':
                for addr in ip['IpAddresses']:
                    aga_ip_list.append(addr)
        if len(aga_ip_list) == 2:
            account_id = accelerator['AcceleratorArn'].split(':')[4]
            global_accelerators.append(
                {'owner_id': account_id, 'arn': accelerator['AcceleratorArn'], 'addr1': aga_ip_list[0],
                 'addr2': aga_ip_list[1]})
    return global_accelerators


def thread_runner(region: str, access_key_id: str, secret_key: str, session_token: str, start_time: str,
                  account_id: str = None, output_path: str = None):
    # Determine the base filename
    if account_id and output_path:
        file_name_base = output_path + '_' + start_time + '_' + account_id + '_' + region
    elif account_id:
        file_name_base = start_time + '_' + account_id + '_' + region
    elif output_path:
        file_name_base = output_path + '_' + start_time + '_' + region
    else:
        file_name_base = start_time + '_' + region

    # Get the EIP information
    eips = describe_eips(region, access_key_id, secret_key, session_token)

    unassociated_eip_output = str()
    for eip in eips['unassociated']:
        if account_id:
            unassociated_eip_output += account_id + ',' + region + ',' + eip + '\n'
        else:
            unassociated_eip_output += region + ',' + eip + '\n'
    with open(file_name_base + '_unassociated_eips.csv', 'w') as f:
        f.write(unassociated_eip_output)

    associated_eip_output = str()
    for eip in eips['associated']:
        if account_id:
            associated_eip_output += account_id + ',' + region + ',' + eip + '\n'
        else:
            associated_eip_output += region + ',' + eip + '\n'
    with open(file_name_base + '_associated_eips.csv', 'w') as f:
        f.write(associated_eip_output)

    # Get the public IP information
    eni_public_ips = describe_public_ips(eips['associated'], region, access_key_id, secret_key, session_token)
    eni_pub_ip_output = str()

    for eni_pub_ip in eni_public_ips:
        eni_pub_ip_output += ','.join(
            [eni_pub_ip['OwnerAccountId'], region, eni_pub_ip['InterfaceId'], eni_pub_ip['Address'],
             eni_pub_ip['VpcId'], eni_pub_ip['SubnetId'], eni_pub_ip['InterfaceType'], eni_pub_ip['IP_type'],
             eni_pub_ip['Suspicion'], eni_pub_ip['Reason']]) + '\n'

    with open(file_name_base + '_eni_public_ips.csv', 'w') as f:
        f.write(eni_pub_ip_output)

    # Get subnets with public IP enabled but no route to an IGW
    suspect_subnets = private_subnets_with_public_ips(region, access_key_id, secret_key, session_token)
    subnet_output = str()
    for subnet in suspect_subnets:
        subnet_output += ','.join([subnet['OwnerId'], region, subnet['VpcId'], subnet['SubnetId']]) + '\n'

    with open(file_name_base + '_private_subnets_with_auto_assign.csv', 'w') as f:
        f.write(subnet_output)

    # Get VPN connections with public IPs
    vpn_connections = describe_vpn_connections(region, access_key_id, secret_key, session_token)
    vpn_output = str()
    for vpn in vpn_connections:
        if account_id:
            vpn_output += account_id + ',' + region + ',' + vpn['ConnectionID'] + ',' + vpn['OutsideIP1'] + ',' + vpn[
                'OutsideIP2'] + '\n'
        else:
            vpn_output += region + ',' + vpn['ConnectionID'] + ',' + vpn['OutsideIP1'] + ',' + vpn['OutsideIP2'] + '\n'

    with open(file_name_base + '_vpn_connections.csv', 'w') as f:
        f.write(vpn_output)

    if region == 'us-west-2':
        # Get Global Accelerators with IPv4
        global_accelerators = describe_global_accelerators(region, access_key_id, secret_key, session_token)
        global_accelerator_output = str()
        for ga in global_accelerators:
            global_accelerator_output += ','.join([ga['owner_id'], ga['arn'], ga['addr1'], ga['addr2']]) + '\n'

        with open(file_name_base + '_global_accelerators.csv', 'w') as f:
            f.write(global_accelerator_output)


def file_region_concatenator(regions: list, file_name: str, file_base: str, error_msg: str, file_header: str = None):
    with open(file_base + '_' + file_name, 'a') as f:
        if file_header:
            f.write(file_header + '\n')
        for region in regions:
            if file_name == 'global_accelerators.csv' and region != 'us-west-2':
                pass
            else:
                try:
                    with open(file_base + '_' + region + '_' + file_name, 'r') as readfile:
                        f.write(readfile.read())
                    if os.path.exists(file_base + '_' + region + '_' + file_name):
                        os.remove(file_base + '_' + region + '_' + file_name)
                except:
                    print('No file for ' + error_msg + ' in ' + region)
                    pass


def file_account_concatenator(accounts: list, file_name: str, file_base: str, error_msg: str, file_header: str):
    with open(file_base + '_' + file_name, 'a') as f:
        f.write(file_header + '\n')
        for account in accounts:
            try:
                with open(file_base + '_' + account + '_' + file_name, 'r') as readfile:
                    f.write(readfile.read())
                if os.path.exists(file_base + '_' + account + '_' + file_name):
                    os.remove(file_base + '_' + account + '_' + file_name)
            except:
                print('No file for ' + error_msg + ' in ' + account)


def single_account(args, side_access_key_id: str = None, side_secret_key: str = None, side_session_token: str = None,
                   side_output_path: str = None, side_regions: str = None, side_account: str = None,
                   start_time: str = None) -> None:
    if not start_time:
        start_time = str(int(time.time()))
    try:
        opts, args = getopt.getopt(args, '', ['profile=', 'regions=', 'access-key-id=', 'secret-key=', 'session-token=',
                                              'output-path='])
    except:
        print("Error")
        sys.exit(1)
    boto_profile = None
    regions_input = None
    access_key_id = None
    secret_key = None
    session_token = None
    output_path = None
    for opt, arg in opts:
        if opt in ['--profile']:
            boto_profile = arg
        elif opt in ['--regions']:
            regions_input = arg
        elif opt in ['--access-key-id']:
            access_key_id = arg
        elif opt in ['--secret-key']:
            secret_key = arg
        elif opt in ['--session-token']:
            session_token = arg
        elif opt in ['--output-path']:
            output_path = arg

    if side_secret_key:
        access_key_id = side_access_key_id
    if side_access_key_id:
        secret_key = side_secret_key
    if side_session_token:
        session_token = side_session_token
    if side_output_path:
        output_path = side_output_path
    if side_regions:
        regions_input = side_regions

    if boto_profile:
        if access_key_id and secret_key:
            session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                            aws_session_token=session_token, profile_name=boto_profile)
        else:
            session = boto3.session.Session(profile_name=boto_profile)
    elif access_key_id and secret_key:
        session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                        aws_session_token=session_token)
    else:
        session = boto3.session.Session()
    regions = list()
    ec2_regions_client = session.client('ec2', region_name='us-east-1')
    ec2_regions = ec2_regions_client.describe_regions()['Regions']
    for region in ec2_regions:
        if region['OptInStatus'] != 'not-opted-in':
            regions.append(region['RegionName'])
    if regions_input:
        region_inputs_validated = list()
        region_inputs = regions_input.split(',')
        for region in region_inputs:
            if region in regions:
                region_inputs_validated.append(region)
        regions = region_inputs_validated
    if not access_key_id:
        access_key_id = session.get_credentials().access_key
    if not secret_key:
        secret_key = session.get_credentials().secret_key
    if not session_token:
        session_token = session.get_credentials().token
    procs = list()
    for region in regions:
        procs.append(Process(target=thread_runner, args=(
            region, access_key_id, secret_key, session_token, start_time, side_account, output_path)))

    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()

    # Determine the base filename
    if side_account and output_path:
        file_name_base = output_path + '_' + start_time + '_' + side_account
    elif side_account:
        file_name_base = start_time + '_' + side_account
    elif output_path:
        file_name_base = output_path + '_' + start_time
    else:
        file_name_base = start_time

    if side_account:
        file_names = ['unassociated_eips.csv', 'associated_eips.csv', 'eni_public_ips.csv',
                      'private_subnets_with_auto_assign.csv', 'vpn_connections.csv', 'global_accelerators.csv']
        for fname in file_names:
            error_msg_text = fname.replace('_', ' ').replace('.csv', '')
            file_region_concatenator(regions, fname, file_name_base, error_msg_text)

    if not side_account:
        file_names = list()
        file_names.append({'file_name': 'unassociated_eips.csv', 'header': 'Region, EIP'})
        file_names.append({'file_name': 'associated_eips.csv', 'header': 'Region, EIP'})
        file_names.append({'file_name': 'eni_public_ips.csv',
                           'header': 'OwnerAccountId, Region, InterfaceId, Address, VpcId, SubnetId, InterfaceType, '
                                     'AddressType, SuspectUnnecessary, Reason'})
        file_names.append(
            {'file_name': 'private_subnets_with_auto_assign.csv', 'header': 'OwnerAccountId, Region, VpcId, SubnetId'})
        file_names.append({'file_name': 'vpn_connections.csv', 'header': 'Region, ConnectionId, Address1, Address2'})
        file_names.append({'file_name': 'global_accelerators.csv', 'header': 'OwnerAccountId, Arn, Address1, Address2'})
        for fname in file_names:
            file_name = fname['file_name']
            file_header = fname['header']
            error_msg_text = file_name.replace('_', ' ').replace('.csv', '')
            file_region_concatenator(regions, file_name, file_name_base, error_msg_text, file_header)


def multi_account(args):
    start = str(int(time.time()))
    try:
        opts, args = getopt.getopt(args, '', ['profile=', 'regions=', 'accounts=', 'access-key-id=', 'secret-key=',
                                              'session-token=', 'external-id=', 'role-name=', 'output-path='])
    except:
        print("Error")
        sys.exit(1)
    boto_profile = None
    regions_input = None
    accounts = None
    access_key_id = None
    secret_key = None
    session_token = None
    output_path = None
    external_id = None
    role_name = None
    for opt, arg in opts:
        if opt in ['--profile']:
            boto_profile = arg
        elif opt in ['--regions']:
            regions_input = arg
        elif opt in ['--accounts']:
            accounts = arg
        elif opt in ['--access-key-id']:
            access_key_id = arg
        elif opt in ['--secret-key']:
            secret_key = arg
        elif opt in ['--session-token']:
            session_token = arg
        elif opt in ['--output-path']:
            output_path = arg
        elif opt in ['--external-id']:
            external_id = arg
        elif opt in ['--role-name']:
            role_name = arg

    if boto_profile:
        if access_key_id and secret_key:
            local_v1_session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                                     aws_session_token=session_token, profile_name=boto_profile)
        else:
            local_v1_session = boto3.session.Session(profile_name=boto_profile)
    elif access_key_id and secret_key:
        local_v1_session = boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_key,
                                                 aws_session_token=session_token)
    else:
        local_v1_session = boto3.session.Session()
    sts_client = local_v1_session.client('sts')
    local_session = local_v1_session.get_credentials()
    local_account = sts_client.get_caller_identity()['Account']
    if not accounts:
        accounts = list()
        unchecked_accounts = list()
        orgs = local_v1_session.client('organizations', region_name='us-east-1')
        paginator = orgs.get_paginator('list_accounts')
        iterator = paginator.paginate()
        for page in iterator:
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append(account['Id'])
                else:
                    unchecked_accounts.append(account['Id'])
        if output_path:
            file_name = output_path + 'unchecked_accounts.csv'
        else:
            file_name = 'unchecked_accounts.csv'
        with open(file_name, 'w') as f:
            f.write('\n'.join(unchecked_accounts))
    else:
        if ',' in accounts:
            accounts = str(accounts).replace(' ', '').split(',')
        elif len(accounts) > 14:
            print('invalid account specification, please specify a list of accounts seperated by a comma.')
            exit(1)
        else:
            accounts = list(str(accounts).replace(' ', ''))

    paginated_account_list = [accounts[i:i + 10] for i in range(0, len(accounts), 10)]

    session_policy = {"Version": "2012-10-17", "Statement": [{"Sid": "RequiredDescribeCalls", "Effect": "Allow",
                                                              "Action": ["ec2:DescribeAddresses",
                                                                         "ec2:DescribeSecurityGroupRules",
                                                                         "ec2:DescribeRouteTables",
                                                                         "ec2:DescribePrefixLists",
                                                                         "ec2:DescribeNetworkInterfaces",
                                                                         "ec2:DescribeSubnets",
                                                                         "ec2:DescribeVpnConnections",
                                                                         "ec2:DescribeRegions",
                                                                         "globalaccelerator:ListAccelerators", ],
                                                              "Resource": "*"}]}
    for page_of_accounts in paginated_account_list:
        procs = list()
        for account in page_of_accounts:
            if account == local_account:

                access_key_id = local_session.access_key
                secret_key = local_session.secret_key
                try:
                    session_token = local_session.token
                except:
                    session_token = None
                procs.append(Process(target=single_account, args=(
                    None, access_key_id, secret_key, session_token, output_path, regions_input, account, start)))
            else:
                if role_name:
                    role = "arn:aws:iam::" + str(account) + ":role/" + role_name
                else:
                    role = "arn:aws:iam::" + str(account) + ":role/OrganizationAccountAccessRole"
                sts = local_v1_session.client('sts', region_name='us-east-1',
                                              endpoint_url='https://sts-fips.us-east-1.amazonaws.com')
                try:
                    if external_id:
                        role_info = sts.assume_role(RoleArn=role, RoleSessionName='IPv4UsageMonitoringForAWS',
                                                    Policy=json.dumps(session_policy), DurationSeconds=3600,
                                                    ExternalId=external_id)
                    else:
                        role_info = sts.assume_role(RoleArn=role, RoleSessionName='IPv4UsageMonitoringForAWS',
                                                    Policy=json.dumps(session_policy), DurationSeconds=3600)
                except:
                    print("ERROR: Unable to assume role for account `" + str(account) + "`")
                    continue
                if 'Credentials' in role_info.keys():
                    access_key_id = role_info['Credentials']['AccessKeyId']
                    secret_key = role_info['Credentials']['SecretAccessKey']
                    session_token = role_info['Credentials']['SessionToken']

                    procs.append(Process(target=single_account, args=(
                        None, access_key_id, secret_key, session_token, output_path, regions_input, account, start)))
                else:
                    print("ERROR: Unable to assume role for account `" + str(account) + "`")
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join()

    if output_path:
        file_name_base = output_path + '_' + start
    else:
        file_name_base = start
    file_names = list()
    file_names.append({'file_name': 'unassociated_eips.csv', 'header': 'AccountId, Region, EIP'})
    file_names.append({'file_name': 'associated_eips.csv', 'header': 'AccountId, Region, EIP'})
    file_names.append({'file_name': 'eni_public_ips.csv',
                       'header': 'OwnerAccountId, Region, InterfaceId, Address, VpcId, SubnetId, InterfaceType, '
                                 'AddressType, SuspectUnnecessary, Reason'})
    file_names.append(
        {'file_name': 'private_subnets_with_auto_assign.csv', 'header': 'OwnerAccountId, Region, VpcId, SubnetId'})
    file_names.append(
        {'file_name': 'vpn_connections.csv', 'header': 'AccountId, Region, ConnectionId, Address1, Address2'})
    file_names.append({'file_name': 'global_accelerators.csv', 'header': 'OwnerAccountId, Arn, Address1, Address2'})
    for fname in file_names:
        file_name = fname['file_name']
        file_header = fname['header']
        error_msg_text = file_name.replace('_', ' ').replace('.csv', '')
        file_account_concatenator(accounts, file_name, file_name_base, error_msg_text, file_header)


def arg_parser_parent(actionobj, argsobj=None):
    if actionobj not in ['run-single-account', 'run-multi-account', 'exit']:
        print("ERROR: Unknown action `" + actionobj + "`.")
        sys.exit(1)
    if actionobj == 'run-single-account':
        single_account(argsobj)
    if actionobj == 'run-multi-account':
        multi_account(argsobj)


if __name__ == '__main__':
    if sys.argv[1:]:
        argv = sys.argv[2:]
        action = str(sys.argv[1])
        arg_parser_parent(action, argv)
    else:
        print('Missing action: ["run-multi-account", "run-single-account"')

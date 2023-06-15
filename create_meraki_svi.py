#!/usr/bin/env python3
"""
Copyright (c) 2023 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Mark Orszycki <morszyck@cisco.com>, Trevor Maco <tmaco@cisco.com>"
__copyright__ = "Copyright (c) 2023 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import ipaddress
import os
import re
import sys

import meraki
from ciscoconfparse import CiscoConfParse
from netmiko import ConnectHandler
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

from config import *

# Create a Meraki API client
dashboard = meraki.DashboardAPI(API_KEY, suppress_logging=True)

# Grab existing list of SVIs
response = dashboard.switch.getDeviceSwitchRoutingInterfaces(MS_SERIAL)
SVIs = [str(svi['vlanId']) for svi in response]

# Rich Console Instance
console = Console()


def get_switch_config():
    """
    Connect to target switch over ssh, retrieve show run output
    :return: String containing results of 'show run' command
    """
    # The source catalyst switch
    switch = {
        "device_type": "cisco_ios",
        "ip": SWITCH_IP,
        "username": SWITCH_USERNAME,
        "password": SWITCH_PASSWORD,
        "secret": SWITCH_SECRET
    }

    console.print(f'Connecting to Switch at [green]{SWITCH_IP}[/]...')

    # Get show run config from switch
    show_command = f"show run"

    with ConnectHandler(**switch) as connection:
        console.print(f' - [green]Connected![/]')

        # Enter privilege mode
        connection.enable()

        # Send command
        output = connection.send_command(show_command)

        # Check if show output is valid
        if 'Invalid' in output:
            console.print(f' - [red]Failed to execute "{show_command}"[/], please ensure the command is correct!')
            return None
        else:
            console.print(f' - Executed [blue]"{show_command}"[/] successfully!')
            return output


def parse_switch_config(file_path):
    """
    Parse SVI config from show run, extract SVI pieces and build dictionary of SVIs
    :param file_path: File path to temporary file containing show run output
    :return: Dictionary of parsed SVIs
    """
    # parse config file for VLANs
    parse = CiscoConfParse(file_path, syntax='ios')
    vlans = parse.find_objects(r'^interface Vlan')

    vlan_count = len(vlans)
    console.print(f'Found [blue]{vlan_count} vlans[/] to convert!')

    # REGEX expressions
    description_re = r"description\s(.+)"
    ip_address_re = r"ip\saddress\s([\d\.]+)\s([\d\.]+)"
    ip_helper_address_re = r"ip\shelper-address\s([\d\.]+)"

    # Store the extracted information in a dictionary
    svi_data = {}

    # iterate over VLANs, extract out fields for Meraki API call
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=vlan_count, transient=True)
        counter = 1

        for vlan in vlans:
            # Get vlan id
            vlan_id = re.search(r'\d+', vlan.text).group()

            progress.console.print(
                "Creating [blue]vlan {}[/] object... ({} of {})".format(vlan_id, str(counter), vlan_count))

            description = ''
            ip_address = ''
            subnet_mask = ''
            ip_helper_addresses = []

            # Search children for description, ip, subnet, helper-address
            for child in vlan.children:
                if 'description' in child.text:
                    description = child.re_match_typed(description_re, group=1)
                elif 'ip address' in child.text:
                    ip_address = child.re_match_typed(ip_address_re, group=1)
                    subnet_mask = child.re_match_typed(ip_address_re, group=2)
                elif 'ip helper-address' in child.text:
                    ip_helper_address = child.re_match_typed(ip_helper_address_re, group=1)

                    # Check if this address is a DHCP Address
                    if ip_helper_address in DHCP_SERVER:
                        ip_helper_addresses.append(ip_helper_address)

            if vlan_id not in svi_data and ip_address != '' and subnet_mask != '':
                # Convert ip/subnet to cidr notation for API call
                subnet = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)

                svi_data[vlan_id] = {
                    "description": description if description != '' else 'Vlan' + vlan_id,
                    "vlan_id": vlan_id,
                    "interface_ip": ip_address,
                    "subnet": str(subnet),
                    "ip_helper_addresses": ip_helper_addresses
                }

                progress.console.print(svi_data[vlan_id])
            else:
                # If key fields are missing, skip
                progress.console.print('[red]Error: one or more key fields are missing from vlan[/] ("ip address"). '
                                       'Skipping...')

            counter += 1
            progress.update(overall_progress, advance=1)

    return svi_data


def default_gateway_exists():
    """
    Check if a default gateway exists for the Meraki MS.
    """
    svi_list_response = dashboard.switch.getDeviceSwitchRoutingInterfaces(MS_SERIAL)
    for svi in svi_list_response:
        if 'defaultGateway' in svi:
            return True
        return False    


def create_default_svi(svi_data):
    """
    Create Meraki SVI which contains default gateway, see README for restrictions on default gateway
    :param svi_data: List of parsed SVIs from Show Run output
    :return:
    """
    target_svi_id = ""

    # Find the SVI which contains the DEFAULT_GATEWAY, create this SVI first
    for vlan_info in svi_data.values():
        network = ipaddress.ip_network(vlan_info['subnet'])

        # Default gateway belongs on this routed interface, create
        if ipaddress.ip_address(DEFAULT_GATEWAY) in network:
            create_svi(console, vlan_info, DEFAULT_GATEWAY)

            target_svi_id = vlan_info['vlan_id']

    # Default gateway doesn't exist on SVI, error
    if target_svi_id == "":
        console.print(f"[red]Error: {DEFAULT_GATEWAY} doesn't exist on SVI, please ensure Default Gateway exists on exactly "
                      f"one imported SVI.[/]")
        return None

    # remove SVI from dictionary
    del svi_data[target_svi_id]

    return target_svi_id


def create_svi(console, vlan_info, default_gateway):
    """
    Create Meraki SVI using Meraki API
    :param console: progress console for printing
    :param vlan_info: Parsed SVI data
    :param default_gateway: Flag, included in API Call Payload if defined
    :return:
    """
    # Skip existing SVIs
    if vlan_info["vlan_id"] in SVIs:
        console.print(f'VLAN {vlan_info["vlan_id"]} already exists! Skipping...')
        return

    interface_data = {
        "name": vlan_info["description"],
        "subnet": vlan_info['subnet'],
        "interfaceIp": vlan_info['interface_ip'],
        "vlanId": int(vlan_info["vlan_id"])
    }

    if default_gateway:
        interface_data['defaultGateway'] = default_gateway

    # Create Meraki SVI
    svi_response = dashboard.switch.createDeviceSwitchRoutingInterface(MS_SERIAL, **interface_data)

    if svi_response:
        console.print(f"Successfully created SVI for [green]VLAN {vlan_info['vlan_id']}[/]")

        # Add DHCP Relay Servers to Interface (if applicable)
        if len(vlan_info['ip_helper_addresses']) > 0:
            dhcp_response = dashboard.switch.updateDeviceSwitchRoutingInterfaceDhcp(serial=MS_SERIAL,
                                                                                    interfaceId=svi_response[
                                                                                        'interfaceId'],
                                                                                    dhcpMode='dhcpRelay',
                                                                                    dhcpRelayServerIps=vlan_info[
                                                                                        'ip_helper_addresses'])

            if dhcp_response:
                console.print(f" - Added [blue]DHCP Relay(s)[/] {vlan_info['ip_helper_addresses']} for [green]VLAN {vlan_info['vlan_id']}[/]")
    else:
        console.print(f"[red]Failed to create SVI for VLAN {vlan_info['vlan_id']}[/]")


def main():
    console.print(Panel.fit("Cisco Catalyst SVI to Meraki MS Migration"))

    # Connect to catalyst switch using netmiko (ssh), retrieve show vlan output
    console.print(Panel.fit(f"Get Switch Config (SSH)", title="Step 1"))
    config = get_switch_config()

    # If config is None, netmiko command failed
    if not config:
        sys.exit(-1)

    # Write results to temp output file for CiscoConfParse to read
    temp_file = "temp.txt"
    with open(temp_file, 'w') as f:
        # Write a string to the file
        f.write(config)

    # Parse show run for vlans
    console.print(Panel.fit(f"Parse Switch Config SVIs", title="Step 2"))
    svi_data = parse_switch_config(temp_file)

    console.print(Panel.fit(f"Create Default Gateway SVI on MS", title="Step 3"))

    # Check MS to see if existing default gateway exists for SVI
    if not default_gateway_exists():
        # Create SVI that contains default gateway first
        result = create_default_svi(svi_data)
        # Default gateway is invalid
        if not result:
            sys.exit(-1)

    # Create the L3 SVIs on Meraki for remaining SVIs
    console.print(Panel.fit(f"Create Remaining SVIs on MS", title="Step 4"))
    vlan_count = len(svi_data.values())

    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=vlan_count, transient=True)
        counter = 1

        for vlan_info in svi_data.values():
            create_svi(progress.console, vlan_info, None)

            counter += 1
            progress.update(overall_progress, advance=1)

    # Delete temp file
    os.remove("temp.txt")


if __name__ == "__main__":
    main()

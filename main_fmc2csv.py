"""
Main application to pull Access Control Policy from any FMC via API
"""
import json
import base64
from getpass import getpass
from datetime import datetime
from re import search
from tkinter import N
from rich.console import Console
from rich.table import Table
import xlsxwriter
import urllib3
import requests
from banner import banner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def logging_json_files(fmc_operation, json_var):
    with open(f"latest_json/{fmc_operation}_latest_json-" + datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p") + ".json", "w") as outfile:
        outfile.write(json_var)

def get_token(uname, pword, fmc_ip):
    """
    Function to gather access token from FMC device
    """
    credentials = f'{uname}:{pword}'
    base64_cred = base64.b64encode(credentials.encode('ascii')).decode('ascii')
    api_url = f'https://{fmc_ip}/api/fmc_platform/v1/auth/generatetoken'
    http_headers = {'Authorization': 'Basic ' + base64_cred}
    response = requests.post( url = api_url, headers = http_headers, verify = False, timeout=5)
    # print(response.status_code)
    if str(response.status_code) in ['404', '403', '401']:
        print(f'## ERROR during token authentication with Status code: {response.status_code}')
        print(f'Detailed message: {response.text}')
        return None
    return [response.headers['X-auth-access-token'], response.headers['X-auth-refresh-token']]

def get_fmc_domains(auth_token, fmc_ip):
    '''
    function to gather domains under FMC
    '''
    api_url = f'https://{fmc_ip}/api/fmc_platform/v1/info/domain?expanded=false'
    http_headers = {'X-auth-access-token' : auth_token}
    response = requests.get( url = api_url, headers = http_headers, verify = False, timeout=5)
    if str(response.status_code) in ['404', '403', '401']:
        print(f'\n\n## ERROR during token authentication with Status code: {response.status_code}')
        print(f'Detailed message: {response.text}')
        return None
    return response.text

def get_fmc_apclist(auth_token, fmc_ip, fmc_domain):
    '''
    function to gather APC in a single domain under FMC
    '''
    api_url = f'https://{fmc_ip}/api/fmc_config/v1/domain/{fmc_domain}/policy/accesspolicies?limit=100'
    http_headers = {'X-auth-access-token' : auth_token}
    response = requests.get( url = api_url, headers = http_headers, verify = False, timeout=5)
    if str(response.status_code) in ['404', '403', '401']:
        print(f'\n\n## ERROR during token authentication with Status code: {response.status_code}')
        print(f'Detailed message: {response.text}')
        return None
    return response.text

def get_fmc_apc_rules(auth_token, fmc_ip, fmc_domain, apc_uuid):
    '''
    function to gather APC rules in a single domain under FMC
    '''
    api_url = f'https://{fmc_ip}/api/fmc_config/v1/domain/{fmc_domain}/policy/accesspolicies/{apc_uuid}/accessrules?limit=60&expanded=true'
    http_headers = {'X-auth-access-token' : auth_token}
    response = requests.get( url = api_url, headers = http_headers, verify = False, timeout=5)
    if str(response.status_code) in ['404', '403', '401']:
        print(f'\n\n## ERROR during token authentication with Status code: {response.status_code}')
        print(f'Detailed message: {response.text}')
        return None
    return response.text

def fmc_domain_table(fmc_domains):
    '''
    FMC domain table and user selection
    '''
    console = Console()
    domain_table = Table(title = 'Domains under FMC', expand = True)
    domain_table.add_column("Domain name", justify="right", style="cyan", no_wrap=True)
    domain_table.add_column("UUID", justify="right", style="green")
    for fmc_domain in json.loads(fmc_domains)['items']:
        domain_table.add_row(fmc_domain['name'], fmc_domain['uuid'])
    console.print(domain_table)
    selected_domain = input('\n++++ Select Domain UUID to pull from FMC: ') or 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
    # TODO: if selected domain is ALL, display APC per domain
    return selected_domain

def fmc_apcs_table(fmcdomain_apcs):
    '''
    FMC APC table and user selection
    '''
    console = Console()
    apcs_table = Table(title = 'Access Control Policy under FMC domain', expand = True, show_lines = True)
    apcs_table.add_column("APC name", justify="right", style="cyan", no_wrap=True)
    apcs_table.add_column("UUID", justify="right", style="green")
    # print(json.loads(fmcdomain_apcs))
    # print(type(fmcdomain_apcs))
    # print(json.dumps(fmcdomain_apcs))
    for fmc_apc in json.loads(fmcdomain_apcs)['items']:
        apcs_table.add_row(fmc_apc['name'], fmc_apc['id'])
    console.print(apcs_table)
    selectec_apc = input('\n++++ Select APC ID to pull from FMC: ') or '005056BF-7C6E-0ed3-0000-244813702083'
    # TODO: if selected APC is ALL, display APC per domain
    return selectec_apc

def fmc_apcrules_list(fmc_apcrules):
    '''
    FMC APC rules table and user selection to print into CSV
    '''
    console = Console()
    apcs_table = Table(title = 'Access Control Policy rules under FMC domain',
                # expand = True,
                show_lines = True)
    apcs_table.add_column("Rule ID / State", justify="center", style="cyan") # 0
    apcs_table.add_column("Action", justify="right", style="green") # 1
    apcs_table.add_column("Name", justify="right", style="green") # 2
    apcs_table.add_column("Src Zone", justify="right", style="green") # 3
    apcs_table.add_column("Src Net", justify="right", style="green") # 4
    apcs_table.add_column("Src Ports", justify="right", style="green") # 5
    apcs_table.add_column("Dst Zone", justify="right", style="green") # 6
    apcs_table.add_column("Dst Net", justify="right", style="green") # 7
    apcs_table.add_column("Dst Ports", justify="right", style="green") # 8
    apcs_table.add_column("Comment history", justify="left", style="blue") # 9
    apcs_table.add_column("IPS Policy", justify="left", style="red") # 10

    #print(type(json.loads(fmc_apcrules)))
    # print(json.dumps(fmc_apcrules, indent = 4))
    # TODO: Add Section, Category, URL list, Src port, dst port, and features
    # such as: comment, IPS Policy, File Policy, logging
    for apc_rule in fmc_apcrules:
        # print(type(apc_rule))
        # print(apc_rule)
        list_row = apc2row(apc_rule)
        # print(list_row)
        # print(type(list_row))
        disabled_rule = ''
        if apc_rule['enabled'] is False:
            disabled_rule = '[dim italic grey70]'
        apcs_table.add_row(disabled_rule + list_row[0],
                            disabled_rule + list_row[1],
                            disabled_rule + list_row[2],
                            disabled_rule + list_row[3],
                            disabled_rule + list_row[4],
                            disabled_rule + list_row[5],
                            disabled_rule + list_row[6],
                            disabled_rule + list_row[7],
                            disabled_rule + list_row[8],
                            disabled_rule + list_row[9],
                            disabled_rule + list_row[10])
    console.print(apcs_table)

def apc2row(apc_rule):
    '''
    creates a string which will be each row under a table
    '''
    returned_obj = [str(apc_rule['metadata']['ruleIndex']) + '\n' + '[green]enabled' if apc_rule['enabled']\
                     else str(apc_rule['metadata']['ruleIndex']) + '\n' + 'disabled',
                    apc_rule['action'] + ' [green]:heavy_check_mark:',
                    apc_rule['name'],
                    'Any', 'Any', 'Any', 'Any','Any','Any', 'N/A', 'N/A']

    if search('block', apc_rule['action'].lower()):
        returned_obj[1] = '[red]:no_entry: ' + apc_rule['action']
    if 'sourceZones' in apc_rule:
        returned_obj[3] = rule_obj_extractor(apc_rule['sourceZones'])
    if 'sourceNetworks' in apc_rule:
        returned_obj[4] = rule_obj_extractor(apc_rule['sourceNetworks'])
    if 'sourcePorts' in apc_rule:
        returned_obj[5] = rule_obj_extractor(apc_rule['sourcePorts'])
    if 'destinationZones' in apc_rule:
        returned_obj[6] = rule_obj_extractor(apc_rule['destinationZones'])
    if 'destinationNetworks' in apc_rule:
        returned_obj[7] = rule_obj_extractor(apc_rule['destinationNetworks'])
    if 'destinationPorts' in apc_rule:
        returned_obj[8] = rule_obj_extractor(apc_rule['destinationPorts'])
    if 'commentHistoryList' in apc_rule:
        returned_obj[9] = rule_obj_extractor(apc_rule)
    if 'ipsPolicy' in apc_rule:
        returned_obj[10] = apc_rule['ipsPolicy']['name'] + '\nMode: ' + apc_rule['ipsPolicy']['inspectionMode']
    # print(returned_obj)
    return returned_obj

def rule_obj_extractor(obj2extract):
    """
    Function to extract particular objects from a nested rule
    """
    returned_obj = ''
    if 'objects' in obj2extract:
        for single_obj in obj2extract['objects']:
            returned_obj += single_obj['name'] + '\n'
    if 'commentHistoryList' in obj2extract:
        for rule_comment in obj2extract['commentHistoryList']:
            returned_obj += rule_comment['date'][:16] + ' ' + rule_comment['user']['name'] + ': ' + rule_comment['comment'] + '\n'
    if 'literals' in obj2extract:
        for literal in obj2extract['literals']:
            try:
                returned_obj += literal['type'] + ': ' + literal['value'] + '\n'
            except:
                if literal['protocol'] == '6':
                    returned_obj += literal['type'] + ' TCP: ' + literal['port'] + '\n'
                else:
                    returned_obj += literal['type'] + ' UDP:' + literal['port'] + '\n'
    return returned_obj

def workbook_xls():
    """
    Function to create an excel file workbook
    """
    ## Definicion de Excel

    workbook = xlsxwriter.Workbook("latest_access_rules-" + datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p") + ".xlsx")
    bold_format = workbook.add_format({'bold': True})
    cell_format = workbook.add_format()
    cell_format.set_align('center')
    cell_format.set_align('top')
    worksheet = workbook.add_worksheet("AccessRules")

    worksheet.write("A1","RID", bold_format)
    worksheet.write("B1","Rule Name", bold_format)
    worksheet.write("C1","Enabled", bold_format)
    worksheet.write("D1","Rule Action", bold_format)
    worksheet.write("E1","Source Zone", bold_format)
    worksheet.write("F1","Source Network", bold_format)
    worksheet.write("G1","destination Zone", bold_format)
    worksheet.write("H1","Destination Network", bold_format)
    worksheet.write("I1","Destination ports", bold_format)
    worksheet.write("J1","Users", bold_format)
    worksheet.write("K1","App List", bold_format)
    worksheet.write("L1","Risk / Filters / Search", bold_format)
    worksheet.write("M1","Comments", bold_format)
    row_index = 2
    workbook.close()

def main_fmc2csv():
    """
    Main function that will sort steps across the application
    """
    print(banner)
    fmc_ip = 'fmcrestapisandbox.cisco.com' ## Default
    fmc_ip = input(f'++++ Insert FMC IP or FQDN [{fmc_ip}]: ') or fmc_ip
    fmc_user = input('++++ Insert FMC Username: ') or 'ingleseang'
    fmc_pass = getpass('++++ Insert FMC user password: ') or 'HQyjy24a'
    session_tkn = get_token(uname=fmc_user, pword=fmc_pass, fmc_ip=fmc_ip)
    # print(session_tkn)
    fmc_domains = get_fmc_domains(session_tkn[0], fmc_ip)
    # logging_json_files('fmc_domains', fmc_domains)
    # print(fmc_domains)
    selected_domain = fmc_domain_table(fmc_domains)
    fmcdomain_apcs = get_fmc_apclist(session_tkn[0], fmc_ip, selected_domain)
    # logging_json_files('fmcdomain_apcs', fmcdomain_apcs)
    selected_domainapc = fmc_apcs_table(fmcdomain_apcs)
    fmcapc_rules = get_fmc_apc_rules(session_tkn[0], fmc_ip, selected_domain,selected_domainapc)
    # logging_json_files('fmcapc_rules', fmcapc_rules)
    fmc_apcrules_list(json.loads(fmcapc_rules)['items'])
# TODO: Collect all rules from FMC into a class
# TODO: Define all parameters on each rule
# TODO: Define all paramenters on a Access Policy, sections, global parameters

if __name__ == "__main__":
    main_fmc2csv()

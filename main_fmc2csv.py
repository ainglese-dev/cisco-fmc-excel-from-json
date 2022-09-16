import json
import base64
from textwrap import indent
from rich.console import Console
from rich.table import Table
import xlsxwriter
import time
import urllib3
from getpass import getpass
import requests
from datetime import datetime
from banner import banner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# class FMC_domains:

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
        print(f'## ERROR during token authentication with Status code: {response.status_code}')
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
        print(f'## ERROR during token authentication with Status code: {response.status_code}')
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
        print(f'## ERROR during token authentication with Status code: {response.status_code}')
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
    selected_domain = input('\n++++ Select Domain UUID to pull from FMC: ')
    # TODO: if selected domain is ALL, display APC per domain
    return selected_domain

def fmc_apcs_table(fmcdomain_apcs):
    '''
    FMC APC table and user selection
    '''
    console = Console()
    apcs_table = Table(title = 'Access Control Policy under FMC domain', expand = True)
    apcs_table.add_column("APC name", justify="right", style="cyan", no_wrap=True)
    apcs_table.add_column("UUID", justify="right", style="green")
    # print(json.loads(fmcdomain_apcs))
    for fmc_apc in json.loads(fmcdomain_apcs)['items']:
        apcs_table.add_row(fmc_apc['name'], fmc_apc['id'])
    console.print(apcs_table)
    selectec_apc = input('\n++++ Select APC ID to pull from FMC: ')
    # TODO: if selected APC is ALL, display APC per domain
    return selectec_apc

def fmc_apcrules_list(fmc_apcrules):
    '''
    FMC APC rules table and user selection to print into CSV
    '''
    console = Console()
    apcs_table = Table(title = 'Access Control Policy rules under FMC domain', expand = True)
    apcs_table.add_column("Rule ID", justify="right", style="cyan", no_wrap=True)
    apcs_table.add_column("Name", justify="right", style="green")
    apcs_table.add_column("Action", justify="right", style="green")
    apcs_table.add_column("Src Zone", justify="right", style="green")
    apcs_table.add_column("Src Net", justify="right", style="green")
    apcs_table.add_column("Dst Zone", justify="right", style="green")
    apcs_table.add_column("Dst Net", justify="right", style="green")

    # TODO: Add Section, Category, URL list, Src port, dst port, and features such as: comment, IPS Policy, File Policy, logging
    # print(json.loads(fmcdomain_apcs))
    for apc_rule in json.loads(fmc_apcrules)['items']:
        apcs_table.add_row(apc2row(apc_rule))
    console.print(apcs_table)
    # selectec_apc = input('\n++++ Select APC ID to pull from FMC: ')

def apc2row(apc_rule):
    pass

def rule_obj_extractor(object):
    returned_obj = ''
    match object:
        case object['sourceZones']:
            for item in object['sourceZones']:
                returned_obj.append(item['name'] + '\n')
            return returned_obj
        case _:
            return 'Any'

def workbook_xls():
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
    print(banner)
    fmc_ip = input('++++ Insert FMC IP or FQDN: ')
    fmc_user = input('++++ Insert FMC Username: ')
    fmc_pass = getpass('++++ Insert FMC user password: ')
    session_tkn = get_token(uname=fmc_user, pword=fmc_pass, fmc_ip=fmc_ip)
    # print(session_tkn)
    fmc_domains = get_fmc_domains(session_tkn[0], fmc_ip)
    selected_domain = fmc_domain_table(fmc_domains)
    fmcdomain_apcs = get_fmc_apclist(session_tkn[0], fmc_ip, selected_domain) 
    selected_domainapc = fmc_apcs_table(fmcdomain_apcs)
    fmcapc_rules = get_fmc_apc_rules(session_tkn[0], fmc_ip, selected_domain,selected_domainapc)
    fmc_apcrules_list(fmcapc_rules)
# TODO: Collect all rules from FMC into a class
# TODO: Define all parameters on each rule
# TODO: Define all paramenters on a Access Policy, sections, global parameters
if __name__ == "__main__":

    main_fmc2csv()

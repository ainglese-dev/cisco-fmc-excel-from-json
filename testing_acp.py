import json
from textwrap import indent
from rich.console import Console
from rich.table import Table
from re import search

def fmc_apcrules_list(fmc_apcrules):
    '''
    FMC APC rules table and user selection to print into CSV
    '''
    console = Console()
    apcs_table = Table(title = 'Access Control Policy rules under FMC domain', 
                expand = False, 
                show_lines = True)
    apcs_table.add_column("Rule ID", justify="center", style="cyan")
    apcs_table.add_column("Action", justify="right", style="green")
    apcs_table.add_column("Name", justify="right", style="green")
    apcs_table.add_column("Src Zone", justify="right", style="green")
    apcs_table.add_column("Src Net", justify="right", style="green")
    apcs_table.add_column("Dst Zone", justify="right", style="green")
    apcs_table.add_column("Dst Net", justify="right", style="green")

    # TODO: Add Section, Category, URL list, Src port, dst port, and features such as: comment, IPS Policy, File Policy, logging
    # print(type(fmc_apcrules[0]))
    for apc_rule in fmc_apcrules:
        list_row = apc2row(apc_rule)
        # print(list_row)
        apcs_table.add_row(list_row[0], 
                            list_row[1], list_row[2], list_row[3],
                            list_row[4], list_row[5], list_row[6])
    console.print(apcs_table)
    # selectec_apc = input('\n++++ Select APC ID to pull from FMC: ')


def apc2row(apc_rule):
    '''
    creates a string which will be each row under a table
    '''
    returned_obj = [str(apc_rule['metadata']['ruleIndex']), 
    apc_rule['action'] + ' [green]:heavy_check_mark:', 
    apc_rule['name'], 
    'Any', 'Any', 'Any', 'Any']
    if search('block', apc_rule['action'].lower()):
        returned_obj[1] = '[red]:no_entry: ' + apc_rule['action']
    if search('monitor', apc_rule['action'].lower()):
        returned_obj[1] = '[grey]:blue_box_with_checkmark: ' + apc_rule['action']
    if 'sourceZones' in apc_rule:
        returned_obj[3] = rule_obj_extractor(apc_rule['sourceZones'])
    if 'sourceNetworks' in apc_rule:
        returned_obj[4] = rule_obj_extractor(apc_rule['sourceNetworks'])
    if 'destinationZones' in apc_rule:
        returned_obj[5] = rule_obj_extractor(apc_rule['destinationZones'])
    if 'destinationNetworks' in apc_rule:
        returned_obj[6] = rule_obj_extractor(apc_rule['destinationNetworks'])
    # print(returned_obj)
    return returned_obj

def rule_obj_extractor(obj2extract):
    returned_obj = ''
    if 'objects' in obj2extract:
        for single_obj in obj2extract['objects']:
            returned_obj += single_obj['name'] + '\n'
    return returned_obj

apc_json_file = open('json_examples/example_acp_rules.json', 'r')
apc_rules = json.load(apc_json_file)
# print(json.dumps(apc_rules['items'][0]['sourceZones']['objects'], indent =4))
fmc_apcrules_list(apc_rules['items'])



apc_json_file.close()
import json
from rich import print
import xlsxwriter
import time
from datetime import datetime


## Definicion de variables Globales


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

## Lectura de JSON

with open('response_1623453929495.json') as json_file:
    data = json.load(json_file)

### Interación de cada uno de los ACL en el Policy
i = 1
for item in data["items"]:
    destPort_lst = [] ## Definicion Local variable per each rule
    users_lst = [] ## Definicion Local variable per each rule
    src_net_lst = [] ## Definicion Local variable per each rule
    dst_net_lst = [] ## Definicion Local variable per each rule
    apps_lst = [] ## Definicion Local variable per each rule
    cat_rsk_sch_lst = [] ## Definicion Local variable per each rule
    comments_lst = [] ## Definicion Local variable per each rule

    print("\n")
    print(f"++ ACL {i}. "+ item["name"] + " | Enabled: " + str(item["enabled"]))
    worksheet.write('A' + str(row_index), i, cell_format)
    worksheet.write('B' + str(row_index), item["name"], cell_format)
    worksheet.write('C' + str(row_index), item["enabled"], cell_format)

    if item["action"] == "ALLOW":        
        print("    -- Action: [bold green]" + item["action"] + "[/]")
        worksheet.write('D' + str(row_index), item["action"], cell_format)
    else:
        print("    -- Action: [bold red]" + item["action"] + "[/]")
        worksheet.write('D' + str(row_index), item["action"], cell_format)
    i += 1
    ### Determinar la ZONE de Origen

    if "sourceZones" in item:
        for inzone in item["sourceZones"]["objects"]:
            print("   Zona de Origen: " + inzone["name"])
            worksheet.write('E' + str(row_index), inzone["name"], cell_format)
    else:
        print("   Zona de Origen: ANY")
        worksheet.write('E' + str(row_index), "Any", cell_format)

    ### Determinar la RED de Origen

    if "sourceNetworks" in item:
        if "objects" in item["sourceNetworks"]:
            for src_net in item["sourceNetworks"]["objects"]:
                print("   Redes de Origen: object: " + src_net["name"])
                src_net_lst.append(str(src_net["name"]))
        elif "literals" in item["sourceNetworks"]:
            for src_net in item["sourceNetworks"]["literals"]:
                print("   Redes de Origen: literals: " + src_net["type"] + " " + src_net["value"])
                src_net_lst.append(str(src_net["type"]) + ": " + str(src_net["value"]))
        else:
            print("   Redes de Origen: ANY")
            src_net_lst.append("Any")
    else:
        print("   Redes de Origen: ANY")
        src_net_lst.append("Any")
    worksheet.write('F' + str(row_index), '\n'.join(src_net_lst), cell_format)

    ### Determinar la ZONE de Destino

    if "destinationZones" in item:
        for outzone in item["destinationZones"]["objects"]:
            print("   [bold magenta]Zona de Destino: [/]" + outzone["name"])
            worksheet.write('G' + str(row_index), outzone["name"], cell_format)
    else:
        print("   [bold magenta]Zona de Destino:[/] ANY")
        worksheet.write('G' + str(row_index), "Any", cell_format)

    ### Determinar la RED de Destino

    if "destinationNetworks" in item:
        if "objects" in item["destinationNetworks"]:
            for dst_net in item["destinationNetworks"]["objects"]:
                print("   Redes de Destino: " + dst_net["name"])
                dst_net_lst.append(str(dst_net["name"]))
        elif "literals" in item["destinationNetworks"]:
            for dst_net in item["destinationNetworks"]["literals"]:
                print("   Redes de Destino: literal: " + dst_net["type"] + "/" + dst_net["value"])
                dst_net_lst.append(str(dst_net["type"]) + "/" + str(dst_net["value"]))
    else:
        print("   Redes de Destino: ANY")
        dst_net_lst.append("Any")
    worksheet.write('H' + str(row_index), '\n'.join(dst_net_lst), cell_format)

    ### Determinar los puertos de Destino

    if "destinationPorts" in item:
        if "objects" in item["destinationPorts"]:
            for dst_ports in item["destinationPorts"]["objects"]:
                print("   Puertos de Destino: Object: " + dst_ports["name"])
                destPort_lst.append("object:" + str(dst_ports["name"]))
        elif "literals" in item["destinationPorts"]:
            for dst_ports in item["destinationPorts"]["literals"]:
                if "icmpType" in dst_ports:
                    print("   Puertos definidos literales: ICMP Type:" + str(dst_ports["icmpType"]) + "/PROTO(" + str(dst_ports["protocol"]) + ")")
                    destPort_lst.append("literal: ICMP:" + str(dst_ports["icmpType"]) + "/PROTO(" + str(dst_ports["protocol"]) + ")")
                else:
                    print("   Puertos definidos literales: " + str(dst_ports["port"] if "port" in dst_ports else "") + " PROTO(" + str(dst_ports["protocol"]) + ")")
                    destPort_lst.append("literal:" + str(dst_ports["port"] if "port" in dst_ports else "") + "/PROTO(" + str(dst_ports["protocol"]) + ")")
        else:
            print("   Puertos de Destino: ANY")
            destPort_lst.append("Any")    
    else:
        print("   Puertos de Destino: ANY")
        destPort_lst.append("Any")
    worksheet.write('I' + str(row_index), '\n'.join(destPort_lst), cell_format)
    
    
    ### Determinar los usuarios permitidos

    if "users" in item:
        for user in item["users"]["objects"]:
            print("   Usuario permitido: " + user["name"])
            users_lst.append(str(user["name"]))
    else:
        print("   Usuario permitido: ANY")
        users_lst.append("Any")
    worksheet.write('J' + str(row_index), '\n'.join(users_lst), cell_format)

    if "applications" in item:
        
        ### Determinar listado de aplicaciones (objetos)

        if "applications" in item["applications"]:
            for app_index in range(len(item["applications"]["applications"])):
                print("   Lista de Apps: " + item["applications"]["applications"][app_index]["name"])
                apps_lst.append(str(item["applications"]["applications"][app_index]["name"]))
        else:
            print("   Lista de Apps: ANY")
            apps_lst.append("Any")
        worksheet.write('K' + str(row_index), '\n'.join(apps_lst), cell_format)

        ### Determinar listado de aplicaciones Filtros y Riesgos

        if "inlineApplicationFilters" in item["applications"]:
            for app_index in range(len(item["applications"]["inlineApplicationFilters"])):
                
                ### Destinado para filtrar categorias de apps

                if "categories" in item["applications"]["inlineApplicationFilters"][app_index]:
                    for cat_index in range(len(item["applications"]["inlineApplicationFilters"][app_index]["categories"])):
                        print("    Lista de Categorías de Apps: " + item["applications"]["inlineApplicationFilters"][app_index]["categories"][cat_index]["name"])
                        cat_rsk_sch_lst.append("categories: " + str(item["applications"]["inlineApplicationFilters"][app_index]["categories"][cat_index]["name"]))
                ### Destinado para filtrar riesgos

                elif "risks" in item["applications"]["inlineApplicationFilters"][app_index]:
                    for risk_index in range(len(item["applications"]["inlineApplicationFilters"][app_index]["risks"])):
                        print("    Lista de Riesgos de Apps: " + item["applications"]["inlineApplicationFilters"][app_index]["risks"][risk_index]["name"])
                        cat_rsk_sch_lst.append("risks: " + str(item["applications"]["inlineApplicationFilters"][app_index]["risks"][risk_index]["name"]))
                ### Destinado para filtrar busquedas

                elif "search" in item["applications"]["inlineApplicationFilters"][app_index]:
                    for search_index in range(len(item["applications"]["inlineApplicationFilters"][app_index])):
                        print("    Listado de Busqueda de Apps: " + item["applications"]["inlineApplicationFilters"][app_index]["search"])
                        cat_rsk_sch_lst.append("search: " + str(item["applications"]["inlineApplicationFilters"][app_index]["search"]))
        else:
            print("   Lista de Apps (Riesgo / Filtros / Search): ANY")
            cat_rsk_sch_lst.append("Any")
        worksheet.write('L' + str(row_index), '\n'.join(cat_rsk_sch_lst), cell_format)
    else:
        print("   Lista de Apps: ANY")
        worksheet.write('K' + str(row_index), "Any", cell_format)
        print("   Lista de Apps (Riesgo / Filtros / Search): ANY")
        worksheet.write('L' + str(row_index), "Any", cell_format)

    ## Listar los comentarios

    if "commentHistoryList" in item:
        for comment_id in range(len(item["commentHistoryList"])):
            print("   Comentarios: " + item["commentHistoryList"][comment_id]["comment"] + " / Usuario: " + item["commentHistoryList"][comment_id]["user"]["name"])
            comments_lst.append(str(item["commentHistoryList"][comment_id]["comment"]) + " / User: " + item["commentHistoryList"][comment_id]["user"]["name"])
    else:
        print("   Comentario: None")
        comments_lst.append("Any")
    worksheet.write('M' + str(row_index), '\n'.join(comments_lst), cell_format)
    row_index += 1
workbook.close()

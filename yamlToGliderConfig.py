# -*- coding: utf-8 -*-
import re

subiplc=[]
subHK=[]
subusually=[]

def data_re_yaml(string: str):
    for line in string.split('\n'):
        pattern_server = r'server: ([^,]*),?|server":"([^,]*)",?'
        pattern_port = r'port: ([^,]*),?|port":([^,]*),?'
        pattern_type = r'type: ([^,]*),?|type":"([^,]*)",?'
        pattern_cipher = r'cipher: ([^,]*),?|cipher":"([^,]*)",?'
        pattern_uuid = r'uuid: ([^,]*),?|uuid":"([^,]*)",?'
        pattern_alterId = r'alterId: ([^,]*),?|alterId":([^,]*),?'
        pattern_password = r'password: ([^,]*),?|password":"([^,]*)",?'
        pattern_protocol = r'protocol: ([^,]*),?|protocol":"([^,]*)",?'
        pattern_obfs = r'obfs: ([^,]*),?|obfs":"([^,]*)",?'
        pattern_protocol_param = r'protocol-param: ([^,]*),?|protocol-param":"([^,]*)",?'
        pattern_obfs_param = r'obfs-param: ([^,]*),?|obfs-param":"([^,]*)",?'
        pattern_sni = r'sni: ([^,]*),?|sni":"([^,]*)",?'
        pattern_path = r'ws-opts: {path: ([^,]*),?'
        pattern_host = r'{Host: ([^,]*)}},?'
        pattern_name = r'name: ([^,]*),?'

        Name = re.search(pattern_name, line)
        type = re.search(pattern_type, line)
        host = re.search(pattern_server, line)
        port = re.search(pattern_port, line)
        uuid = re.search(pattern_uuid, line)
        alterId = re.search(pattern_alterId, line)
        method = re.search(pattern_cipher, line)
        Pass = re.search(pattern_password, line)
        protocol = re.search(pattern_protocol, line)
        protocol_param = re.search(pattern_protocol_param, line)
        obfs = re.search(pattern_obfs, line)
        obfs_param = re.search(pattern_obfs_param, line)
        serverName = re.search(pattern_sni, line)
        path = re.search(pattern_path, line)
        host_ws = re.search(pattern_host, line)

        try:
            if type is not None and path is None:


                if no_gfw(Name.group(1)):
                    if type.group(1) == 'vmess':
                        subiplc.append(vmess_re_yaml(alterId.group(1), method.group(1), uuid.group(1), host.group(1), port.group(1)))
                    if type.group(1) == 'ssr':
                        subiplc.append(ssr_re_yaml(method.group(1), Pass.group(1), host.group(1), port.group(1), protocol.group(1), protocol_param.group(1), obfs.group(1), obfs_param.group(1)))
                    if type.group(1) == 'ss':
                        subiplc.append(ss_re_yaml(method.group(1), Pass.group(1), host.group(1), port.group(1)))
                    if type.group(1) == 'trojan':
                        subiplc.append(trojan_re_yaml(Pass.group(1), host.group(1), port.group(1), serverName.group(1)))
                if hongKong(Name.group(1)):
                    if type.group(1) == 'vmess':
                        subHK.append(vmess_re_yaml(alterId.group(1), method.group(1), uuid.group(1), host.group(1), port.group(1)))
                    if type.group(1) == 'ssr':
                        subHK.append(ssr_re_yaml(method.group(1), Pass.group(1), host.group(1), port.group(1), protocol.group(1), protocol_param.group(1), obfs.group(1), obfs_param.group(1)))
                    if type.group(1) == 'ss':
                        subHK.append(ss_re_yaml(method.group(1), Pass.group(1), host.group(1), port.group(1)))
                    if type.group(1) == 'trojan':
                        subHK.append(trojan_re_yaml(Pass.group(1), host.group(1), port.group(1), serverName.group(1)))
                else:
                    if type.group(1) == 'vmess':
                        subusually.append(vmess_re_yaml(alterId.group(1), method.group(1), uuid.group(1), host.group(1), port.group(1)))
                    if type.group(1) == 'ssr':
                        subusually.append(ssr_re_yaml(method.group(1), Pass.group(1), host.group(1), port.group(1), protocol.group(1), protocol_param.group(1), obfs.group(1), obfs_param.group(1)))
                    if type.group(1) == 'ss':
                        subusually.append(ss_re_yaml(method.group(1), Pass.group(1), host.group(1), port.group(1)))
                    if type.group(1) == 'trojan':
                        subusually.append(trojan_re_yaml(Pass.group(1), host.group(1), port.group(1), serverName.group(1)))
        except:
            pass



def no_gfw(name: str) -> bool:
    pattern_iplc = r'IPLC|iplc|IEPL|iepl'
    iplc_bool = re.search(pattern_iplc, name)
    if iplc_bool is not None:
        return True
    else:
        return False

def hongKong(name: str) -> bool:
    pattern_kong = r'港|kong|Kong|KONG'
    iplc_bool = re.search(pattern_kong, name)
    if iplc_bool is not None:
        return True
    else:
        return False

def vmess_re_yaml(alterId: str, method: str, uuid: str, host: str, port: str) -> str:
    # VMess scheme:
    # vmess: // [security:]uuid @ host: port[?alterID = num]
    # if alterID=0 or not set, VMessAEAD will be enabled
    if alterId == '0' and method == 'auto':
        return f"forward=vmess://{uuid}@{host}:{port}"
    elif alterId != '0' and method == 'auto':
        return f"forward=vmess://{uuid}@{host}:{port}?alterId={alterId}"
    elif alterId == '0' and method != 'auto':
        return f"forward=vmess://{method}:{uuid}@{host}:{port}"
    else:
        return f"forward=vmess://{method}:{uuid}@{host}:{port}?alterId={alterId}"


def ssr_re_yaml(method: str, Pass: str, host: str, port: str, protocol: str, protocol_param: str, obfs: str,
                obfs_param: str) -> str:
    # ssr://method:pass@host:port?protocol=xxx&protocol_param=yyy&obfs=zzz&obfs_param=xyz
    # forward=ssr://method:pass@1.1.1.1:8443?protocol=auth_aes128_md5&protocol_param=xxx&obfs=tls1.2_ticket_auth&obfs_param=yyy
    return f"forward=ssr://{method}:{Pass}@{host}:{port}?protocol={protocol}&protocol_param={protocol_param}&obfs={obfs}&obfs_param={obfs_param}"


def trojan_re_yaml(Pass: str, host: str, port: str, serverName: str) -> str:
    ##  trojan://pass@host:port[?serverName=SERVERNAME][&skipVerify=true][&cert=PATH]
    return f"forward=trojan://{Pass}@{host}:{port}?serverName={serverName}&skipVerify=true"


def ss_re_yaml(method: str, Pass: str, host: str, port: str) -> str:
    #  ss://method:pass@host:port
    return f"forward=ss://{method}:{Pass}@{host}:{port}"


# 未解决
def ws_re_yaml(uuid: str, server: str, port: str, host: str) -> str:
    return f"forward=ws://{uuid}@{server}:{port}{path}?host={host}"


def read_input_data_from_file(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8') as file:
        input_data = file.read()
    return input_data


def write_output_data_to_file(fwd: str='./out/forward.txt', iplc: str = './out/iplc.txt', HK: str = './out/HK.txt') -> None:
    with open(fwd, 'a') as file:
        for item in subusually:
            file.write(item + '\n')
    with open(iplc, 'a') as file:
        for item in subiplc:
            file.write(item + '\n')
    with open(HK, 'a') as file:
        for item in subHK:
            file.write(item + '\n')    

def data_out_print():
    print('普通forward地址')
    for line in subusually:
        print(line)
    print('\n\niplc或iepl地址')
    for line in subiplc:
        print(line)

if __name__ == "__main__":
    path = '0616_sub.txt'   # 修改读取文件地址
    # data = [{"name":"🇭🇰 香港 | V2 | 01","type":"vmess","server":"in.hceok.com","port":37109,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V2 | 02","type":"vmess","server":"var.heataek.com","port":37110,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 01","type":"vmess","server":"in.hceok.com","port":11101,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 02","type":"vmess","server":"var.heataek.com","port":11102,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 03","type":"vmess","server":"to.hceok.com","port":11106,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 04","type":"vmess","server":"qui.heataek.com","port":2103,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 05","type":"vmess","server":"in.hceok.com","port":11802,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 06","type":"vmess","server":"qui.heataek.com","port":11105,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇭🇰 香港 | V1 | 直连","type":"vmess","server":"line.acetace.com","port":39589,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇨🇳 台湾 | V2 | 01","type":"vmess","server":"one.jcocp.com","port":37402,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇨🇳 台湾 | V2 | 02","type":"vmess","server":"two.jcocp.com","port":31202,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇨🇳 台湾 | V1 | 01","type":"vmess","server":"two.jcocp.com","port":32602,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇨🇳 台湾 | V1 | 02","type":"vmess","server":"one.jcocp.com","port":31093,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇨🇳 台湾 | V1 | 03","type":"vmess","server":"one.jcocp.com","port":37121,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本 | V2 | 01","type":"vmess","server":"one.jcocp.com","port":37308,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本| V2 | 02","type":"vmess","server":"one.jcocp.com","port":37112,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本 | V1 | 01","type":"vmess","server":"two.jcocp.com","port":11034,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本 | V1 | 02","type":"vmess","server":"two.jcocp.com","port":2301,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本 | V1 | 03","type":"vmess","server":"two.jcocp.com","port":3301,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本 | V1 | 04","type":"vmess","server":"one.jcocp.com","port":1031,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 日本 | V1 | 05","type":"vmess","server":"one.jcocp.com","port":1032,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 新加坡 | V2 | 01","type":"vmess","server":"ovo.swvwg.com","port":33207,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 新加坡 | V2 | 02","type":"vmess","server":"ovo.swvwg.com","port":37113,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 新加坡 | V1 | 01","type":"vmess","server":"xyz.swvwg.com","port":11209,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 新加坡 | V1 | 02","type":"vmess","server":"xyz.swvwg.com","port":11206,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 新加坡 | V1 | 03","type":"vmess","server":"xyz.swvwg.com","port":2201,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 新加坡 | V1 | 04","type":"vmess","server":"xyz.swvwg.com","port":3201,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇺🇲 美国 | V1 | 01","type":"vmess","server":"bcr.ueves.com","port":11503,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇺🇲 美国 | V1 | 02","type":"vmess","server":"bcr.ueves.com","port":11502,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇺🇲 美国 | V1 | 03","type":"vmess","server":"aev.ueves.com","port":2501,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇺🇲 美国 | V1 | 04","type":"vmess","server":"aev.ueves.com","port":11501,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇰🇷 韩国 | V1 | 01","type":"vmess","server":"co.oyvyt.com","port":11401,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇰🇷 韩国 | V1 | 02","type":"vmess","server":"bg.oyvyt.com","port":1402,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇷🇺 俄罗斯 | V1 | 01","type":"vmess","server":"co.oyvyt.com","port":51908,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇵🇭 菲律宾 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":11907,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇮🇳 印度 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":11901,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇹🇭 泰国 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":11906,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇬🇧 英国 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":11903,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇩🇪 德国 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":51909,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇨🇦 加拿大 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":48312,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇦🇺 澳大利亚 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":37111,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇵🇰 巴基斯坦 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":37115,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇹🇷 土耳其 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":11905,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇦🇷 阿根廷 | V1 | 01","type":"vmess","server":"bg.oyvyt.com","port":11904,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 试用 | 新加坡 | 01 | 限 20 Mbs","type":"vmess","server":"bcr.ueves.com","port":10001,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇸🇬 试用 | 新加坡 | 02 | 限 20 Mbs","type":"vmess","server":"bcr.ueves.com","port":10004,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 试用 | 日本 | 01 | 限 20 Mbs","type":"vmess","server":"bcr.ueves.com","port":10002,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"},{"name":"🇯🇵 试用 | 日本 | 02 | 限 20 Mbs","type":"vmess","server":"bcr.ueves.com","port":10003,"uuid":"f2998c53-50f0-3ad6-8d60-d1807e826970","alterId":0,"cipher":"auto","udp":"true"}]
    data1 = read_input_data_from_file(path)
    # json_str = json_data(data1)
    # vmess_json_yaml(json_str)
    data_re_yaml(data1)
    print('筛选完成')
    print(f'普通forward地址共有：{len(subusually)}')
    print(f'iplc和iepl地址共有：{len(subiplc)}')
    print(f'香港地址共有：{len(subHK)}')    
    print('开始写入文件,位于当前文件下out文件夹中')
    write_output_data_to_file()
    print('写入成功')


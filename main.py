import socket
import socks
import threading
import queue
import time
import logging
import yaml
import os


connect_cont = {"client_cont": 0, "server_vpn_cont": 0, 'server_con_cont': 0}
# 日志格式
log_format = "%(asctime)s - %(levelname)s - %(message)s"
log_format ='[%(asctime)s.%(msecs)03d] %(filename)s -> %(funcName)s line:%(lineno)d [%(levelname)s] : %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)


# 域名路由表
# {'baidu.com': [["con", 1523432343], ["vpn", 1523423343]]}
domain_route = {}
domain_fust = [
    "al", "dz", "af", "ar", "ae", "aw", "om", "az", "eg", "et", "ie", "ee", "ad", "ao", "ai", "ag", "at", "au", "mo", "bb", 
    "pg", "bs", "pk", "py", "ps", "bh", "pa", "br", "by", "bm", "bg", "mp", "bj", "be", "is", "pr", "ba", "pl", "bo", "bz", 
    "bw", "bt", "bf", "bi", "bv", "kp", "gq", "dk", "de", "tg", "dm", "do", "ru", "ec", "er", "fr", "fo", "pf", "gf", "tf", 
    "va", "ph", "fj", "fi", "cv", "fk", "gm", "cg", "cd", "co", "cr", "gg", "gd", "gl", "ge", "cu", "gp", "gu", "gy", "kz", 
    "ht", "kr", "nl", "an", "hm", "hn", "ki", "dj", "kg", "gn", "gw", "ca", "gh", "ga", "kh", "cz", "zw", "cm", "qa", "ky", 
    "km", "ci", "kw", "cc", "hr", "ke", "ck", "lv", "ls", "la", "lb", "lt", "lr", "ly", "li", "re", "lu", "rw", "ro", "mg", 
    "im", "mv", "mt", "mw", "my", "ml", "mk", "mh", "mq", "yt", "mu", "mr", "us", "um", "as", "vi", "mn", "ms", "bd", "pe", 
    "fm", "mm", "md", "ma", "mc", "mz", "mx", "nr", "np", "ni", "ne", "ng", "nu", "no", "nf", "na", "za", "aq", "gs", "eu", 
    "pw", "pn", "pt", "jp", "se", "ch", "sv", "ws", "yu", "sl", "sn", "cy", "sc", "sa", "cx", "st", "sh", "kn", "lc", "sm", 
    "pm", "vc", "lk", "sk", "si", "sj", "sz", "sd", "sr", "sb", "so", "tj", "tw", "th", "tz", "to", "tc", "tt", "tn", "tv", 
    "tr", "tm", "tk", "wf", "vu", "gt", "ve", "bn", "ug", "ua", "uy", "uz", "es", "eh", "gr", "hk", "sg", "nc", "nz", "hu", 
    "sy", "jm", "am", "ac", "ye", "iq", "ir", "il", "it", "in", "id", "uk", "vg", "io", "jo", "vn", "zm", "je", "td", "gi", 
    "cl", "cf", "cn", "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "as", "at", "au", "aw", "az", 
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", 
    "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cx", "cy", "cz", "de", "dj", "dk", 
    "dm", "do", "dz", "ec", "ee", "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gd", "ge", 
    "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", 
    "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", 
    "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", 
    "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", 
    "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", 
    "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", 
    "sl", "sm", "sn", "so", "sr", "st", "sv", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", 
    "tp", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "um", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", 
    "wf", "ws", "ye", "yt", "yu", "yr", "za", "zm", "zw", "com", "edu", "gov", "int", "mil", "net", "org", "biz", "info", 
    "pro", "name", "museum", "coop", "aero", "xxx", "idv"
]

def parse_domain(addr:str):
    # 将域名解析为短域名
    if addrtype == 0x03: # domain address
        addr_list = addr.split('.')
        addr_list.reverse()
        
        addr = ''
        for i in addr_list:
            addr = i + '.' + addr
            if i not in domain_fust:
                addr = addr.strip('.')
                break
    return addr


def action_route(addr: str, src:str='none'):
    # 处理路由表，当src='none'时，仅查询路由，否则应该为vpn/con, 用于记录路由
    t = time.time()
    addr = parse_domain(addr)
    
    # 查询路由信息
    if src == 'none':
        try:
            if addr in domain_route and len(domain_route[addr]) == 2:
                tm_x = time.time() - domain_route[addr][1][1]
                if tm_x < route_timeout:
                    if domain_route[addr][0][0] == domain_route[addr][1][0]:
                        route_select = domain_route[addr][1][0]
                        if debug == True:
                            logging.info("%s: 路由：根据路由表指示: %s" % (addr, route_select))
                        return route_select
                    else:
                        # 两条路由不一致，认为左右横跳，只要两条路由均未超时，让其走直连
                        tm_x = time.time() - domain_route[addr][0][1]
                        if tm_x < route_timeout:
                            if debug == True:
                                logging.info("%s: 路由：两条路由不一致，重新竞争" % addr)
                            return 'none'
            else:
                # addr在路由表中，而且一条记录
                if domain_route[addr][0][1] == 0:
                    if debug == True:
                        logging.info("%s: 根据配置文件路由：%s" % (addr, domain_route[addr][0][0]))
                    return domain_route[addr][0][0]

            return 'none'
        except:
            return 'none'

    # 打印路由竞争结果
    if debug == True:
        logging.info("%s: 路由：本次路由选择: %s" % (addr, src))

    # 写入路由信息
    try:
        if addr in domain_route and len(domain_route[addr]) == 1:
            # 路由表中有且只有一个关于此addr的记录时，执行追加操作
            domain_route[addr].append([src, t])
            if debug == True:
                logging.info("%s: 已提交到路由表" % addr)

        elif len(domain_route[addr]) == 2:
            if domain_route[addr][0][0] != domain_route[addr][1][0]:
                tm1 = t - domain_route[addr][0][1]
                tm2 = t - domain_route[addr][1][1]
                if tm1 < route_timeout and tm2 < route_timeout:
                    domain_route[addr] = [[src, t], [src, t]]
                    if debug == True:
                        logging.info("%s: 已提交到路由表" % addr)
                    return
                
            domain_route[addr] = []
            domain_route[addr].append([src, t])

        else:
            domain_route[addr] = []
            domain_route[addr].append([src, t])
    except:
        domain_route[addr] = []
        domain_route[addr].append([src, t])



def vpn_sync(client_socket, vpn_client_buff, addr, port, server_con_status, client_status_close, competing):
    try:
        cmt = competing[0]
    except:
        cmt = 'cmt'

    if  cmt != 'dont_competing':
        # 如果直连直在lagtime内返回失败，则直接连接vpn
        # 否则等待lagtime结束（lattime，建立直连后等待多长时间建立vpn）
        old_time = time.time()
        try:
            lag_scs = lag_time_buff.get(timeout=lag_time)
        except:
            lag_scs = False

        if lag_scs == True:
            free_time = lag_time - (time.time() - old_time)
            try:
                time.sleep(free_time)
            except:
                pass
            
        # 检查直连是否获得守帧数据
        if 'con' in competing:
            if debug == True:
                logging.info('%s: 直连建立完成，不建立 vpn链路！' % addr)
            return 

        if debug == True:
            logging.info('%s: vpn链路延迟创建%s秒' % (addr, str(time.time()-old_time)))
    
    
    # 建立与目标服务器的连接
    try:
        # 通过socks5代理访问目标服务器（由于增加了一层代理，原本需要从server_socket读取的数据
        # 现在需要从server_proxy_socket中读取）
        server_proxy_socket = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        server_proxy_socket.set_proxy(socks.SOCKS5, proxy_addr, proxy_port)
        server_proxy_socket.connect((addr, port))
        server_con_status.put(True)
    except:
        server_con_status.put(False)
        try:
            server_proxy_socket.close()
        except:
            pass
        if debug == True:
            logging.error('%s: 直连：服务器连接失败' % addr)
            connect_cont['server_vpn_cont'] = connect_cont['server_vpn_cont'] - 1
        return
    

    # 进行转发数据
    # 客户端数据发送到服务器proxy socket
    def read_client_buff():
        while True:
            data = vpn_client_buff.get()
            if client_status_close[0] == True or now_exit == True:
                # 如果客户端关闭了连接，终止与服务器的连接
                server_proxy_socket.close()
                break

            try:
                server_proxy_socket.sendall(data)
            except:
                # 服务器数据发送异常，关闭连接
                try:
                    server_proxy_socket.close()
                except:
                    pass
                return

    now_exit = False  
    t = threading.Thread(target=read_client_buff)
    t.start()

    # 服务器数据发送到客户端
    while True:
        try:
            data = server_proxy_socket.recv(524288)
        except:
            data = bytes()

        # 服务端关闭了连接
        if not data:
            # 释放客户端读取等待锁
            now_exit = True
            vpn_client_buff.put('close')
            break

        # 如果客户端关闭了连接，终止与服务器的连接
        if client_status_close[0] == True:
            server_proxy_socket.close()
            break

        # 双路选择竞争
        if len(competing) == 0:
            competing.append('vpn')
            action_route(addr, 'vpn')
        else:
            if competing[0] != "vpn" and competing[0] != 'dont_competing':
                # 释放客户端读取等待锁，更新连接状态为断开
                now_exit = True
                vpn_client_buff.put('close')
                break
        
        try:
            client_socket.sendall(data)
        except:
            # 释放客户端读取等待锁，更新连接状态为断开
            now_exit = True
            vpn_client_buff.put('close')
            break


    # 关闭服务器连接
    t.join()
    if debug == True:
        logging.info('%s: 代理：关闭服务器连接' % addr)
        connect_cont['server_vpn_cont'] = connect_cont['server_vpn_cont'] - 1
    server_proxy_socket.close()


def con_sync(client_socket, con_client_buff, addr, port, server_con_status, client_status_close, competing):
    # 建立与目标服务器的连接
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((addr, port))
        server_con_status.put(True)
        lag_time_buff.put(True)
    except:
        server_con_status.put(False)
        lag_time_buff.put(False)
        try:
            server_socket.close()
        except:
            pass
        if debug == True:
            logging.error('%s: 直连：服务器连接失败' % addr)
            connect_cont['server_con_cont'] = connect_cont['server_con_cont'] - 1
        return

    # 进行转发数据
    # 客户端数据发送到服务器proxy socket
    def read_client_buff():
        while True:
            data = con_client_buff.get()
            
            if client_status_close[0] == True or now_exit == True:
                # 如果客户端关闭了连接，终止与服务器的连接
                server_socket.close()
                break

            try:
                server_socket.sendall(data)
            except:
                # 服务器数据发送异常，关闭连接
                try:
                    server_socket.close()
                except:
                    pass
                return

    now_exit = False 
    t = threading.Thread(target=read_client_buff)
    t.start()

    # 服务器数据发送到客户端
    while True:
        try:
            data = server_socket.recv(524288)
        except:
            data = bytes()

        # 服务端关闭了连接
        if not data:
            # 释放客户端读取等待锁，更新连接状态为断开
            now_exit = True
            con_client_buff.put('close')
            break

        # 如果客户端关闭了连接，终止与服务器的连接
        if client_status_close[0] == True:
            server_socket.close()
            break

        # 双路选择竞争
        if len(competing) == 0:
            competing.append('con')
            action_route(addr, 'con')
        else:
            if competing[0] != "con" and competing[0] != 'dont_competing':
                # 释放客户端读取等待锁，更新连接状态为断开
                now_exit = True
                con_client_buff.put('close')
                break
        
        try:
            client_socket.sendall(data)
        except:
            # 释放客户端读取等待锁，更新连接状态为断开
            now_exit = True
            con_client_buff.put('close')
            break

    # 关闭服务器连接
    t.join()

    if debug == True:
        logging.info('%s: 直连：关闭服务器连接' % addr)
        connect_cont['server_con_cont'] = connect_cont['server_con_cont'] - 1
    server_socket.close()

# # 广告屏蔽函数
# def parse_adguard_rules(filename):
#     rules = []
#     buff = {}
#     with open(filename, 'r') as f:
#         for line in f:
#             line = line.strip()
#             # Ignore comments
#             if line.startswith('!'):
#                 continue
#             # Handle exception rules
#             if line.startswith('@@'):
#                 line = line[2:]
#                 exception = True
#             else:
#                 exception = False
#             # Handle domain prefix rules
#             if line.startswith('||'):
#                 domain = line[2:].strip('^')
#                 domain = '^' + domain
#             # Handle domain suffix rules
#             elif line.startswith('|'):
#                 domain = line[1:].strip('^')
#                 domain = domain + '$'
#             elif line.startswith('@@||'):
#                 domain = line[4:].strip('^')
#                 domain = '^' + domain
#             elif line.startswith('@@|'):
#                 domain = line[3:].strip('^')
#                 domain = domain + '$'

#             domain = domain.replace('.', '\.').replace('*', '.*')
#             rules.append({"pattern": re.compile(domain), "exception": exception})           
#     return rules

# buff = {}
# def is_domain_blocked(domain):
#     data = buff.get(domain)
#     if data:
#         return data
    
#     for ru in ad_rules:
#         exception = ru['exception']
#         pattern = ru['pattern']
#         if exception:
#             continue
#         if pattern.match(domain):
#             buff[domain] = True
#             return True
        
#     buff[domain] = False
#     return False


# 建立客户端sockes连接
def handle_client(client_socket):
    global addrtype
    
    # 接收客户端请求
    request = client_socket.recv(4096)
    if not request:
        client_socket.close()
        return

    # 处理socks5协议请求
    version = request[0]
    if version != 0x05:
        client_socket.close()
        return

    num_methods = request[1]
    methods = request[2:2+num_methods]
    if 0x00 not in methods:
        client_socket.close()
        return

    client_socket.send(b"\x05\x00")

    # 接收客户端请求细节
    request = client_socket.recv(4096)
    if not request:
        client_socket.close()
        return

    version = request[0]
    if version != 0x05:
        client_socket.close()
        return

    cmd = request[1]
    if cmd != 0x01:
        client_socket.close()
        return

    addrtype = request[3]
    if addrtype == 0x01: # IPv4 address
        addr = socket.inet_ntoa(request[4:8])
        port = int.from_bytes(request[8:10], byteorder='big')

    elif addrtype == 0x03: # Domain name
        length = request[4]
        addr = request[5:5+length].decode()
        port = int.from_bytes(request[5+length:7+length], byteorder='big')

    elif addrtype == 0x04:  # IPv6 address
        addr = socket.inet_ntop(socket.AF_INET6, request[4:20])
        port = int.from_bytes(request[20:22], byteorder='big')

    else:
        client_socket.close()
        return
    
    # 如果目标在禁止的list中，关闭连接
    if addr in reject_list:
        if debug == True:
            logging.warning('%s: url禁止连接' % addr)
        client_socket.close()
        return 

    
    # 数据自动分流
    threads = []
    competing = []
    client_status_close = [False]
    server_con_status = queue.Queue()   # 两个异步线程与服务器建立连接状态
    vpn_client_buff = queue.Queue()     # 客户端数据分两份写队列，给两个线程
    con_client_buff = queue.Queue()     # 客户端数据分两份写队列，给两个线程
    if debug == True:
        connect_cont['client_cont'] = connect_cont['client_cont'] + 1
        print("\n当前连接数：", connect_cont)
        print('当前路由表：', domain_route)
        logging.info('%s: 建立连接'% addr)
        
    # 路由选择, 如果competing中存在dont_competing则不竞争
    route_jg = action_route(addr)
    if route_jg != 'none':
        competing.append('dont_competing')

    # 直连线程
    if route_jg == 'con' or route_jg == 'none':
        if debug == True:
            connect_cont['server_con_cont'] = connect_cont['server_con_cont'] + 1

        t = threading.Thread(target=con_sync, args=(client_socket, con_client_buff, addr, port, server_con_status, client_status_close, competing))
        threads.append(t)
        t.start()

    # vpn线程
    if route_jg == 'vpn' or route_jg == 'none':
        if debug == True:
            connect_cont['server_vpn_cont'] = connect_cont['server_vpn_cont'] + 1

        t = threading.Thread(target=vpn_sync, args=(client_socket, vpn_client_buff, addr, port, server_con_status, client_status_close, competing))
        threads.append(t)
        t.start()
    

    # 判断是否有至少一个线程成功连接到目标服务器
    scs_x = 0
    while True:
        try:
            scs = server_con_status.get(timeout=60)
        except:
            scs = False

        if scs == True:
            reply = b"\x05\x00\x00\x01"
            reply += socket.inet_aton(lisent_addr) + lisent_port.to_bytes(2, byteorder='big')
            client_socket.send(reply)
            break

        if scs == False:
            scs_x = scs_x + 1

            # 如果路由表存在addr，且连接失败，注销路由条目
            if route_jg != 'none':
                scs_x = 2
                mini_addr = parse_domain(addr)
                # 如果不是用户手动指定的路由表，清除路由条目
                if domain_route[mini_addr][0][1] != 0:
                    domain_route.pop(mini_addr)
                    if debug == True:
                        logging.error('%s: 连接失败，从路由表清除' % addr)

            if scs_x == 2:
                # 服务器连接失败
                if debug == True:
                    logging.error('%s: 目标服务器连接失败，放弃' % addr)
                    connect_cont['client_cont'] = connect_cont['client_cont'] - 1

                client_socket.close()
                return 
    
    # 读取客户端数据，写入线程buff
    while True:
        try:
            data = client_socket.recv(4096)
        except:
            data = bytes()

        if not data:
            # 释放客户端读取等待锁，更新连接状态为断开
            client_status_close.clear()
            client_status_close.append(True)
            con_client_buff.put('close')
            vpn_client_buff.put('close')
            break

        con_client_buff.put(data)
        vpn_client_buff.put(data)

    # 等待双线程退出后关闭客户端连接
    for i in threads:
        i.join()

    # 关闭客户端连接
    if debug == True:
        logging.info('%s: 关闭客户端连接' % addr)
        connect_cont['client_cont'] = connect_cont['client_cont'] - 1

    try:
        client_socket.close()
    except:
        pass
    

def start_server():
    # 创建服务器套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((lisent_addr, lisent_port))
    server_socket.listen(128)

    # 监听客户端连接并处理
    while True:
        try:
            client_socket, _ = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
        except:
            pass

if __name__ == "__main__":
    logging.info('正在启动...')
    lag_time_buff = queue.Queue() 

    # 解析配置文件路由
    if os.path.exists('config.yaml') == False:
        config = {
            "lisent_addr": "0.0.0.0",
            "lisent_port": 1081,
            "proxy_addr": "127.0.0.1",
            "proxy_port": 1080,
            "debug": False,
            "route_timeout": 1800,
            "lag_time": 300,
            'reject': [],
            "local": [
                '127.0.0.1', "localhost", '::1', '10.0.0.0',
                '172.16.0.0', '192.168.0.0', '114.114.114.114', 
                '119.29.29.29', '114.114.115.115', 'baidu.com', 'qq.com'
            ], 
            'proxy': ['google.com', 'youtube.com', 'github.com', '8.8.8.8', '8.8.4.4'],
        }
        with open('config.yaml', 'w') as f:
            f.write(yaml.safe_dump(config))

    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f.read())

    # 导入配置
    lisent_addr = config["lisent_addr"]
    lisent_port = config["lisent_port"]
    proxy_addr  = config["proxy_addr"]
    proxy_port = config["proxy_port"]
    debug = config["debug"]
    route_timeout = config["route_timeout"]
    lag_time = config["lag_time"] / 1000

    # 导入静态路由
    for i in config['local']:
        domain_route[i] = [['con', 0]]
    for i in config['proxy']:
        domain_route[i] = [['vpn', 0]]

    # 禁止访问
    reject_list = config['reject']
    # # 导入广告信息
    # if config['reject_mod'] == True:
    #     
        
    #     if os.path.exists(config['reject_file'][0]) == False:
    #         logging.info('从远程加载广告配置文件...')
    #         import requests
    #         r = requests.get(config['reject_file'][1])
    #         respon = r.text
    #         with open(config['reject_file'][0], 'w') as f:
    #             f.write(respon)

    # ad_rules = parse_adguard_rules(config['reject_file'][0])

    logging.info("启动成功！")
    start_server()


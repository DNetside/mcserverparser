import requests, ipaddress, os, socket, re, pystyle
from mcstatus import JavaServer
from pystyle import Colors

# Pystyle colors
lg = Colors.light_green
lr = Colors.light_red
ly = Colors.yellow
lc = Colors.cyan
lm = Colors.pink
lb = Colors.light_blue

# MAIN MENU
print(f"""{lm}
 Developed by DNetside.
 https://discord.gg/EwKJbFQSku
 --------------------------------------
  M C   S E R V E R   P A R S E R   V 1
 --------------------------------------

""")
ipin = input(f'{lb}Input ip/domen to scan (preferably a node)\n---> '+lg)
logver = input(f'{lb}Input version to save ("all" to save all)\n---> '+lg)
resolve = input(f'{lb}Use resolver? y/n\n---> '+lg)

# RESOLVER
if ':' in ipin:
    ipin = ipin.rpartition(':')[0]
if resolve == 'y':
    response = requests.get(url=f'https://api.mcsrvstat.us/3/{ipin}').json()
    data = {'ip': response.get('ip')}
    ipin = f"{data['ip']}"
    print(f'{lc}IP - {ipin}')
else:
    print(f'{lc}Resolver skipped')

ipch = ipin.rpartition('.')[0]+'.0'

# SAVING SYSTEM
savedir = 'scan/'
savename = f'{ipch} scan.txt'
if not os.path.isdir(savedir): os.mkdir(savedir)

savefile = f"{savedir}{savename}"
with open(savefile, "w+") as log:
    log.write(f'Result for {ipin} found:')

# MCSTATUS
def servcheck(ip,port):
    print(lc+'====={ mcstatus test }=====')
    try:
        server = JavaServer.lookup(f'{ip}:{port}')
        status = server.status()
        motdfull = status.description
        online = f"{status.players.online} of {status.players.max}"
        version = status.version.name
        motd = re.sub(r'§.|&.|\n', '', motdfull)

        scrinf = f"{lg}[MCS] Found server: {ip}:{port}\nMOTD: {motd}\nVersion: {version}\nOnline: {online}"
        print(scrinf)

        # SERVER SAVER    
        textfile = f'\n{ip}:{port} | Version: {version} | Online: {online} | MOTD: {motd}'
        if logver != 'all':
            if logver in version:
                with open(savefile, "a+") as log:
                    log.write(textfile)
        else:
            with open(savefile, "a+") as log:
                    log.write(textfile)
    except:
        print(lr+'Failed to check MCstatus')

# LONG PORTSCANNER
def portscan(chip, sp, ep, full):
    for i in range(ep):
        if i > sp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                connect = sock.connect((str(chip),i))
                sock.close()
                print(f'{lg}[PS] Found port | {chip}:{i}')
                if full == True:
                    servcheck(str(chip),str(i))
                Found = True
                if full == False:
                    return Found
            except:
                if full == False:
                    Found = False
    if full == False:
        return Found

# IP RANGE SCANNER 0 - 255
for ip in ipaddress.IPv4Network(f'{ipch}/24'):
        print(f'{ly}[P] Checking {ip}...')

        # SHORT SCAN ST1
        print(f'{ly}[P] Stage 1 of 3')
        Found0 = False
        if portscan(ip,24000,24010,False) == True:
             Found0 = True
        if Found0 == True:
            print(lc+'====={ Portscanner 1 }=====')
            print(portscan(ip, 24000, 25565,True))
            print('[PS] Succes scanned ports')

        # SHORT SCAN ST2
        print(f'{ly}[P] Stage 2 of 3')
        Found1 = False
        if portscan(ip,25560,25580,False) == True:
            Found1 = True
        if Found1 == True:
            print(lc+'====={ Portscanner 2 }=====')
            print(portscan(ip, 25500, 26000,True))
            print('[PS] Succes scanned ports')

        # SHORT SCAN ST3
        print(f'{ly}[P] Stage 3 of 3')
        Found2 = False
        if portscan(ip,30620,30640,False) == True:
            Found2 = True
        if Found2 == True:
            print(lc+'====={ Portscanner 3 }=====')
            print(portscan(ip, 30500, 32500,True))
            print('[PS] Succes scanned ports')

        print(f'{lr}[P] Nothing found')

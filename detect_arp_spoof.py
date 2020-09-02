from scapy.all import Ether, ARP, srp, sniff, conf
from colorama import init, Fore
import sys, random

# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

def ClownLogo():
    clear = "\x1b[0m"
    colors = [36, 32, 34, 35, 31, 37]

    x = """

   
        ____       __            __     ___    ____  ____     _____                   ____
       / __ \___  / /____  _____/ /_   /   |  / __ \/ __ \   / ___/____  ____  ____  / __/
      / / / / _ \/ __/ _ \/ ___/ __/  / /| | / /_/ / /_/ /   \__ \/ __ \/ __ \/ __ \/ /_  
     / /_/ /  __/ /_/  __/ /__/ /_   / ___ |/ _, _/ ____/   ___/ / /_/ / /_/ / /_/ / __/  
    /_____/\___/\__/\___/\___/\__/  /_/  |_/_/ |_/_/       /____/ .___/\____/\____/_/     
                                                               /_/                        
    CS! : Detect ARP Spoof es un script facil de usar podra ejecutarlo solo en linux.       
    """
    for N, line in enumerate(x.split("\n")):
         sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
         time.sleep(0.05)

def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def process(packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # if they're different, definetely there is an attack
                if real_mac != response_mac:
                    print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass

if __name__ == "__main__":
    import sys
    ClownLogo()
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = conf.iface
    sniff(store=False, prn=process, iface=iface)

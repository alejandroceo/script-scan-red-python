from scapy.all import ARP, Ether, srp
import socket
import struct
import fcntl
import netifaces
from urllib.request import urlopen

def get_local_ip(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
        )[20:24])
    except OSError:
        return None

def get_active_interface():
    interfaces = netifaces.interfaces()
    for ifname in interfaces:
        ip = get_local_ip(ifname)
        if ip and ip.startswith('192.168.'):
            return ifname, ip
    return None, None

def get_ip_range():
    ifname, local_ip = get_active_interface()
    if not ifname:
        print("No se pudo detectar una interfaz de red activa.")
        return None
    network_prefix = local_ip.rsplit('.', 1)[0]
    return f"{network_prefix}.0/24"

def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        with urlopen(url) as response:
            vendor = response.read().decode('utf-8')
            return vendor
    except:
        return "Desconocido"

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=5, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Desconocido"
        mac = received.hwsrc
        vendor = get_vendor(mac)
        devices.append({'ip': received.psrc, 'mac': mac, 'hostname': hostname, 'vendor': vendor})

    return devices

def main():
    ip_range = get_ip_range()
    if not ip_range:
        return
    
    print(f"Escaneando la red {ip_range}...")
    
    devices = scan_network(ip_range)

    if devices:
        print("Dispositivos encontrados:")
        print("{:<16} {:<18} {:<30} {}".format("IP", "MAC", "Fabricante", "Hostname"))
        for device in devices:
            print("{:<16} {:<18} {:<30} {}".format(device['ip'], device['mac'], device['vendor'], device['hostname']))
    else:
        print("No se encontraron dispositivos en la red.")

if __name__ == "__main__":
    main()

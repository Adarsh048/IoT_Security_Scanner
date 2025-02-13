import scapy.all as scapy
import nmap
import netifaces

def get_local_network():
    """Get the local network IP range."""
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        try:
            iface_details = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            ip = iface_details['addr']
            netmask = iface_details['netmask']
            subnet = f"{ip}/{netmask_to_cidr(netmask)}"
            return subnet
        except (KeyError, ValueError):
            continue
    return None

def netmask_to_cidr(netmask):
    """Convert subnet mask to CIDR notation."""
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

def scan_network(subnet):
    """Scan the local network for connected IoT devices."""
    print(f"Scanning network: {subnet} ...")
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)
    
    return devices

def scan_ports(ip):
    """Scan open ports on a given device."""
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-T4 -F')  # Fast scan mode
    open_ports = [port for port in scanner[ip]['tcp'] if scanner[ip]['tcp'][port]['state'] == 'open']
    return open_ports

def main():
    subnet = get_local_network()
    if not subnet:
        print("Could not determine local network range.")
        return
    
    devices = scan_network(subnet)
    
    if not devices:
        print("No IoT devices found.")
        return

    print("\n🛡 IoT Devices & Open Ports:")
    for device in devices:
        open_ports = scan_ports(device['ip'])
        print(f"🔹 IP: {device['ip']} | MAC: {device['mac']} | Open Ports: {open_ports if open_ports else 'None'}")

if __name__ == "__main__":
    main()

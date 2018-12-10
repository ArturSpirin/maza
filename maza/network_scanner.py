import threading
import time
from datetime import datetime
import netifaces
import pprint
import socket
from netaddr import IPAddress, IPNetwork


class NetworkScanner:

    def __init__(self):
        self.targets = {}
        self.threads = []

    def is_legal_ip(self, ip):
        try:
            socket.inet_aton(ip)
        except:
            return False
        return True

    def cird_to_ips(self, cird):
        return IPNetwork(cird)

    def get_cird(self, netmask):
        return IPAddress(netmask).netmask_bits()

    def get_scanning_range(self):
        # TODO support specific interface and/or netmask
        ranges = []
        interfaces = netifaces.interfaces()
        for data in interfaces:
            ips = netifaces.ifaddresses(data)
            for key, interface_data in ips.items():
                for item in interface_data:
                    if item.get("netmask", None) is not None and \
                            item.get("addr", None) is not None and \
                            self.is_legal_ip(item["netmask"]):
                        range = "{ip}/{cird}".format(ip=item["addr"], cird=self.get_cird(item["netmask"]))
                        if range not in ranges and "127.0.0.1" not in range:
                            ranges.append(range)
        return ranges

    def get_potential_targets(self):
        network_targets = {}
        for network in self.get_scanning_range():
            ips = self.cird_to_ips(network)
            targets = []
            for ip in ips:
                targets.append(ip)
            print("Potential targets on {} network: {}".format(network, len(targets)))
            network_targets.update({network: targets})
        return network_targets

    def scan_for_open_ports(self, ip, ports_to_scan):
        # TODO allow to set timeout
        ip = str(ip)

        def run_scan(_port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, _port))
            if result == 0:
                self.targets[_port].append(ip)
                print("Port {}: 	 Open on {}".format(_port, ip))
            else:
                print("Port {}: 	 Closed on {}".format(_port, ip))
            sock.close()

        try:
            for port in ports_to_scan:
                self.__run_in_a_thread(run_scan, (port, ))
                # thread = threading.Thread(target=run_scan, args=(port, ))
                # thread.start()

        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            exit()

        except socket.gaierror:
            print('Hostname could not be resolved. Exiting')
            exit()

        except socket.error:
            print("Couldn't connect to server")
            exit()

    def get_targets(self, ports_to_scan):

        print("Scanning for targets with following open ports: {}".format(ports_to_scan))

        t1 = datetime.now()
        # TODO update range
        ips = self.get_potential_targets().get("192.168.0.87/24")
        for port in ports_to_scan:
            self.targets.update({port: []})
        for ip in ips:
            self.__run_in_a_thread(self.scan_for_open_ports, (ip, ports_to_scan))

        for t in self.threads:
            t.join()

        t2 = datetime.now()
        total = t2 - t1
        print('Scanning Completed in: ', total)
        return self.targets

    def get_active_threads(self):
        active = 0
        for t in self.threads:
            if t.isAlive():
                active += 1
            else:
                self.threads.remove(t)
        return active

    def __run_in_a_thread(self, func, args):
        # TODO allow to set number of threads
        while self.get_active_threads() > 600:
            time.sleep(0.5)
        thread = threading.Thread(target=func, args=args)
        thread.start()
        self.threads.append(thread)


# pprint.pprint(NetworkScanner().get_targets([22, 23, 80, 443, 5432]))
# print(socket.gethostbyname(socket.gethostname()))

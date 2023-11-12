import os
import pprint
import sys
import threading
import time
from datetime import datetime
import netifaces
import socket
from optparse import OptionParser

from netaddr import IPAddress, IPNetwork

sys.path.insert(1, "E:\Development\maza")
import maza.modules as modules
from maza.core.exploit.utils import pythonize_path


class Utility:
    __THREADS = []

    @staticmethod
    def run_in_a_thread(func, args, limit):
        """
        Utility function to run operations in a thread but honors the thread limit
        """

        def get_active_threads():
            active = 0
            for t in Utility.__THREADS:
                if t.isAlive():
                    active += 1
                else:
                    Utility.__THREADS.remove(t)
            return active

        while get_active_threads() > limit:
            time.sleep(0.5)
        thread = threading.Thread(target=func, args=args)
        thread.start()
        Utility.__THREADS.append(thread)

    @staticmethod
    def join_threads():

        for thread in Utility.__THREADS:
            thread.join()

    @staticmethod
    def modulize_exploit_path(path):

        path = path.split("maza")[-1]
        return "maza" + pythonize_path(path).replace(".py", "")


class NetworkScanner:

    def __init__(self, timeout=3, thread_limit=300, network=None):

        self.targets = {}
        self.__thread_limit = thread_limit
        self.__timeout = timeout
        self.__network = network

    def is_legal_ip(self, ip):
        """
        :param ip: STRING 192.168.0.1
        :return: BOOLEAN
        """
        try:
            socket.inet_aton(ip)
        except Exception:
            return False
        return True

    def __get_scanning_range(self):
        """
        Creates CIRD range notation (network) based on the currently configures network interfaces/adapters
        If scanning range was set at run time, it will just use that one
        :return: LIST ["192.168.0.1/24", ".../..", ".../.."]
        """
        if self.__network is not None:
            return [self.__network]
        networks = []
        interfaces = netifaces.interfaces()
        for data in interfaces:
            ips = netifaces.ifaddresses(data)
            for key, interface_data in ips.items():
                for item in interface_data:
                    if item.get("netmask", None) is not None and \
                            item.get("addr", None) is not None and \
                            self.is_legal_ip(item["netmask"]) and item.get("addr") not in ["127.0.0.1", "0.0.0.0"]:
                        network = "{ip}/{cird}".format(ip=item["addr"],
                                                       cird=IPAddress(item["netmask"]).netmask_bits())
                        if network not in networks:
                            networks.append(network)
        return networks

    def __get_potential_targets(self):
        """
        Converts CIRD notation(network) to IP addresses and maps them to the network
        :return: DICT aka {"192.168.0.1/24": ["192.168.0.1", "192.168.0.2", ...]}
        """
        network_targets = {}
        for network in self.__get_scanning_range():
            ips = IPNetwork(network)  # converts CIRD notation to IP addresses
            targets = list(ips)
            print(f"Potential targets on {network} network: {len(targets)}")
            network_targets[network] = targets
        return network_targets

    def __scan_for_open_ports(self, ip, ports_to_scan):
        """
        Scans a given IP for specific open ports
        :param ip: STRING 192.168.0.1
        :param ports_to_scan: LIST [22, 23, 80, ...]
        :return:
        """
        ip = str(ip)

        def run_scan(_port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.__timeout)
                result = sock.connect_ex((ip, _port))
                if result == 0:
                    self.targets[_port].append(ip)
                    print("Port {}: 	 Open on {}".format(_port, ip))
                sock.close()
            except socket.gaierror:
                print('Hostname could not be resolved: {}'.format(ip))
            except socket.error:
                print("Couldn't connect to server: {}".format(ip))

        for port in ports_to_scan:
            Utility.run_in_a_thread(run_scan, (port,), self.__thread_limit)

    def get_targets(self, ports_to_scan):
        """
        Returns suitable targets to perform vulnerability scans on broken down by open ports
        :param ports_to_scan: LIST [22, 23, 80, ...]
        :return: DICT {80: [192.168.0.1, 192.168.0.2, ..., 22: [...], 23: [...]]}
        """
        t1 = datetime.now()
        network_ips = self.__get_potential_targets()
        for port in ports_to_scan:
            self.targets.update({port: []})

        print(f"Port scan in progress for the following open ports: {ports_to_scan}")
        for network, ips in network_ips.items():
            for ip in ips:
                Utility.run_in_a_thread(self.__scan_for_open_ports, (ip, ports_to_scan), self.__thread_limit)

        Utility.join_threads()

        t2 = datetime.now()
        total = t2 - t1
        print('Port scan completed in: ', total)
        return self.targets


class VulnerabilityScanner:

    def __init__(self):

        self.__vulnerable_ports = {}

    def get_vulnerable_ports(self):
        """
        Returns a map of what ports we can potentially hack services on and what exploits can do it
        :return: DICT {80: ["path/to/exploit.py", "...py", "...py"], 22: [..., ...], 23: [..., ...]}
        """
        self.__get_vulnerable_ports(modules.__path__[0])
        return self.__vulnerable_ports

    def __get_vulnerable_ports(self, path):
        """
        Utility function that will recursively go through all of the RSF modules to find all of the exploits and will
        map all of the exploits that can be done to ports
        :param path: STRING path to the RSF modules directory
        :return: None, will update the instance variable
        """
        files = os.listdir(path)
        for file in files:
            if file != "__init__.py" and ".pyc" not in file:
                doc_path = f"{path}{os.sep}{file}"
                if os.path.isfile(doc_path):
                    with open(doc_path, "r") as doc:
                        lines = doc.readlines()
                        for line in lines:
                            if "port = OptPort" in line:
                                string = line.split(",")[0].split("(")[-1].replace("port = OptPort(", "")
                                port = int(string)
                                if port not in self.__vulnerable_ports:
                                    self.__vulnerable_ports.update({port: [doc_path]})
                                else:
                                    self.__vulnerable_ports[port].append(doc_path)
                else:
                    self.__get_vulnerable_ports(doc_path)

    @staticmethod
    def __create_exploit(module_name, class_name):
        """
        :param module_name: STRING aka maza.modules.exploits.cameras.avigilon.videoiq_camera_path_traversal
        :param class_name: STRING aka Exploit
        :return: Exploit object
        """
        m = __import__(module_name, globals(), locals(), class_name)
        return getattr(m, class_name)

    @staticmethod
    def run_exploit(_exploit, _ip, _port):
        try:
            _exploit = VulnerabilityScanner.__create_exploit(_exploit, "Exploit")()
            _exploit.target = _ip
            if getattr(_exploit, "check_default", None) is not None:
                result = _exploit.check_default()
                if result is None:
                    print(
                        f"[N/A] Cannot asses if target: {_ip}:{_port} is vulnerable to: {_exploit}."
                    )
                elif result:
                    print(
                        f"[OK] Target: {_ip}:{_port} is vulnerable to: {_exploit}. Credentials: {result}"
                    )
            else:
                result = _exploit.check()
                if result is True:
                    print(f"[OK] Target: {_ip}:{_port} is vulnerable to: {_exploit}")
                elif result is not False:
                    print(
                        f"[N/A] Cannot asses if target: {_ip}:{_port} is vulnerable to: {_exploit}"
                    )
        except Exception:
            print(sys.exc_info())
            print(f"Failed to create Exploit: {_exploit}")


if "__main__" == __name__:

    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", type=str, default=None,
                      help="Sets the target ip for the vulnerability scan")
    parser.add_option("-n", "--network", dest="network", type=str, default=None,
                      help="Sets the range to use for the network scan aka 10.10.0.1/24")
    parser.add_option("", "--threads", dest="threads", type=int, default=300,
                      help="Sets the limit for the maximum number of threads that can be using when scanning "
                           "ip range for open ports. Default is 300 threads")
    parser.add_option("", "--request_timeout", dest="request_timeout", type=int, default=3,
                      help="Sets the timeout for requests when scanning ip range for open ports. Default is 3 seconds")
    parser.add_option("", "--place_holder", dest="place_holder", default=False, action="store_true",
                      help="")
    options = parser.parse_args()[0]

    vulnerability_scanner = VulnerabilityScanner()
    network_scanner = NetworkScanner(network=options.network,
                                     thread_limit=options.threads,
                                     timeout=options.request_timeout)

    t1 = datetime.now()

    vulnerable_ports = vulnerability_scanner.get_vulnerable_ports()
    vulnerable_machines = network_scanner.get_targets(vulnerable_ports.keys())

    for target_port, target_ips in vulnerable_machines.items():
        for target_ip in target_ips:
            for exploit in vulnerable_ports[target_port]:
                modulirized_exploit = Utility.modulize_exploit_path(exploit)
                Utility.run_in_a_thread(func=vulnerability_scanner.run_exploit,
                                        args=(modulirized_exploit, target_ip, target_port),
                                        limit=options.threads)
    Utility.join_threads()

    t2 = datetime.now()
    total = t2 - t1
    print('Vulnerability assessment completed in: ', total)

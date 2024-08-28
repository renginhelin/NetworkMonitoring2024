import re
from flask import Flask, jsonify, render_template, request
import subprocess
import platform
import netmiko
import threading
import deneme
import ipaddress

import router_service

app = Flask(__name__)
router_db = router_service.router_service("devices")
host_db = deneme.db_operations("devices", "host")


class NetmikoHandler:
    def __init__(self, device):
        self.device = device
        self.connection = None

    def connect(self):
        try:
            self.connection = netmiko.ConnectHandler(**self.device)
        except netmiko.NetMikoTimeoutException as e:
            print(f"Connection timed out: {e}")
            self.connection = None
        except netmiko.NetMikoAuthenticationException as e:
            print(f"Authentication failed: {e}")
            self.connection = None
        except Exception as e:
            print(f"Connection failed: {e}")
            self.connection = None

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None

    def send_command(self, command):
        if not self.connection:
            return "Connection not established"
        try:
            output = self.connection.send_command(command)
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            return "Timeout"

    def show_inventory(self):
        try:
            output = self.connection.send_command("show inventory")
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            return "Timeout"

    def show_hardware_and_version(self):
        index_for_extract = [0, 3, 5, 6, 8, 28, 29, 30, 31, 32, 33, 35]
        try:
            output = self.connection.send_command("show hardware").split("\n")
            output = "\n".join([output[index] for index in index_for_extract])
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            return "Timeout"

    def get_hostname(self):
        try:
            output = self.connection.send_command("show running-config | include hostname")
            hostname = output.split("hostname ")[1].strip()
            return hostname
        except Exception as e:
            return f"Error retrieving hostname: {e}"

    def get_interface_ips(self):
        """Fetch all IP addresses from 'show ip interface brief' output."""
        command = "show ip interface brief"
        output = self.send_command(command)
        ip_addresses = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output)
        print(ip_addresses)
        return ip_addresses

    def transform_arp_output(self):
        arp_output = self.send_command("show arp")
        lines = arp_output.strip().split("\n")[1:]

        # Initialize the dictionary to hold the transformed output
        arp_map = {}

        for line in lines:
            parts = [part for part in line.split() if part]
            match = re.search(r'\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)$', line)

            if len(parts) >= 5:
                ip_address = parts[1] if parts[1] != '-' else None
                hardware_address = parts[3] if parts[3] != 'Incomplete' else None
                if match:
                    interface = match.group(3)

                    # Only include entries with valid IP addresses and hardware addresses
                    if ip_address and hardware_address:
                        arp_map[ip_address] = [hardware_address, interface]

        return arp_map

    def combine_ip_interface(self):
        # Send the commands to get the outputs
        ip_output = self.connection.send_command("sh cdp entry * protocol | include IP")
        interface_output = self.connection.send_command("sh cdp neighbors detail | include Interface")

        def parse_ip_output(ip_output):
            # Extract IP addresses from the output
            ip_addresses = []
            lines = ip_output.strip().splitlines()
            for line in lines:
                if "IP address:" in line:
                    ip_address = line.split(":")[1].strip()
                    ip_addresses.append(ip_address)
            return ip_addresses

        def parse_interface_output(interface_output):
            # Extract interfaces from the output
            interfaces = []
            lines = interface_output.strip().splitlines()
            for line in lines:
                if "Interface:" in line:
                    interface = line.split(",")[0].split(":")[1].strip()
                    print(line)
                    interfaces.append(interface)
            return interfaces

        # Parsing the outputs
        ip_addresses = parse_ip_output(ip_output)
        interfaces = parse_interface_output(interface_output)
        print(ip_addresses, interfaces)
        # Check lengths for mismatches
        if len(ip_addresses) != len(interfaces):
            raise ValueError("The number of IP addresses and interfaces does not match.")

        # Combine IP addresses and interfaces into a dictionary
        combined_map = {}
        for ip, interface in zip(ip_addresses, interfaces):
            combined_map[interface] = ip

        return combined_map


ssh_handlers = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/ping_devices', methods=['GET'])
def ping_devices():
    def ping_device(ip, results, index):
        try:
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                command = ["ping", "-c", "1", "-W", "1", ip]

            output = subprocess.run(command, capture_output=True, text=True)

            if platform.system() == "Windows":
                if "Request timed out" in output.stdout or "Destination host unreachable" in output.stdout:
                    results[index] = {"host": ip, "status": False}
                    return
            else:
                if "100% packet loss" in output.stdout or "unreachable" in output.stdout:
                    results[index] = {"host": ip, "status": False}
                    return

            results[index] = {"host": ip, "status": True}
        except Exception as e:
            print(f"An error occurred while pinging {ip}: {e}")
            results[index] = {"host": ip, "status": False}

    devices = router_db.get_routers()
    threads = []
    results = [{} for _ in devices]

    for i, device in enumerate(devices):
        thread = threading.Thread(target=ping_device, args=(device["connection"]['host'], results, i))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
    sorted_results = sorted(results, key=lambda d: d['host'])  # Sorting by 'host'
    return jsonify(sorted_results)


@app.route('/broadcast_devices', methods=['GET'])
def broadcast():
    def ping_device(ip, new_devices):
        try:
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                command = ["ping", "-c", "1", "-W", "1", ip]

            output = subprocess.run(command, capture_output=True, text=True)

            if platform.system() == "Windows":
                if "Request timed out" in output.stdout or "Destination host unreachable" in output.stdout:
                    return
            else:
                if "100% packet loss" in output.stdout or "unreachable" in output.stdout:
                    return

            new_device = ip
            new_devices.append(new_device)
        except Exception as e:
            print(f"An error occurred while pinging {ip}: {e}")

    subnet = ipaddress.ip_network('10.10.10.0/24', strict=False)
    existing_devices = {device["connection"]['host'] for device in router_db.get_routers()}
    new_devices = []
    threads = []

    for ip in subnet.hosts():
        ip_str = str(ip)
        if ip_str not in existing_devices:
            thread = threading.Thread(target=ping_device, args=(ip_str, new_devices))
            print(new_devices)
            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()

    return jsonify({"status": "success", "new_devices": new_devices})


@app.route('/perform_operation', methods=['POST'])
def perform_operation():
    data = request.json
    host = data.get('host')
    operation = data.get('operation')
    ssh_handler = ssh_handlers.get(host)

    if ssh_handler and ssh_handler.connection:
        if operation == 'show_interface_brief':
            output = ssh_handler.send_command("show ip interface brief")
            output = format_interface_brief(output)
        elif operation == 'show_inventory':
            output = ssh_handler.show_inventory()
        elif operation == 'show_hardware_and_version':
            output = ssh_handler.show_hardware_and_version()
        elif operation == 'show_arp_table':
            output = ssh_handler.send_command("show arp")
            output = format_arp_table(output)
        else:
            output = "Invalid operation"
        return jsonify({"status": "success", "output": output})
    else:
        return jsonify({"status": "error", "message": "No active SSH session or connection not established"})


@app.route('/detailed_trace', methods=['POST'])
def detailed_trace():
    def parse_next_hop(output):
        # Split the output by lines
        lines = output.strip().splitlines()
        # Iterate over the lines to find the line containing the next hop
        for line in lines:
            # Find a line that contains the hop number followed by an IP address
            match = re.search(r'\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                return match.group(1)

        return None


    devices = router_db.get_routers()
    data = request.json
    source = data.get('source')
    destination = data.get('destination')

    trace_result = []
    current_hop = 1

    current_hop_device = next((device for device in devices if source in device['interface']), None)

    while not (destination in current_hop_device["interface"]):
        ssh_handler = NetmikoHandler(current_hop_device["connection"])
        ssh_handler.connect()
        if ssh_handler and ssh_handler.connection:
            cdp_output = ssh_handler.combine_ip_interface()
            print(cdp_output)
            if re.match(r"SW\d+", current_hop_device["name"]):
                command = f"traceroute {destination}"
                next_device_ip = parse_next_hop(ssh_handler.send_command(command))
                if next_device_ip in cdp_output.values():
                    print("merhabalarmerhabalar")
                    trace_result.append(current_hop_device)
                    current_hop += 1
                    current_hop_device = next((device for device in devices if next_device_ip in device['interface']), None)
            else:

                arp_output = ssh_handler.transform_arp_output()
                print(arp_output)
                command = f"traceroute {destination} ttl 1 1"
                next_device_ip = parse_next_hop(ssh_handler.send_command(command))
                print(next_device_ip)
                interface = arp_output[next_device_ip][1]
                print(interface)
                if arp_output[next_device_ip][1] in cdp_output.keys():

                    trace_result.append(current_hop_device)
                    current_hop += 1
                    current_hop_device = next((device for device in devices if str(cdp_output[interface]) in device['interface']), None)
        ssh_handler.disconnect()


    trace_result.append(current_hop_device)
    current_hop += 1
    return jsonify({"status": "success", "trace": trace_result})




def format_interface_brief(output):
    lines = output.splitlines()
    headers = ["Interface", "IP-Address", "OK?", "Method", "Status", "Protocol"]
    rows = [line.split() for line in lines[1:] if line.strip()]

    table_html = '<h6>Interface Brief</h6><table><thead><tr>' + \
                 ''.join(f'<th>{header}</th>' for header in headers) + \
                 '</tr></thead><tbody>' + \
                 ''.join(f'<tr>{"".join(f"<td>{col}</td>" for col in row)}</tr>' for row in rows) + \
                 '</tbody></table>'
    return table_html


def format_arp_table(output):
    lines = output.splitlines()
    headers = ["Protocol", "Address", "Age (min)", "Hardware Addr", "Type", "Interface"]
    rows = [line.split() for line in lines[1:] if line.strip()]

    table_html = '<h6>ARP Table</h6><table><thead><tr>' + \
                 ''.join(f'<th>{header}</th>' for header in headers) + \
                 '</tr></thead><tbody>' + \
                 ''.join(f'<tr>{"".join(f"<td>{col}</td>" for col in row)}</tr>' for row in rows) + \
                 '</tbody></table>'
    return table_html


@app.route('/cancel_ssh', methods=['POST'])
def cancel_ssh():
    data = request.json
    host = data.get('host')
    ssh_handler = ssh_handlers.pop(host, None)
    if ssh_handler:
        ssh_handler.disconnect()
        return jsonify({"status": "success", "message": "SSH session ended"})
    else:
        return jsonify({"status": "error", "message": "No active SSH session"})


@app.route('/start_ssh', methods=['POST'])
def start_ssh():
    devices = router_db.get_routers()
    data = request.json
    host = data.get("host")
    password = data.get("password")

    # Fetch the device from the database
    connection_json = next((device["connection"] for device in devices if device["connection"]["host"] == host), None)

    if connection_json:
        # Update the device dictionary with the provided password
        connection_json['password'] = password

        ssh_handler = NetmikoHandler(connection_json)
        ssh_handler.connect()

        if ssh_handler.connection:
            ssh_handlers[host] = ssh_handler
            return jsonify({"status": "success"}), 200
        else:
            return jsonify({"status": "error", "message": "SSH connection failed"}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found"}), 404


@app.route('/add_device', methods=['POST'])
def add_device():
    data = request.json
    device_type = data.get("deviceType")

    if device_type == "router" :
        host = data.get("host")
        name = data.get("name")
        username = data.get("username")
        password = data.get("password")

        if not all([host, name, username, password]):
            return jsonify({"status": "error", "message": "Missing required fields for router"}), 400

        connection = {"device_type": "cisco_ios", "host": host,
                      "username": username, "password": password}

        ssh_handler = NetmikoHandler(connection)
        ssh_handler.connect()
        print("hello")
        print(ssh_handler.connection)
        if ssh_handler.connection:
            print("hello2")
            new_device = {
                "name": name,
                "connection": connection,
                "interface": ssh_handler.get_interface_ips()
            }
            result = router_db.add_router(new_device)
            ssh_handler.disconnect()

            return jsonify({"status": "success", "result": result}), 200
        else:
            return jsonify({"status": "error", "message": "Failed to connect to the device"}), 500

    elif device_type == "switch":
        # Handle switch-specific logic here
        pass
    elif device_type == "vpcs":
        # Handle VPCS-specific logic here
        pass
    else:
        return jsonify({"status": "error", "message": "Invalid device type"}), 400


if __name__ == "__main__":
    app.run(debug=True)

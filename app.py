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


@app.route('/traceroute', methods=['POST'])
def traceroute():
    def parse_next_hop(output):
        match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', output)
        if match:
            return match.group()
        return None

    devices = router_db.get_routers()
    vpcs = host_db.find_documents()
    data = request.json
    source = data.get('source')
    destination = data.get('destination')

    trace_result = []
    current_hop = 1
    current_ip = source

    while current_ip != destination:
        current_device = next((device for device in devices if device['host'] == current_ip), None)

        if current_device:
            ssh_handler = NetmikoHandler(current_device)
            ssh_handler.connect()
            if ssh_handler and ssh_handler.connection:
                command = f"traceroute {destination} ttl 1 2"
                output = ssh_handler.send_command(command)
                next_hop_ip = parse_next_hop(output)

                if next_hop_ip:
                    trace_result.append({
                        "hop": current_hop,
                        "ip": current_ip,
                        "device_type": "Router"
                    })
                    current_ip = next_hop_ip
                else:
                    trace_result.append({
                        "hop": current_hop,
                        "ip": current_ip,
                        "device_type": "Unknown"
                    })
                    break

        # Check if the current_ip matches any host in vpcs
        current_vpcs = next((vpc for vpc in vpcs if vpc['host'] == current_ip), None)

        if current_vpcs:
            trace_result.append({
                "hop": current_hop,
                "ip": current_ip,
                "device_type": "VPCS"
            })
            break

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

    if device_type == "router":
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
                "interface": []
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

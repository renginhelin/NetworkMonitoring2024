from flask import Flask, jsonify, render_template, request
import subprocess
import platform
import netmiko
import threading
import deneme
import ipaddress

app = Flask(__name__)
db = deneme.db_operations("devices", "network")

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

    devices = db.find_documents()
    threads = []
    results = [{} for _ in devices]

    for i, device in enumerate(devices):
        thread = threading.Thread(target=ping_device, args=(device['host'], results, i))
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

            new_device = {"host": ip, "device_type": "cisco_ios", "username": "admin", "password": "cisco123"}
            new_devices.append(new_device)
        except Exception as e:
            print(f"An error occurred while pinging {ip}: {e}")

    subnet = ipaddress.ip_network('10.10.10.0/24', strict=False)
    existing_devices = {device['host'] for device in db.find_documents()}
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
    devices = db.find_documents()
    data = request.json
    host = data.get("host")
    password = data.get("password")

    # Fetch the device from the database
    device = next((device for device in devices if device['host'] == host), None)

    if device:
        # Update the device dictionary with the provided password
        device['password'] = password

        ssh_handler = NetmikoHandler(device)
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
    host = data.get("host")
    new_device = {"host": host, "device_type": "cisco_ios", "username": "admin", "password": "cisco123"}
    db.insert_document(new_device)
    return jsonify({"status": "success"}), 200


if __name__ == "__main__":
    app.run(debug=True)
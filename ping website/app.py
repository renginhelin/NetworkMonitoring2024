from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import subprocess
import platform
import netmiko
import ipaddress
import threading
import re
import time
from netmiko import ConnectHandler
from netaddr import IPNetwork

app = Flask(__name__)
app.secret_key = '123'  # Required for session management

# Configuration
hostname = '192.168.199.102'
port = 22
username = 'admin'
password = 'admin'
device_type = 'cisco_ios'

# Router connection details
router = {
    'device_type': device_type,
    'host': hostname,
    'username': username,
    'password': password,
    'port': port,
    'secret': password,
    'verbose': False
}

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

# Router Login
users = {
    username: {"password": password}
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

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

devices = [
    {"device_type": device_type, "host": hostname, "username": username, "password": password}
]

ssh_handlers = {}

# Dictionary to store throughput data for all interfaces
throughput_data = {}

def get_interfaces():
    output = net_connect.send_command('show ip interface brief')
    interfaces = re.findall(r'(\S+)\s+\d+\.\d+\.\d+\.\d+', output)
    return interfaces

def get_interface_rates(interface):
    output = net_connect.send_command(f'show interface {interface}')
    input_rate_match = re.search(r"5 minute input rate (\d+) bits/sec", output)
    output_rate_match = re.search(r"5 minute output rate (\d+) bits/sec", output)

    input_rate = int(input_rate_match.group(1)) if input_rate_match else 0
    output_rate = int(output_rate_match.group(1)) if output_rate_match else 0

    return input_rate, output_rate

def collect_throughput_data():
    minute = 0
    interfaces = get_interfaces()
    for interface in interfaces:
        throughput_data[interface] = {
            "time_intervals": [],
            "input_throughputs": [],
            "output_throughputs": []
        }

    while True:
        for interface in interfaces:
            input_rate, output_rate = get_interface_rates(interface)
            throughput_data[interface]["time_intervals"].append(minute)
            throughput_data[interface]["input_throughputs"].append(input_rate)
            throughput_data[interface]["output_throughputs"].append(output_rate)
        
        minute += 3
        time.sleep(3)

# Start collecting throughput data in a background thread
net_connect = ConnectHandler(**router)
net_connect.enable()
thread = threading.Thread(target=collect_throughput_data)
thread.start()

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users.get(username)
        if user and user['password'] == password:
            user_obj = User(username)
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/throughput')
def throughput():
    return render_template('throughput.html')

@app.route('/data')
@login_required
def data():
    return jsonify(throughput_data)

# Modify the index route to require login
@app.route('/')
@login_required
def index():
    print(f"User authenticated: {current_user.is_authenticated}")
    return render_template('index.html')

@app.route('/broadcast')
@login_required
def device_configuration_page():
    subnets = retrieve_subnets()
    return render_template('newpage.html', subnets=subnets)

@app.route('/ping_devices', methods=['GET'])
@login_required
def ping_devices():
    def ping_device(ip):
        try:
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                command = ["ping", "-c", "1", "-W", "1", ip]

            output = subprocess.run(command, capture_output=True, text=True)

            if platform.system() == "Windows":
                if "Request timed out" in output.stdout or "Destination host unreachable" in output.stdout:
                    return False
            else:
                if "100% packet loss" in output.stdout or "unreachable" in output.stdout:
                    return False

            return True
        except Exception as e:
            print(f"An error occurred while pinging {ip}: {e}")
            return False

    available_devices = [{"host": device['host'], "status": ping_device(device['host'])} for device in devices]
    return jsonify(available_devices)

@app.route('/ping_arp_devices', methods=['POST'])
@login_required
def ping_arp_devices():
    data = request.json
    host = data.get('host')
    ssh_handler = ssh_handlers.get(host)

    if not ssh_handler or not ssh_handler.connection:
        return jsonify({"status": "error", "message": "No active SSH session or connection not established"})

    def ping_device(ip):
        try:
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", "-w", "2000", ip]
            else:
                command = ["ping", "-c", "1", "-W", "2", ip]

            output = subprocess.run(command, capture_output=True, text=True)

            if platform.system() == "Windows":
                if "Request timed out" in output.stdout or "Destination host unreachable" in output.stdout:
                    return False
            else:
                if "100% packet loss" in output.stdout or "unreachable" in output.stdout:
                    return False

            return True
        except Exception as e:
            print(f"An error occurred while pinging {ip}: {e}")
            return False

    arp_results = []
    arp_table = ssh_handler.send_command("show arp")
    arp_lines = arp_table.split('\n')[1:]  # Skip the header line
    for line in arp_lines:
        if line.strip():
            columns = line.split()
            ip_address = columns[1]  # Assuming the IP address is in the second column
            is_reachable = ping_device(ip_address)
            arp_results.append({"ip": ip_address, "reachable": is_reachable})

    return jsonify({"status": "success", "results": arp_results})

@app.route('/perform_operation', methods=['POST'])
@login_required
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
@login_required
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
@login_required
def start_ssh():
    data = request.json
    host = data.get("host")
    device = next((device for device in devices if device['host'] == host), None)
    if device:
        ssh_handler = NetmikoHandler(device)
        ssh_handler.connect()
        if ssh_handler.connection:
            ssh_handlers[host] = ssh_handler
            print(ssh_handlers)
            return jsonify({"status": "success"}), 200
        else:
            return jsonify({"status": "error", "message": "SSH connection failed"}), 500
    else:
        return jsonify({"status": "error", "message": "Device not found"}), 404

def get_interface_ip_addresses(ssh_client):
    command = "show running-config"
    output = ssh_client.send_command(command)
    lines = output.splitlines()
    
    interface_ips = {}
    current_interface = None
    
    for line in lines:
        if line.startswith('interface'):
            current_interface = line.split()[-1]
        elif current_interface and 'ip address' in line:
            parts = line.split()
            ip_address = parts[2]
            subnet_mask = parts[3]

            interface_ips[current_interface] = (ip_address, subnet_mask)
            current_interface = None
    
    return interface_ips

def subnet_mask_to_prefix(subnet_mask):
    try:
        return IPNetwork(f'0.0.0.0/{subnet_mask}').prefixlen
    except Exception as e:
        print(f"Error converting subnet mask {subnet_mask} to prefix length: {e}")
        return None

def retrieve_subnets():
    device = {
        'device_type': device_type,
        'host': hostname,
        'username': username,
        'password': password,
    }

    with ConnectHandler(**device) as ssh_client:
        interface_ips = get_interface_ip_addresses(ssh_client)
        all_subnets = []
        subnet_id = 1

        for interface, (ip, subnet_mask) in interface_ips.items():
            try:
                prefix_len = subnet_mask_to_prefix(subnet_mask)
                if prefix_len is None:
                    continue

                network = IPNetwork(f'{ip}/{prefix_len}')
                for subnet in network.subnet(network.prefixlen):
                    all_subnets.append({'id': subnet_id, 'subnet': str(subnet)})
                    subnet_id += 1
            
            except Exception as e:
                print(f"Error processing IP {ip} with mask {subnet_mask}: {e}")

    return all_subnets

    
@app.route('/broadcast_devices', methods=['GET'])
@login_required
def broadcast_devices():
    def ping_device(ip, new_devices):
        try:
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", "-w", "2000", ip]
            else:
                command = ["ping", "-c", "1", "-W", "2", ip]

            output = subprocess.run(command, capture_output=True, text=True)

            if platform.system() == "Windows":
                if "Request timed out" in output.stdout or "Destination host unreachable" in output.stdout:
                    return
            else:
                if "100% packet loss" in output.stdout or "unreachable" in output.stdout:
                    return

            new_device = {"host": ip, "device_type": "cisco_ios", "username": "admin", "password": "admin"}
            new_devices.append(new_device)
        except Exception as e:
            print(f"An error occurred while pinging {ip}: {e}")

    subnet = request.args.get('subnet')
    if not subnet:
        return jsonify({"status": "error", "message": "Subnet not provided"}), 400

    subnet = ipaddress.ip_network(subnet, strict=False)
    new_devices = []
    threads = []

    for ip in subnet.hosts():
        ip_str = str(ip)
        thread = threading.Thread(target=ping_device, args=(ip_str, new_devices))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

    return jsonify({"status": "success", "new_devices": new_devices})

@app.route('/traceroute', methods=['POST'])
@login_required
def traceroute():
    data = request.json
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({"status": "error", "message": "IP address not provided"}), 400

    try:
        if platform.system() == "Windows":
            command = ["tracert", ip_address]
        else:
            command = ["traceroute", ip_address]

        output = subprocess.run(command, capture_output=True, text=True)
        return jsonify({"status": "success", "output": output.stdout})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

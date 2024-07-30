import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def ssh_connect(hostname, port, username, password, timeout=5):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname, port=port, username=username, password=password, allow_agent=False, timeout=timeout)
        return client
    except Exception as e:
        print(f"Failed to connect to {hostname}: {e}")
        return None

def get_connected_devices(router_ip, username, password):
    client = ssh_connect(router_ip, 22, username, password)
    if not client:
        return None, "SSH session could not be established"
    try:
        stdin, stdout, stderr = client.exec_command('show ip arp')  # Adjust this command based on your router's OS
        stdout.channel.recv_exit_status()  # Ensure the command has completed
        output = stdout.read().decode()
        error = stderr.read().decode()
        if error:
            return None, error

        # Extract IP addresses from the ARP table output
        ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
        devices = ip_pattern.findall(output)
        return devices, None
    except Exception as e:
        return None, str(e)
    finally:
        client.close()

def ping_device(router_ip, username, password, device_ip):
    client = ssh_connect(router_ip, 22, username, password)
    if not client:
        return False, "SSH session could not be established"
    try:
        stdin, stdout, stderr = client.exec_command(f'ping {device_ip}')
        stdout.channel.recv_exit_status()  # Ensure the command has completed
        output = stdout.read().decode()
        error = stderr.read().decode()
        if error:
            return False, error
        
        # Check if the ping was successful by analyzing the output
        if "Success rate is 0 percent" in output:
            return False, output
        return True, output
    except Exception as e:
        return False, str(e)
    finally:
        client.close()

def ping_devices_from_router(router_ip, username, password):
    devices, error = get_connected_devices(router_ip, username, password)
    if error:
        return None, error

    results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_device = {executor.submit(ping_device, router_ip, username, password, device): device for device in devices}
        for future in as_completed(future_to_device):
            device = future_to_device[future]
            try:
                success, output = future.result()
                results[device] = {'success': success, 'output': output}
            except Exception as e:
                results[device] = {'success': False, 'output': str(e)}
    return results, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ping_devices', methods=['POST'])
def ping_devices():
    router_ip = request.form['router_ip']
    username = request.form['username']
    password = request.form['password']

    results, error = ping_devices_from_router(router_ip, username, password)
    if error:
        return jsonify({'error': error})

    return jsonify({'results': results})

if __name__ == "__main__":
    app.run(debug=True)

import netmiko

def send_ping_to_multiple_devices(connection, devices: list):
    result = []
    try:
        for device in devices:
            output = connection.send_command(f"ping {device["host"]}")
            result.append(output)
        return result
    except (netmiko.exceptions.SSHException, netmiko.exceptions.ConnectionException):
        print("Connection failed")
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")

def show_interface_brief(connection):
    result = []
    try:
        output = connection.send_command(f"show ip interface brief")
        return output
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")

def show_inventory(connection):
    result = []
    try:
        output = connection.send_command(f"show inventory")
        return output
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")

def hardware_and_version(connection):
    result = []
    index_for_extract = [0, 3, 5, 6, 8,28,29,30,31,32,33,35]
    try:
        output = str(connection.send_command(f"show hardware")).split("\n")
        output = "".join([output[index]+"\n" for index in index_for_extract])
        return output
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")


if __name__ == "__main__":
    try:

        host1 = {
            "device_type":'cisco_ios',
            "host": '10.10.1.1',
            "username": 'admin',
            "password": 'cisco123',
            }
        host2 = {
            "device_type": 'cisco_ios',
            "host": '10.10.10.2',
            "username": 'admin',
            "password": 'cisco123',
        }

        host3 = {
            "device_type":'cisco_ios',
            "host": '10.10.10.3',
            "username": 'admin',
            "password": 'cisco123',
            }
        devices = [host1, host2, host3]

        with open("outputs.txt", "w") as f:
            for device in devices:
                connection = netmiko.ConnectHandler(**device)
                ping_output_list = send_ping_to_multiple_devices(connection, devices)
                interface_output_list = show_interface_brief(connection)
                hardware_and_version_list = hardware_and_version(connection)
                show_inventory_list = show_inventory(connection)
                f.write("-"*70 + "\n")
                f.write("".join(ping_output_list) + '\n')
                f.write("\n"+interface_output_list + "\n")
                f.write("\n"+hardware_and_version_list + "\n")
                f.write("\n"+show_inventory_list)

                connection.disconnect()
        f.close()
    except Exception as e:
        print(f"An error occurred: {e}")

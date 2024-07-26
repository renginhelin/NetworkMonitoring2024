import netmiko
import threading
import tempfile
import os


def send_ping_to_multiple_devices(connection, devices: list):
    result = []
    try:
        for device in devices:
            output = connection.send_command(f"ping {device['host']}")
            result.append(output)
        return result
    except (netmiko.exceptions.SSHException, netmiko.exceptions.ConnectionException):
        print("Connection failed")
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")


def show_interface_brief(connection):
    try:
        output = connection.send_command("show ip interface brief")
        return output
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")


def show_inventory(connection):
    try:
        output = connection.send_command("show inventory")
        return output
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")


def hardware_and_version(connection):
    index_for_extract = [0, 3, 5, 6, 8, 28, 29, 30, 31, 32, 33, 35]
    try:
        output = connection.send_command("show hardware").split("\n")
        output = "\n".join([output[index] for index in index_for_extract])
        return output
    except netmiko.exceptions.NetMikoTimeoutException:
        print("Timeout")


def thread_function(host, devices: list, tmp_filename):
    with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as tmp:
        connection = netmiko.ConnectHandler(**host)
        ping_output_list = send_ping_to_multiple_devices(connection, devices)
        interface_output_list = show_interface_brief(connection)
        hardware_and_version_list = hardware_and_version(connection)
        show_inventory_list = show_inventory(connection)

        tmp.write("-" * 70 + "\n")
        tmp.write("\n".join(ping_output_list) + '\n')
        tmp.write("\n" + interface_output_list + "\n")
        tmp.write("\n" + hardware_and_version_list + "\n")
        tmp.write("\n" + show_inventory_list)
        tmp.flush()
        connection.disconnect()

        # Store the name of the temporary file
        tmp_filename.append(tmp.name)


if __name__ == "__main__":
    try:
        host1 = {
            "device_type": 'cisco_ios',
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
            "device_type": 'cisco_ios',
            "host": '10.10.10.3',
            "username": 'admin',
            "password": 'cisco123',
        }
        devices = [host1, host2, host3]

        tmp_filenames = []

        t1 = threading.Thread(target=thread_function, args=(host1, devices, tmp_filenames))
        t2 = threading.Thread(target=thread_function, args=(host2, devices, tmp_filenames))
        t3 = threading.Thread(target=thread_function, args=(host3, devices, tmp_filenames))

        t1.start()
        t2.start()
        t3.start()

        t1.join()
        t2.join()
        t3.join()

        # Combine all temporary files into output.txt
        with open("output.txt", "w") as output_file:
            for tmp_filename in tmp_filenames:
                with open(tmp_filename, "r") as tmp_file:
                    output_file.write(tmp_file.read())
                # Optionally, delete the temporary file after reading
                os.remove(tmp_filename)

    except Exception as e:
        print(f"An error occurred: {e}")

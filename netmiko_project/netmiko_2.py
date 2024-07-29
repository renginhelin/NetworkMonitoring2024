import netmiko
import threading
import tempfile
import os
import time


class NetmikoHandler:
    def __init__(self, host):
        self.host = host
        self.connection = None

    def connect(self):
        try:
            self.connection = netmiko.ConnectHandler(**self.host)
        except Exception as e:
            print(f"Connection failed: {e}")

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()

    def send_ping_to_multiple_devices(self, devices: list):
        result = []
        try:
            for device in devices:
                output = self.connection.send_command(f"ping {device['host']}")
                result.append(output)
            return result
        except (netmiko.exceptions.SSHException, netmiko.exceptions.ConnectionException):
            print("Connection failed")
        except netmiko.exceptions.NetMikoTimeoutException:
            print("Timeout")

    def show_interface_brief(self):
        try:
            output = self.connection.send_command("show ip interface brief")
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            print("Timeout")

    def show_inventory(self):
        try:
            output = self.connection.send_command("show inventory")
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            print("Timeout")

    def show_hardware_and_version(self):
        index_for_extract = [0, 3, 5, 6, 8, 28, 29, 30, 31, 32, 33, 35]
        try:
            output = self.connection.send_command("show hardware").split("\n")
            output = "\n".join([output[index] for index in index_for_extract])
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            print("Timeout")

    def show_arp_table(self):
        try:
            output = self.connection.send_command("show arp")
            return output
        except netmiko.exceptions.NetMikoTimeoutException:
            print("Error on show arp table")


def thread_function(host:dict, devices: list, tmp_filename):
    total_time = 0
    handler = NetmikoHandler(host)
    start_time = time.time()
    handler.connect()
    end_time = time.time()
    total_time += end_time - start_time
    print(f"1-host {host["host"]}   {start_time - end_time}")

    if handler.connection:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as tmp:
            start_time = time.time()
            ping_output_list = handler.send_ping_to_multiple_devices(devices)
            end_time = time.time()
            total_time += end_time - start_time
            print(f"2-host {host["host"]}  {start_time - end_time}")

            start_time = time.time()
            interface_output_list = handler.show_interface_brief()
            hardware_and_version_list = handler.show_hardware_and_version()
            inventory_list = handler.show_inventory()
            arp_table = handler.show_arp_table()
            end_time = time.time()
            total_time += end_time - start_time
            print(f"3-host {host["host"]}   {start_time - end_time}")
            print(f"Total time: {total_time}")
            tmp.write("-" * 70 + "\n")
            tmp.write("\n".join(ping_output_list) + '\n')
            tmp.write("\n" + interface_output_list + "\n")
            tmp.write("\n" + hardware_and_version_list + "\n")
            tmp.write("\n" + inventory_list)
            tmp.write("\n" + arp_table)
            tmp.write("\n")

            tmp.flush()
            handler.disconnect()

            # Store the name of the temporary file
            tmp_filename.append(tmp.name)


if __name__ == "__main__":
    start_time = time.time()
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
        end_time = time.time()
        print(f"execute: {end_time - start_time}")
        print("Successful")
    except Exception as e:
        print(f"An error occurred: {e}")

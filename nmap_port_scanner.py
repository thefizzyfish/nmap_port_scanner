#!/usr/bin/env python3
import os
import re
import subprocess


def all_ports(ip):
    # get the current working directory
    cwd = os.getcwd()
    # construct the output file path
    output_file = os.path.join(cwd, "all-ports.nmap")
    # Print notification
    print(f"[*] Running nmap scan on {ip} to find all open ports.")
    # run nmap scan
    subprocess.run(["nmap", "-p-", "-T4", "-oN", output_file, ip], stdout=subprocess.PIPE)
    # read nmap scan output
    with open(output_file, "r") as file:
        output = file.read()
        # return open ports
        return re.findall(r"(\d+)/tcp\s+open", output)
        


def full_scan(ip):
    # get open ports from all_ports function
    open_ports = all_ports(ip)
    # Print number of open ports found
    print(f"[*] Found {len(open_ports)} open ports on {ip}.")
    # check if no open ports are found
    if not open_ports:
        print("[-] No open ports found.")
        return
    # convert open ports to string
    ports_str = ",".join(open_ports)
    # get the current working directory
    cwd = os.getcwd()
    # construct the output file path
    output_file = os.path.join(cwd, "full-scan.nmap")
    # run full nmap scan
    try:
        print("[*] Running service enumeration scan on open ports:", ports_str)
        subprocess.run(["nmap", "-p", ports_str, "-A", "-T4", "-oN", output_file, ip], stdout=subprocess.PIPE)
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return
    # read nmap scan output
    with open(output_file, "r") as file:
        output = file.read()
        return output

def main():
    ip = input("Enter the IP address: ")
    print(full_scan(ip))

if __name__ == "__main__":
    main()


import subprocess
import re
import os
import socket
import nmap
import bonjour
from scapy.all import *
import requests
from bs4 import BeautifulSoup

def scan_for_cameras(verbose=False):
    """
    Scans for cameras using various techniques.
    Args:
        verbose (bool, optional): If True, prints additional information about the scanning process. Defaults to False.
    Returns:
        list: A list of potential cameras found.
    """
    cameras = []

    # 1. Scan for USB Cameras
    if verbose:
        print("Scanning for USB cameras...")
    try:
        usb_devices = subprocess.check_output(['lsusb']).decode('utf-8')
        usb_camera_regex = re.compile(r'^(.*) (.*): (.*) (.*) (.*)')

        for line in usb_devices.splitlines():
            match = usb_camera_regex.match(line)
            if match:
                # Check for common camera vendor and product IDs
                if match.group(3) in ["046d", "04f2", "05ac", "041e", "03f0", "17e9", "13d3", "045e", "05a9", "0525", "0409", "0424", "040c", "0410", "10c4", "0456", "0483", "0403"]:
                    cameras.append(f"USB Camera: {match.group(1)} {match.group(2)} (Vendor ID: {match.group(3)}, Product ID: {match.group(4)})")
    except FileNotFoundError:
        if verbose:
            print("lsusb command not found. Unable to scan for USB cameras.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for USB cameras: {e}")

    # 2. Scan for Network Cameras using Bonjour (mDNS)
    if verbose:
        print("Scanning for network cameras using Bonjour (mDNS)...")
    try:
        bonjour_services = subprocess.check_output(['avahi-browse', '-a']).decode('utf-8')
        bonjour_camera_regex = re.compile(r'  _rtsp._tcp local (.*) (.*) (.*) (.*)')
        bonjour_camera_regex2 = re.compile(r'  _onvif._tcp local (.*) (.*) (.*) (.*)')

        for line in bonjour_services.splitlines():
            match = bonjour_camera_regex.match(line)
            if match:
                cameras.append(f"Bonjour Camera: {match.group(1)}: {match.group(2)} (Type: RTSP, Address: {match.group(3)}, Port: {match.group(4)})")
            else:
                match = bonjour_camera_regex2.match(line)
                if match:
                    cameras.append(f"Bonjour Camera: {match.group(1)}: {match.group(2)} (Type: ONVIF, Address: {match.group(3)}, Port: {match.group(4)})")
    except FileNotFoundError:
        if verbose:
            print("avahi-browse command not found. Unable to scan for network cameras using Bonjour.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for Bonjour cameras: {e}")

    # 3. Scan for Network Cameras using ARP
    if verbose:
        print("Scanning for network cameras using ARP...")
    try:
        arp_table = subprocess.check_output(['arp', '-a']).decode('utf-8')
        arp_camera_regex = re.compile(r'.*\((.*)\)')

        for line in arp_table.splitlines():
            match = arp_camera_regex.search(line)
            if match:
                ip_address = match.group(1)
                # Check if the IP address is in the range of common network cameras
                if ip_address.startswith('192.168') or ip_address.startswith('10.') or ip_address.startswith('172.16'):
                    cameras.append(f"ARP Camera: {ip_address}")
    except FileNotFoundError:
        if verbose:
            print("arp command not found. Unable to scan for network cameras using ARP.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for ARP cameras: {e}")

    # 4. Scan for Network Cameras using Network IP Range Scanning
    if verbose:
        print("Scanning for network cameras using network IP range scanning...")
    try:
        nm = nmap.PortScanner
        ip_ranges = ["192.168.0.0/24", "10.0.0.0/24", "172.16.0.0/12"]

        for ip_range in ip_ranges:
            nm = nmap.PortScanner() 
            nm.scan(hosts=ip_range, arguments='-sT -p 80,8080,554,555,8000,8001,8008,81,8090,8091 -T4')

            for ip_address in nm.all_hosts():
                if nm[ip_address]['status']['state'] == 'up':
                    for port in nm[ip_address]['tcp'].keys():
                        if port in [80, 8080, 554, 555, 8000, 8001, 8008, 81, 8090, 8091]:
                            cameras.append(f"Network Camera: {ip_address}: {port}")
    except FileNotFoundError:
        if verbose:
            print("nmap or bonjour command not found. Unable to scan for network cameras using network discovery protocols.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for network cameras using IP range scanning: {e}")

    # 5. Scan for Network Cameras using Port Scanning
    if verbose:
        print("Scanning for network cameras using port scanning...")
    try:
        nm = nmap.PortScanner

        camera_ports = [80, 8080, 554, 555, 8000, 8001, 8008, 81, 8090, 8091, 8098, 8099, 8081, 8089, 9000, 9001, 9090, 8023, 8024, 9091]

        interfaces = socket.getaddrinfo(socket.gethostname(), None)
        for interface in interfaces:
            if interface == socket.AF_INET:
                network = interface
                network_regex = re.compile(r'\d+\.\d+\.\d+\.')
                network_ip = network_regex.search(network).group(0)

                nm.scan(hosts=network_ip + "0/24", arguments='-sT -p ' + ",".join(str(port) for port in camera_ports) + ' -T4')

                for ip_address in nm.all_hosts():
                    if nm[ip_address]['status']['state'] == 'up':
                        for port in nm[ip_address]['tcp'].keys():
                            if port in camera_ports:
                                cameras.append(f"Network Camera: {ip_address}: {port}")
    except FileNotFoundError:
        if verbose:
            print("nmap command not found. Unable to scan for network cameras using port scanning.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for network cameras using port scanning: {e}")

    # 6. Scan for Network Cameras using Known Camera URLs
    if verbose:
        print("Scanning for network cameras using known camera URLs...")
    try:
        camera_urls = [
            "http://{ip_address}/",
            "http://{ip_address}/axis-cgi/admin/index.cgi",
            "http://{ip_address}/admin/",
            "http://{ip_address}/view/index.shtml",
            "http://{ip_address}/cgi-bin/viewer/video.jpg",
            "http://{ip_address}/cgi-bin/snapshot.cgi",
            "http://{ip_address}/mjpg/video.mjpg",
            "http://{ip_address}/videostream.cgi",
            "http://{ip_address}/onvif/device.xml",
            "rtsp://{ip_address}/live",
            "rtsp://{ip_address}/h264",
            "rtsp://{ip_address}/media",
            "rtsp://{ip_address}/stream1",
            "rtsp://{ip_address}/stream2",
            "rtsp://{ip_address}/stream3"
        ]

        interfaces = socket.getaddrinfo(socket.gethostname(), None)
        for interface in interfaces:
            if interface == socket.AF_INET:
                network = interface
                network_regex = re.compile(r'\d+\.\d+\.\d+\.')
                network_ip = network_regex.search(network).group(0)

                for camera_url in camera_urls:
                    try:
                        url = camera_url.format(ip_address=network_ip + "1")
                        response = subprocess.check_output(['curl', '-s', '-m', '5', url]).decode('utf-8')

                        if "Axis" in response or "Foscam" in response or "Dahua" in response or "Hikvision" in response or "Amcrest" in response or "Reolink" in response or "IP Camera" in response or "onvif" in response or "rtsp" in response:
                            cameras.append(f"Network Camera: {network_ip + '1'} (URL: {url})")
                    except subprocess.CalledProcessError:
                        pass
    except FileNotFoundError:
        if verbose:
            print("curl command not found. Unable to scan for network cameras using known camera URLs.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for network cameras using known camera URLs: {e}")

    # 7. Scan for Network Cameras using Network Discovery Protocols
    if verbose:
        print("Scanning for network cameras using network discovery protocols...")
    try:
        nm = nmap.PortScanner

        camera_ports = [80, 8080, 554, 555, 8000, 8001, 8008, 81, 8090, 8091]

        interfaces = socket.getaddrinfo(socket.gethostname(), None)
        for interface in interfaces:
            if interface == socket.AF_INET:
                network = interface
                network_regex = re.compile(r'\d+\.\d+\.\d+\.')
                network_ip = network_regex.search(network).group(0)

                nm.scan(hosts=network_ip + "0/24", arguments='-sT -p ' + ",".join(str(port) for port in camera_ports) + ' -T4')

                # Check for ONVIF Discovery
                try:
                    service_info = bonjour.DNSService
                    regtype='_onvif._tcp'
                    domain='local.';
                    port=0;
                    name='';
                    type=bonjour.kDNSServiceType_SRV;
                    interfaceIndex=interface;
                    flags=0;
                    serviceName=None;
                    serviceType=None;
                    servicePort=None;
                    serviceInstance=None;
                    serviceDomain=None;
                    serviceText=None;
                    serviceTTL=None;
                    serviceProperties=None
                    service_info.start()
                    while True:
                        # Receive ONVIF discovery response
                        (_, flags, hostname, service, port, text) = service_info.get()
                        if network_ip == hostname:
                            cameras.append(f"Network Camera: {network_ip} (Protocol: ONVIF)")
                            break
                except Exception as e:
                    if verbose:
                        print(f"Error scanning for ONVIF cameras: {e}")

                # Check for RTSP Discovery
                try:
                    service_info = bonjour.DNSService
                    regtype='_rtsp._tcp'
                    domain='local.';
                    port=0;
                    name='';
                    type=bonjour.kDNSServiceType_SRV;
                    interfaceIndex=interface;
                    flags=0;
                    serviceName=None;
                    serviceType=None;
                    servicePort=None;
                    serviceInstance=None;
                    serviceDomain=None;
                    serviceText=None;
                    serviceTTL=None;
                    serviceProperties=None
                    service_info.start()
                    while True:
                        # Receive RTSP discovery response
                        (_, flags, hostname, service, port, text) = service_info.get()
                        if network_ip == hostname:
                            cameras.append(f"Network Camera: {network_ip} (Protocol: RTSP)")
                            break
                except Exception as e:
                    if verbose:
                        print(f"Error scanning for RTSP cameras: {e}")

    except FileNotFoundError:
        if verbose:
            print("nmap or bonjour command not found. Unable to scan for network cameras using network discovery protocols.")
    except Exception as e:
        if verbose:
            print(f"Error scanning for network cameras using network discovery protocols: {e}")

    # 8. Scan for Cloud Cameras
    if verbose:
        print("Scanning for cloud cameras...")
    try:
        cloud_camera_platforms = [
            "https://www.example.com",  # Replace with actual cloud camera platform URLs
            "https://www.anotherplatform.com",
            "https://www.yetanotherplatform.com"
        ]

        for platform in cloud_camera_platforms:
            response = requests.get(platform)
            soup = BeautifulSoup(response.content, 'html.parser')

            camera_elements = soup.find_all('div', class_='camera')  # Adjust selector as needed
            for camera_element in camera_elements:
                camera_name = camera_element.find('h2').text  # Adjust selectors as needed
                camera_url = camera_element.find('a', href=True)['href']  # Adjust selectors as needed
                cameras.append(f"Cloud Camera: {camera_name} (URL: {camera_url})")
    except Exception as e:
        if verbose:
            print(f"Error scanning for cloud cameras: {e}")

    if verbose:
        print("Scanning completed. Found Cameras:")
        for camera in cameras:
            print(camera)
    return cameras

# Example usage:
scan_for_cameras(verbose=True) 

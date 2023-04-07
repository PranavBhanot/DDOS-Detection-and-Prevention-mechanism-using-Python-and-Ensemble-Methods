# https://github.com/anapeksha/python-proxy-server/blob/main/src/server.py
import socket
import sys
import threading
import pickle
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import time
from util import ip

WEBSERVER_IP = "127.0.0.1"
WEBSERVER_PORT = 8080
PORT = 3500

MAX_CONNECTIONS = 25000
buffer_size = 8192*2


threads = []
_running = True
model = None
packetsCount = 0
startTime = 0

_lock = threading.Lock()


def timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


def start():
    global _running
    global startTime
    global packetsCount

    try:
        clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSock.bind(('', PORT))
        clientSock.listen(MAX_CONNECTIONS)
        print(f"Proxy listening on port {PORT}")
        startTime = time.time()
    except Exception as e:
        _running = False
        sys.exit(0)

    try:
        while _running:
            conn, clientAddr = clientSock.accept()
            data = conn.recv(buffer_size)
            host = data.decode().split("Host: ")[1].split("\r\n")[0].split(":")[0]
            if host == "localhost":
                host = "127.0.0.1"
            isDDOSAttack = isDDOS(
                host,
                conn.getsockname()[0],
                clientAddr[1],
                len(data),
                packetsCount / (time.time() - startTime))
            if isDDOSAttack:
                print(f"[{timestamp()}] Got new proxy request ({host}, {clientAddr[1]}) ---- !!!!! Got DDOS")
                conn.close()
            else:
                packetsCount += 1
                print(f"[{timestamp()}] Got new proxy request {clientAddr}")
                thread = threading.Thread(target=proxyRequest, args=(conn, data, clientAddr))
                threads.append(thread)
                thread.start()
        clientSock.close()
        sys.exit(0)
    except KeyboardInterrupt:
        print("Exiting...")
        _running = False
        clientSock.close()
        for thread in threads:
            thread.join()
        sys.exit(0)


def proxyRequest(conn, data, clientAddr):
    global model
    global startTime
    global _lock
    global packetsCount

    try:
        with _lock:
            srcIP = clientAddr[0]
            srcPort = clientAddr[1]
            packetLen = len(data)
            packetsCount += 1
            packetsSec = packetsCount / (time.time() - startTime)
            isDDOSAttack = isDDOS(srcIP, WEBSERVER_IP, srcPort, packetLen, packetsSec)
            if isDDOSAttack:
                print(
                    f"Got DDOS request from {srcIP}:{srcPort} at ${time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
            else:
                proxyToServer(WEBSERVER_IP, WEBSERVER_PORT, conn, clientAddr, data)
    except Exception as e:
        pass


def isDDOS(srcIP, dstIP, srcPort, packetLen, packetsSec):
    dstIP = "127.0.0.1" if dstIP == "localhost" else dstIP
    df = pd.DataFrame([{
        "src_port": srcPort,
        "pkt_len": packetLen,
        "pkts_per_sec": packetsSec,
        "src_ip": srcIP,
        "dst_ip": dstIP
    }], columns=["src_port", "pkt_len", "pkts_per_sec", "src_ip", "dst_ip"])
    df[["src_ip_a", "src_ip_b", "src_ip_c", "src_ip_d"]
       ] = df.src_ip.str.split(".", expand=True)
    df[["dst_ip_a", "dst_ip_b", "dst_ip_c",
        "dst_ip_d"]] = df.dst_ip.str.split(".", expand=True)
    df = df.drop(columns=["src_ip", "dst_ip", ])
    preds = model.predict(df)
    return ip(srcIP, dstIP, srcPort, packetLen, packetsSec, preds)


def proxyToServer(webserver, port, conn, addr, data):
    global _running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((webserver, port))
        sock.send(data)

        while _running:
            reply = sock.recv(buffer_size)
            if (len(reply) > 0):
                conn.send(reply)

                dar = float(len(reply))
                dar = float(dar/1024)
                dar = "%.3s" % (str(dar))
                dar = "%s KB" % (dar)
                print("Request Done: %s => %s <=" % (str(addr[0]), str(dar)))
            else:
                break
        sock.close()
        conn.close()
    except socket.error as err:
        sock.close()
        conn.close()
        sys.exit(1)


if __name__ == "__main__":
    print("Loading model...")
    with open("./proxy/model.pkl", "rb") as f:
        model = pickle.load(f)
        start()

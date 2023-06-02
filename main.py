import faulthandler
import datetime
import arrow
import socket
import os
from binascii import hexlify
import sys
from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from PyQt5.QtWidgets import QTextBrowser
from gui1 import *
from scapy.all import conf as scapyconf
from scapy.layers import inet, l2


class Statistics():
    def __init__(self):
        self.eth = 0
        self.ip = 0
        self.tcp = 0
        self.udp = 0
        self.arp = 0
        self.icmp = 0
        self.http = 0
        self.https = 0
    def update(self, eth, ip, tcp, udp, arp, icmp, http, https):
        self.eth += eth
        self.ip += ip
        self.tcp += tcp
        self.udp += udp
        self.arp += arp
        self.icmp += icmp
        self.http += http
        self.https += https
    def reset(self):
        self.eth = 0
        self.ip = 0
        self.tcp = 0
        self.udp = 0
        self.arp = 0
        self.icmp = 0
        self.http = 0
        self.https = 0

class Switch():
    def __init__(self, mac, st):
        self.mac_table = mac
        self.st = st
        self.ui = None
        self.stop1 = False
        self.stop2 = False
        self.last_sent_packet = None
        self.temp_packets = []
        self.timer = 300
        self.eth0 = ""
        self.eth1 = ""
        self.thread1 = threading.Thread(target=self.capture1)
        self.thread2 = threading.Thread(target=self.capture2)
        self.status = False
        self.syslog = False
        self.syslog_src_ip = ""
        self.syslog_dst_ip = ""
        self.syslog_interface = 0
        self.filters = []
        self.allow_int1 = False
        self.allow_int2 = False


    def start_capture(self):
        if self.eth0 == "" or self.eth1 == "" or self.eth0 == self.eth1:
            print("zle vybraty interface")
            print(self.eth0, self.eth1)
            return
        self.status = True
        self.thread1.start()
        self.thread2.start()
        self.send_syslog("start")

    def stop_capture(self):
        self.status = False
        print("zastavujem 1.")
        self.thread1.join()
        print("zastavujem 2.")
        self.thread2.join()
        print("konec")
        self.send_syslog("stop")

    def stop_filter(self, pkt):
        if self.status:
            return False
        else:
            return True


    def packet_test(self, packet, input_iface):
        print(packet.summary)
        try:
            dst_mac = packet[Ether].dst
            src_mac = packet[Ether].src
        except:
            return

        if (dst_mac == "00-e0-4c-3f-c6-47" or dst_mac == "98:fa:9b:26:86:5f"):   #pridať mac adresy interfacov
            return
        if packet in self.temp_packets:
            self.temp_packets.remove(packet)
            return
        if(self.filter_packets(input_iface, "IN", packet)) is False:
            return

        if input_iface == self.eth0:   # Interface 0 in
            self.mac_table.reset_int_timer(self.eth0)
            self.stats(packet, self.st[0])
            if Ether in packet:
                src_mac = packet[Ether].src
                record = Mac_record(src_mac, self.eth0, self.timer)
                self.mac_table.update_table(record, self.timer)
                output_iface = self.mac_table.where_forward(packet[Ether].dst)
                if output_iface == False:
                    output_iface = self.eth1
            else:
                return

            self.stop2 = True
        elif input_iface == self.eth1:   # Interface 1 in
            self.mac_table.reset_int_timer(self.eth1)
            self.stats(packet, self.st[2])
            if Ether in packet:
                src_mac = packet[Ether].src
                record = Mac_record(src_mac, self.eth1, self.timer)
                self.mac_table.update_table(record, self.timer)
                output_iface = self.mac_table.where_forward(packet[Ether].dst)
                if output_iface == False:
                    output_iface = self.eth0
            else:
                print("jako")
                return

            self.stop1 = True
        elif input_iface == "syslog1":
            output_iface = self.eth0
        elif input_iface == "syslog2":
            output_iface = self.eth1

        else:
            return
        #if last_sent_packet is not None and packet == last_sent_packet:
        #    print("Packet already sent.")
        #    return
       #if(self.temp_packets[i] == packet):
       #         self.temp_packets.pop(i)
       #         return
        if self.filter_packets(output_iface, "OUT", packet) is False:
            return
        self.temp_packets.append(packet)

        sendp(packet, iface = output_iface, verbose=False)
        if input_iface==self.eth0:
            #stop2=False
            self.stats(packet, self.st[3])
        if input_iface==self.eth1:
            #stop1=False
            self.stats(packet, self.st[1])

    def capture1(self):
        while self.status:
            print("capturing 1")
            if self.stop1:
                return
            sniff(iface=self.eth0, promisc = True, stop_filter = self.stop_filter, prn=lambda pkt: self.packet_test(pkt, self.eth0))
        return

    def capture2(self):
        while self.status:
            print("capturing 2")
            if self.stop2:
                return
            sniff(iface=self.eth1, promisc = True, stop_filter = self.stop_filter,  prn=lambda pkt: self.packet_test(pkt, self.eth1))
        return

    def send_syslog(self, action):
        if self.syslog:
            dst_mac = "ff:ff:ff:ff:ff:ff"
            ip = inet.IP(src=self.syslog_src_ip, dst=self.syslog_dst_ip)
            udp = inet.UDP(sport=514, dport=514)
            eth = l2.Ether(dst=dst_mac)
            timestamp = arrow.now()
            formatted_timestamp = timestamp.format('YYYY-MM-DD HH:mm:ss')
            pid = str(os.getpid())
            if action == "start":
                print("STARTED CAPTURING")
                message = "<1>", formatted_timestamp, " switch ", pid, " - Device started capturing"
                message = "".join(message)
            elif action == "stop":
                message = "<1>", formatted_timestamp, " switch ", pid, " - Device stopped capturing"
                message = "".join(message)
            elif action == "clear mac":
                message = "<3>", formatted_timestamp, " switch ", pid, " - Mac table cleared"
                message = "".join(message)
            elif action == "add filter":
                message = "<2>", formatted_timestamp, " switch ", pid, " - Filter added"
                message = "".join(message)
            elif action == "cable changed":
                message = "<2>", formatted_timestamp, " switch ", pid, " - Cable changed"
                message = "".join(message)
            pkt = eth/ip/udp/message
            if self.syslog_interface == 1:
                self.packet_test(pkt, "syslog1")
            elif self.syslog_interface == 2:
                self.packet_test(pkt, "syslog2")
        else:
            return


    def filter_packets(self, interface, direction, packet):
        dst_mac = packet[Ether].dst
        src_mac = packet[Ether].src
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        except:
            src_ip = ""
            dst_ip = ""
        if packet.haslayer(TCP):
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
        elif packet.haslayer(UDP):
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
        else:
            src_port = None
            dst_port = None

        for i in range(len(self.filters)):
            if(self.filters[i][0] == "Interface 1"):
                interface_filter = self.eth0
            elif (self.filters[i][0] == "Interface 2"):
                interface_filter = self.eth1
            if interface_filter == interface:
                if interface_filter == self.eth0 and self.filters[i][2] == "Allow":
                    self.allow_int1 = True
                if interface_filter == self.eth1 and self.filters[i][2] == "Allow":
                    self.allow_int2 = True
                if direction == self.filters[i][1]:
                    if self.filters[i][2] == "Deny":
                        if (self.filters[i][3] == '' or self.filters[i][3] == src_port or self.filters[i][3] == dst_port or (self.filters[i][3] == "ping" and packet.haslayer(ICMP) is True)) and \
                                (self.filters[i][4] == '' or self.filters[i][4] == src_mac) and \
                                (self.filters[i][5] == '' or self.filters[i][5] == dst_mac) and \
                                (self.filters[i][6] == '' or self.filters[i][6] == src_ip) and \
                                (self.filters[i][7] == '' or self.filters[i][7] == dst_ip):
                            print("Packet dropped")
                            self.allow_int1 = False
                            self.allow_int2 = False
                            return False
                    if self.filters[i][2] == "Allow":
                        if (self.filters[i][3] == '' or self.filters[i][3] == src_port or self.filters[i][3] == dst_port or (self.filters[i][3] == "ping" and packet.haslayer(ICMP) is True)) and \
                                (self.filters[i][4] == '' or self.filters[i][4] == src_mac) and \
                                (self.filters[i][5] == '' or self.filters[i][5] == dst_mac) and \
                                (self.filters[i][6] == '' or self.filters[i][6] == src_ip) and \
                                (self.filters[i][7] == '' or self.filters[i][7] == dst_ip):
                            self.allow_int1 = False
                            self.allow_int2 = False
                            return True

        if interface == self.eth0:
            if self.allow_int1:
                self.allow_int1 = False
                print("Packet dropped")
                return False
        elif interface == self.eth1:
            if self.allow_int2:
                self.allow_int2 = False
                print("Packet dropped")
                return False
        return True




    def stats(self, packet, st):
        ether = 0
        ip = 0
        tcp = 0
        udp = 0
        arp = 0
        icmp = 0
        http = 0
        https = 0
        is_eth = Ether(packet)
        eth = packet
        if is_eth:
            ether += 1
        if IP in eth:
            ip += 1
        if TCP in eth:
            tcp += 1
        if UDP in eth:
            udp += 1
        if ARP in eth:
            arp += 1
        if ICMP in eth:
            icmp += 1
        if eth.haslayer(TCP) and eth.haslayer(Raw):
            if eth[TCP].dport == 80 or eth[TCP].sport == 80:
                http += 1
            else:
                pass
        if eth.haslayer(TCP):
            if eth[TCP].dport == 443 or eth[TCP].sport == 443:
                https += 1
            else:
                pass
        else:
            pass
        st.update(ether, ip, tcp, udp, arp, icmp, http, https)

def create_ListOfStats():
    zoz = []
    st1_IN = Statistics()
    zoz.append(st1_IN)
    st1_OUT = Statistics()
    zoz.append(st1_OUT)
    st2_IN = Statistics()
    zoz.append(st2_IN)
    st2_OUT = Statistics()
    zoz.append(st2_OUT)
    return zoz



class Mac_record():
    def __init__(self, mac_address, port, time):
        self.mac_address = mac_address
        self.port = port
        self.timer = time

class Mac_Table():
    def __init__(self):
        self.mac_rows = []
        self.eth0_timer = 6
        self.eth1_timer = 6
        self.int0 = ""
        self.int1 = ""
        self.changed = False


    def update_table(self, record, time):
        for i in range(len(self.mac_rows)):
            if (record.mac_address == self.mac_rows[i].mac_address):
                if (record.port == self.mac_rows[i].port):
                    self.mac_rows[i].timer = time
                    return
                else:
                    self.changed = True
                    self.mac_rows[i].port = record.port
                    self.mac_rows[i].timer = 300
                    return
        self.mac_rows.append(record)

    def where_forward(self, mac):
        if mac == "ff:ff:ff:ff:ff:ff":
            return False
        for i in range(len(self.mac_rows)):
            if mac == self.mac_rows[i].mac_address:
                return self.mac_rows[i].port
        return False

    def reset_int_timer(self, interface):
        if interface == self.int0:
            self.eth0_timer = 6
        if interface == self.int1:
            self.eth1_timer = 6

    def decrement_timer(self):
        self.eth0_timer -= 1
        self.eth1_timer -= 1
        list = []
        list1 = []
        if self.eth0_timer == 0:
            for i in range(len(self.mac_rows)):
                if self.mac_rows[i].port == self.int0:
                    list.append(i)
            for index in sorted(list, reverse=True):
                self.mac_rows.pop(index)
        if self.eth1_timer == 0:
            for i in range(len(self.mac_rows)):
                if self.mac_rows[i].port == self.int1:
                    list1.append(i)
            for index in sorted(list1, reverse=True):
                self.mac_rows.pop(index)
        for i in range(len(self.mac_rows)):
            self.mac_rows[i].timer -= 1
            if self.mac_rows[i].timer == 0:
                self.mac_rows.pop(i)
                break

        threading.Timer(1, self.decrement_timer).start()


def main():
    st = create_ListOfStats()
    mac_table = Mac_Table()
    mac_table.decrement_timer()
    app = QtWidgets.QApplication(sys.argv)
    faulthandler.enable()
    MainWindow = QtWidgets.QMainWindow()
    QtWidgets.qApp.processEvents()
    switch = Switch(mac_table, st)
    ui = Ui_MainWindow(st, mac_table, switch)
    ui.setupUi(MainWindow)
    MainWindow.show()
    ui.updater()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
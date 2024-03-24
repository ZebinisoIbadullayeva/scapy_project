# scapy_project
# установить инструмент Npcap:
# https://npcap.com/#download

# установить библиотеку Scapy
$ pip install scapy

# импорт библиотека Scapy и несколькими его протоколами
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# импортируйте библиотеку Tkinter для графического интерфейса
from tkinter import *

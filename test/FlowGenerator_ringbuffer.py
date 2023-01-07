from scapy.all import *
import libpcap
import pyshark
import os
import glob

T_SHARK_PATH = r'D:\CTF Software\Wireshark\tshark.exe'
IFACE = r'\Device\NPF_{EF585BC3-9FC4-4DFC-B37C-689355D94B00}'

TEMP_NAME = r'temp'
TEMP_PATH = r'../capture\\'
TEMP_FILE = TEMP_PATH + TEMP_NAME + '.pcap'
RING_SIZE = 1024

# def pktsgenrate():
#     packets = sniff(iface=r'\Device\NPF_{EF585BC3-9FC4-4DFC-B37C-689355D94B00}',count=100,)
#     wrpcap("temp.pcap", packets)


# def check_file(cap_prex: int):
#
#     full_name = glob.glob(pathname=TEMP_PATH + TEMP_NAME + '_*'+format(cap_prex, '05d')+'_*')
#     next = (glob.glob(pathname=TEMP_PATH + TEMP_NAME + '_*'+format(cap_prex+1, '05d')+'_*') is not None)
#     if full_name is not None:
#         if os.path.getsize(full_name[0]) / 1000 >= RING_SIZE and next:
#             return True
#     else:
#         return False


def tsharkgenerator():
    capture = pyshark.LiveRingCapture(interface=IFACE,
                                      tshark_path=T_SHARK_PATH,
                                      ring_file_name=TEMP_FILE,
                                      ring_file_size=RING_SIZE,
                                      )
    capture.sniff()
    # print(capture.ring_file_name())
    # check_state(capture.ring_file_name())

    # capture = pyshark.LiveCapture(interface=r'\Device\NPF_{EF585BC3-9FC4-4DFC-B37C-689355D94B00}',
    #                               tshark_path=T_SHARK_PATH,
    #                               output_file=r'.\capture\temp.pcap'
    #                               )
    # capture.sniff(timeout=50)

if __name__ == '__main__':
    # tsharkgenerator()
    # check_file('')
    pass
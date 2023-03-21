import pandas as pd
from scapy.all import *
import libpcap
import pyshark
import os
import logging
from threading import Thread
from multiprocessing import Process, Queue
import nfstream
import glob
import time
from pcap import pcap
from preparedumps import dump_pipeline
from MachineProcessor import MLProcessor
from preprocessing import constants

# Cancel future version warning
from warnings import simplefilter

simplefilter(action='ignore', category=FutureWarning)

# Some global definition
LOGGING_PATH = r"logs\\"
T_SHARK_PATH = r'D:\CTF Software\Wireshark\tshark.exe'
IFACE = r'\Device\NPF_{FC79931E-6347-40CF-95A0-E16E915BCF66}'
TEMP_PRX = r'capture'
TEMP_DIR = r'capture\\'
TEMP_NAME = TEMP_DIR + TEMP_PRX + '.pcap'
RING_SIZE = 10240 * 2

info_que = Queue()
cont_que = Queue()
log_queue = Queue()


# def pktsgenrate():
#     packets = sniff(iface=r'\Device\NPF_{EF585BC3-9FC4-4DFC-B37C-689355D94B00}',count=100,)
#     wrpcap("temp.pcap", packets)



def del_file(path: str):
    """Delete all out-dated files"""
    ls_ = os.listdir(path)
    for i in ls_:
        c_path = os.path.join(path, i)
        if os.path.isdir(c_path):
            del_file(c_path)
        else:
            os.remove(c_path)
    print("Files are all removed!")


def init_folder(path: str):
    """ Clear all files that created in last turn"""
    print("Checking the folder...")
    if len(os.listdir(path)) != 0:
        del_file(path)
    print("Finish checking.")


def check_file(que: Queue):
    """Scan the files created by captor thread"""
    cap_prex = 1
    start = time.perf_counter()
    print(f'start: {start}')
    while True:
        # Match the file with the same name in the folder to check that the pcap has been captured periodical
        full_name = glob.glob(pathname=TEMP_DIR + TEMP_PRX + '_*' + format(cap_prex, '05d') + '_*')
        next_exist = glob.glob(pathname=TEMP_DIR + TEMP_PRX + '_*' + format(cap_prex + 1, '05d') + '_*')
        if full_name:
            # Ensure filesize satisfies the required size and new file is being created
            # if os.path.getsize(full_name[0]) / 1000 >= RING_SIZE and next_exist:
            if next_exist:
                que.put(full_name[0])
                end = time.perf_counter()
                print(f"S1: {end}  {os.path.getsize(full_name[0]) / 1000} KB")
                # print(f"{full_name[0]} {os.path.getsize(full_name[0]) / 1000} KB")
                cap_prex += 1
        else:
            time.sleep(0.1)


def tshark_generator():
    """create packets file with fixed filesize, default = RING_SIZE KB"""
    capture = pyshark.LiveRingCapture(interface=IFACE,
                                      tshark_path=T_SHARK_PATH,
                                      ring_file_name=TEMP_NAME,
                                      ring_file_size=RING_SIZE,
                                      bpf_filter='host 10.208.19.21 and !arp',
                                      num_ring_files=1000,
                                      )
    capture.sniff()


# 服务器端: sudo tcpreplay -i eth0 -M 2 ./rewrite_2021_12_28_Active.pcap.pcap
#          sudo tcpreplay -i eth0 ./replay2host/rewrite_NetatmoCamTCPFlood_3.pcap.pcap

def tshark_generator_fixsec():
    """create packets file with fixed timeout"""
    capture = pyshark.LiveCapture(interface=IFACE,
                                  tshark_path=T_SHARK_PATH,
                                  bpf_filter='host 192.168.0.115 and !arp',
                                  custom_parameters={'-b': 'duration:7', '-w': TEMP_NAME},
                                  )
    capture.sniff()


def nfstream_process(que_1: Queue, que_2: Queue):
    """Flow processing thread"""
    while True:
        if not que_1.empty():
            # print(f"waiting flow process {que_1.qsize()} files")
            # Achieve the data from queue
            # Send variable que_1.get() address information to message
            message = que_1.get()
            # print(message, flush=True)
            # print(f"Flow process:{message[11:]}")

            start = time.time()
            #stc_raw = nfstream.NFStreamer(source=message, statistical_analysis=True, )
            stc_df = nfstream.NFStreamer(source=message, statistical_analysis=True, ).to_pandas()
            end = time.time()

            print(f"S2: {end - start}  {stc_df.__sizeof__()} B")

            que_2.put(stc_df)
            # If you want to save the flow data, you can use "stc_csv = stc_raw.to_csv()" to save


def processML(que: Queue):
    """Machine Learning Detection Module"""
    mlengine = MLProcessor()
    while True:
        if not que.empty():
            real_df = que.get()
            dec_info = []
            # pred is np.narray type

            start = time.perf_counter()
            pred = mlengine.predict(real_df)
            end = time.perf_counter()

            print(f"S3: {end - start}\n")
            # row is pandas.Series type
            for _, row in real_df.iterrows():
                dec_info.append(parsePredictionDF(row))
            # display_log_data(pred, dec_info)


def display_log_data(pred, dec_info: list):
    """"Display the detection result and log in file"""
    for index in range(len(dec_info)):
        if pred[index] == 0:
            print("ANOMALY: %s" % dec_info[index])
            # logging.warning("ANOMALY: %s" % dec_info[index])
        else:
            print("BENIGN: %s" % dec_info[index])
            # logging.info("BENIGN: %s" % dec_info[index])
    print("\n")


def parsePredictionDF(dataframe):
    """Process the info of flows"""
    src_ip = dataframe["src_ip"]
    src_port = dataframe["src_port"]
    dst_ip = dataframe["dst_ip"]
    dst_port = dataframe["dst_port"]
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    return "%s %s:%s => %s:%s" % (timestamp, src_ip, src_port, dst_ip, dst_port)


def prepareDumps():
    """Prepare the preprocessing dumps with joblib"""
    if dump_pipeline.createDumps():
        print("Pipeline dumps were created Successfully")
    else:
        print("Error in creation of pipeline dumps")



if __name__ == '__main__':
    # Initialization procedure
    print("***********************************************")
    prepareDumps()
    init_folder(TEMP_DIR)
    # Launch scan_thread, flow_thread, det_thread, tshark_generator to execute detection procedure
    scan_thread = Process(target=check_file, args=(info_que,))
    flow_thread = Process(target=nfstream_process, args=(info_que, cont_que))
    det_thread = Process(target=processML, args=(cont_que,))
    scan_thread.start()
    flow_thread.start()
    det_thread.start()
    print("Detection procedures are activated!")
    print("***********************************************")
    tshark_generator_fixsec()
    # tshark_generator()

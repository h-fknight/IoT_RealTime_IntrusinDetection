import pandas as pd
from scapy.all import *
import libpcap
import pyshark
import os
import logging
from threading import Thread
import queue
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
LOGGING_PATH = r".\logs\\"
T_SHARK_PATH = r'D:\CTF Software\Wireshark\tshark.exe'
IFACE = r'\Device\NPF_{EF585BC3-9FC4-4DFC-B37C-689355D94B00}'
TEMP_PRX = r'capture'
TEMP_DIR = r'.\\capture\\'
TEMP_NAME = TEMP_DIR + TEMP_PRX + '.pcap'
RING_SIZE = 1024


info_que = queue.Queue()
cont_que = queue.Queue()
log_queue = queue.Queue()

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


def check_file(que: queue.Queue):
    """Scan the files created by captor thread"""
    cap_prex = 1
    while True:
        # Match the file with the same name in the folder to check that the pcap has been captured periodical
        full_name = glob.glob(pathname=TEMP_DIR + TEMP_PRX + '_*' + format(cap_prex, '05d') + '_*')
        next_exist = glob.glob(pathname=TEMP_DIR + TEMP_PRX + '_*' + format(cap_prex + 1, '05d') + '_*')
        if full_name:
            # Ensure filesize satisfies the required size and new file is being created
            if os.path.getsize(full_name[0]) / 1000 >= RING_SIZE and next_exist:
                que.put(full_name[0])
                print(f"{full_name[0]} {os.path.getsize(full_name[0]) / 1000} KB")
                cap_prex += 1
        else:
            time.sleep(0.5)


def tshark_generator():
    """create packets file with fixed filesize, default = RING_SIZE KB"""
    capture = pyshark.LiveRingCapture(interface=IFACE,
                                      tshark_path=T_SHARK_PATH,
                                      ring_file_name=TEMP_NAME,
                                      ring_file_size=RING_SIZE,
                                      num_ring_files=1000,
                                      )
    capture.sniff()


def nfstream_process(que_1: queue.Queue, que_2: queue.Queue):
    """Flow processing thread"""
    while True:
        if not que_1.empty():
            print(f"waiting flow process {que_1.qsize()} files")
            # Achieve the data from queue
            # Send variable que_1.get() address information to message
            message = que_1.get()
            # print(message, flush=True)
            # print(f"Flow process:{message[11:]}")
            stc_raw = nfstream.NFStreamer(source=message, statistical_analysis=True)
            stc_df = stc_raw.to_pandas()
            que_2.put(stc_df)
            # If you want to save the flow data, you can use "stc_csv = stc_raw.to_csv()" to save


def processML(que: queue.Queue):
    """Machine Learning Detection Module"""
    mlengine = MLProcessor()
    while True:
        if not que.empty():
            real_df = que.get()
            dec_info = []
            # pred is np.narray type
            pred = mlengine.predict(real_df)
            # row is pandas.Series type
            for _, row in real_df.iterrows():
                dec_info.append(parsePredictionDF(row))
            display_log_data(pred, dec_info)


def display_log_data(pred, dec_info: list):
    """"Display the detection result and log in file"""
    for index in range(len(dec_info)):
        if pred[index] == 0:
            print("ANOMALY: %s" % dec_info[index])
            logging.warning("ANOMALY: %s" % dec_info[index])
        else:
            print("BENIGN: %s" % dec_info[index])
            logging.info("BENIGN: %s" % dec_info[index])
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


def log_init():
    """Initialize the log file"""
    # logging - level: makes it print information above a certain level
    # default = logging.WARNING
    cur_datime = time.strftime("%Y-%m-%d-%H_%M_%S", time.localtime(time.time()))
    logging.basicConfig(format='%(levelname)s - %(message)s',
                        level=logging.INFO,
                        filename=LOGGING_PATH+cur_datime+'_log.log',
                        filemode='a', )
    print("The log file was initialized successfully")


if __name__ == '__main__':
    # Initialization procedure
    print("***********************************************")
    log_init()
    prepareDumps()
    init_folder(TEMP_DIR)
    # Launch scan_thread, flow_thread, det_thread, tshark_generator to execute detection procedure
    scan_thread = Thread(target=check_file, args=(info_que,))
    flow_thread = Thread(target=nfstream_process, args=(info_que, cont_que))
    det_thread = Thread(target=processML, args=(cont_que,))
    scan_thread.start()
    flow_thread.start()
    det_thread.start()
    print("Detection procedures are activated!")
    print("***********************************************")
    tshark_generator()


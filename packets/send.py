#!/usr/bin/env python
import argparse
import time
from time import sleep
import sys
import os
import numpy as np

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, sendpfast
from scapy.all import Packet, BitField, bind_layers
from scapy.all import Ether, IP, UDP

class Features_15(Packet):
    name = "Features"
    fields_desc = [
        BitField("features", 0, 90),
        BitField("padding", 0, 6)]

class Features_11(Packet):
    name = "Features"
    fields_desc = [
        BitField("features", 0, 66),
        BitField("padding", 0, 6)]

class Features_10(Packet):
    name = "Features"
    fields_desc = [
        BitField("features", 0, 60),
        BitField("padding", 0, 4)]
    
class Features_5(Packet):
    name = "Features"
    fields_desc = [
        BitField("features", 0, 30),
        BitField("padding", 0, 2)]
    
class Labelling_1(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4),
        BitField("padding", 0, 4)]

class Labelling_3(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4),
        BitField("prediction_2", 0, 4),
        BitField("prediction_3", 0, 4),
        BitField("padding", 0, 4)]
    
class Labelling_5(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4),
        BitField("prediction_2", 0, 4),
        BitField("prediction_3", 0, 4),
        BitField("prediction_4", 0, 4),
        BitField("prediction_5", 0, 4),
        BitField("padding", 0, 4)]
    
class Labelling_7(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4),
        BitField("prediction_2", 0, 4),
        BitField("prediction_3", 0, 4),
        BitField("prediction_4", 0, 4),
        BitField("prediction_5", 0, 4),
        BitField("prediction_6", 0, 4),
        BitField("prediction_7", 0, 4),
        BitField("padding", 0, 4)]
    
class Labelling_9(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4),
        BitField("prediction_2", 0, 4),
        BitField("prediction_3", 0, 4),
        BitField("prediction_4", 0, 4),
        BitField("prediction_5", 0, 4),
        BitField("prediction_6", 0, 4),
        BitField("prediction_7", 0, 4),
        BitField("prediction_8", 0, 4),
        BitField("prediction_9", 0, 4),
        BitField("padding", 0, 4)]

def read_features(filepath):
    features = []
    with open(filepath, 'r') as f:
        for line in f:
            binary_str = line.strip()
            features.append(int(binary_str, 2))
    return features

def bind_feature_layers(features, tasks):
    if features == 15:
        bind_layers(IP, Features_15)
        bind_task_layers(Features_15, tasks)
    elif features == 10:
        bind_layers(IP, Features_10)
        bind_task_layers(Features_10, tasks)
    elif features == 5:
        bind_layers(IP, Features_5)
        bind_task_layers(Features_5, tasks)
    elif features == 11:
        bind_layers(IP, Features_11, proto=200)
        bind_task_layers(Features_11, tasks)
    else:
        print("Invalid number of features")
        sys.exit(1)

def bind_task_layers(feature_layer, tasks):
    if tasks == 1:
        bind_layers(feature_layer, Labelling_1)
    elif tasks == 3:
        bind_layers(feature_layer, Labelling_3)
    elif tasks == 5:
        bind_layers(feature_layer, Labelling_5)
    elif tasks == 7:
        bind_layers(feature_layer, Labelling_7)
    elif tasks == 9:
        bind_layers(feature_layer, Labelling_9)
    else:
        print("Invalid number of tasks")
        sys.exit(1)

def create_packet(iface, src_ip, dst_ip, feature, features, tasks, i):
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(src=src_ip, dst=dst_ip, proto=200, id=i)
    if features == 15:
        pkt = pkt / Features_15(features=feature)
    elif features == 10:
        pkt = pkt / Features_10(features=feature)
    elif features == 5:
        pkt = pkt / Features_5(features=feature)
    elif features == 11:
        pkt = pkt / Features_11(features=feature)
    
    if tasks == 1:
        pkt = pkt / Labelling_1()
    elif tasks == 3:
        pkt = pkt / Labelling_3()
    elif tasks == 5:
        pkt = pkt / Labelling_5()
    elif tasks == 7:
        pkt = pkt / Labelling_7()
    elif tasks == 9:
        pkt = pkt / Labelling_9()
    pkt = pkt / UDP(dport=1234)
    return pkt

def main(args):
    # file_name = f"/home/mnc/mnc/MARTINI/magazine/results/SendPkt_{args.mode}_f{args.f}_t{args.t}.txt"
    # sys.stdout = open(file_name,'w')

    input_features_file_path = f"/home/mnc/mnc/MARTINI/magazine/data/input/input_f{args.f}.txt"
    features = read_features(input_features_file_path)

    src_ip = "10.10.0.1"
    dst_ip = "10.10.0.2"
    
    # ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    # iface = ifaces[0]
    iface = "veth0"
    
    bind_feature_layers(args.f, args.t)
    
    pkts = []
    for i, feature in enumerate(features):
        pkt = create_packet(iface, src_ip, dst_ip, feature, args.f, args.t, i)
        pkts.append(pkt)
    
    pkt_id = []
    # features = []
    # prediction = []
    send_time = []
    print("No, Features, Prediction, Time")
    for pkt in pkts:
        send_time.append(time.time())

        pkt.show()

        sendp(pkt, iface=iface,verbose=False)
        pkt_id.append(pkt[IP].id)
        # sleep(0.0001)
    for i in range(len(pkts)):
        print(pkt_id[i], send_time[i])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='receiver parser')
    parser.add_argument('--mode', help='mtl or stl', type=str, required=True)
    parser.add_argument('--f', help='Number of features', type=int, required=True)
    parser.add_argument('--t', help='Number of tasks', type=int, required=True)
    args = parser.parse_args()
    main(args)
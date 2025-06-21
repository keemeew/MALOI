#!/usr/bin/env python
import time
from time import sleep
import sys
import threading
import argparse

from scapy.all import sendp, get_if_hwaddr
from scapy.all import Packet, BitField, bind_layers, sniff
from scapy.all import Ether, IP, UDP, TCP

parser = argparse.ArgumentParser(description='bfrt parser')
parser.add_argument('--d', help='Datasets, network or census', type=int, required=True)
parser.add_argument('--m', help='stl or mtl', type=int, required=True)
parser.add_argument('--f', help='Number of features', type=int, required=True)
parser.add_argument('--t', help='Number of tasks', type=int, required=True)
args = parser.parse_args()

if args.d == "network":
    if args.m == 'stl':
        class maloi(Packet):
            name = "maloi"
            fields_desc = [
                BitField("cnt", 0, 11),
                BitField("padding", 0, 5),
                BitField("layer", 0, 8)
            ]

        class features(Packet):
            name = "Features"
            fields_desc = [
                BitField("padding", 0, 7),
                BitField("features", 0, 169)
            ]

    elif args.m == 'mtl':
        if args.f == 6:
            class maloi(Packet):
                name = "maloi"
                fields_desc = [
                    BitField("cnt", 0, 8),
                    BitField("layer", 0, 8)
                ]

            class features(Packet):
                name = "Features"
                fields_desc = [
                    BitField("features", 0, 112)
                ]

        elif args.f == 11:
            class maloi(Packet):
                name = "maloi"
                fields_desc = [
                    BitField("cnt", 0, 9),
                    BitField("padding", 0, 7),
                    BitField("layer", 0, 8)
                ]

            class features(Packet):
                name = "Features"
                fields_desc = [
                    BitField("padding", 0, 7),
                    BitField("features", 0, 169)
                ]
    class labeling(Packet):
        name = "Prediction results"
        fields_desc = [
            BitField("prediction_1", 0, 2),
            BitField("prediction_2", 0, 2),
            BitField("prediction_3", 0, 2),
            BitField("prediction_4", 0, 2),
            BitField("padding", 0, 4),
            BitField("prediction_5", 0, 2),
            BitField("prediction_6", 0, 2)
        ]

elif args.d == "census":
    if args.m == 'stl':
        class maloi(Packet):
            name = "maloi"
            fields_desc = [
                BitField("cnt", 0, 14),
                BitField("padding", 0, 2),
                BitField("layer", 0, 8)
            ]
        class features(Packet):
            name = "Features"
            fields_desc = [
                BitField("padding", 0, 6),
                BitField("features", 0, 90)
            ]
    elif args.m == 'mtl':
        if args.f == 11:
            class maloi(Packet):
                name = "maloi"
                fields_desc = [
                    BitField("cnt", 0, 8),
                    BitField("layer", 0, 8)
                ]
            class features(Packet):
                name = "Features"
                fields_desc = [
                    BitField("padding", 0, 6),
                    BitField("features", 0, 66)
                ]
        elif args.f == 15:
            class maloi(Packet):
                name = "maloi"
                fields_desc = [
                    BitField("cnt", 0, 8),
                    BitField("layer", 0, 8)
                ]
            class features(Packet):
                name = "Features"
                fields_desc = [
                    BitField("padding", 0, 6),
                    BitField("features", 0, 90)
                ]
    class labeling_1(Packet):
        name = "Prediction results"
        fields_desc = [
            BitField("prediction_6", 0, 8),
            BitField("prediction_12", 0, 8)
        ]

    class labeling_2(Packet):
        name = "Prediction results"
        fields_desc = [
            BitField("prediction_10", 0, 8),
            BitField("prediction_2", 0, 8)
        ]

    class labeling_3(Packet):
        name = "Prediction results"
        fields_desc = [
            BitField("prediction_13", 0, 8)
        ]
            
def read_features(filepath):
    features = []
    with open(filepath, 'r') as f:
        for line in f:
            binary_str = line.strip()
            features.append(int(binary_str, 2))
    return features

def read_labels(filepath):
    labels = []
    with open(filepath, 'r') as f:
        for line in f:
            label = int(line.strip())
            labels.append(label)
    return labels

def calculate_accuracy(predictions, ground_truth):
    if len(predictions) == 0 or len(ground_truth) == 0:
        return 0.0
    
    min_len = min(len(predictions), len(ground_truth))
    correct = 0
    
    for i in range(min_len):
        if predictions[i] == ground_truth[i]:
            correct += 1
    
    accuracy = correct / min_len * 100.0
    return accuracy

def print_accuracy_results():
    global task1, task2, task3, task4, task5, task6, task10, task12, task13
    label_files = []
    task_names = []
    if args.t == 6:
        label_files = [
            "../data/network/test_labels/te_task1_label_i.txt",
            "../data/network/test_labels/te_task2_label_i.txt",
            "../data/network/test_labels/te_task3_label_i.txt",
            "../data/network/test_labels/te_task4_label_i.txt",
            "../data/network/test_labels/te_task5_label_i.txt",
            "../data/network/test_labels/te_task6_label_i.txt",
        ]
        task_names = [
            "Task1",
            "Task2",
            "Task3",
            "Task4",
            "Task5",
            "Task6"
        ]
        tasks = [task1, task2, task3, task4, task5, task6]
    elif args.t == 5:
        label_files = [
            "../data/census/test_labels/te_task2_label_i.txt",
            "../data/census/test_labels/te_task6_label_i.txt",
            "../data/census/test_labels/te_task10_label_i.txt",
            "../data/census/test_labels/te_task12_label_i.txt",
            "../data/census/test_labels/te_task13_label_i.txt",
        ]
        task_names = [
            "Task2",
            "Task6",
            "Task10",
            "Task12",
            "Task13"
        ]
        tasks = [task2, task6, task10, task12, task13]
    
    accuracies = []
    
    print("\n" + "="*50)
    print("ACCURACY RESULTS")
    print("="*50)
    
    for i, (task_predictions, label_file, task_name) in enumerate(zip(tasks, label_files, task_names)):
        ground_truth = read_labels(label_file)
        accuracy = calculate_accuracy(task_predictions, ground_truth)
        accuracies.append(accuracy)
        
        print(f"{task_name}: {accuracy:.2f}% ({len(task_predictions)} predictions, {len(ground_truth)} labels)")
        
    if accuracies:
        avg_accuracy = sum(accuracies) / len(accuracies)
        print(f"\nAverage Accuracy: {avg_accuracy:.2f}%")
    else:
        print("\nNo accuracy data available")
    
    print("="*50)

def create_packet(iface, src_ip, dst_ip, feature, i):
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(src=src_ip, dst=dst_ip, proto=200, id=i)
    if args.t == 6:
        pkt = pkt / maloi() / features(features=feature) / labeling()
        pkt = pkt / TCP(dport=1234, sport=1234)
    elif args.t == 5:
        pkt = pkt / maloi() / features(features=feature) / labeling_1() / labeling_2() / labeling_3()
        pkt = pkt / UDP(dport=1234, sport=1234)
    
    return pkt

def mac_to_decimal(mac_str: str) -> int:
    return int(mac_str.replace(":",""),16)

def receive_packet():
    global recv_iface
    bind_layers(IP,maloi)
    bind_layers(maloi,features)
    if args.t ==6:
        bind_layers(features,labeling)
        bind_layers(labeling,TCP)
    elif args.t == 5:
        bind_layers(features,labeling_1)
        bind_layers(features,labeling_2)
        bind_layers(features,labeling_3)
        bind_layers(labeling,UDP)
    sniff(iface = recv_iface, prn = lambda x: handle_pkt(x))

def handle_pkt(pkt):
    global recv_pkts, flag, task1,task2, task3, task4, task5, task6, task10, task12, task13
    # pkt.show()
    if maloi in pkt:
        if pkt[IP].ttl != 64:
            recv_pkts.append(pkt)
            if args.t == 6:
                task1.append(pkt[labeling].prediction_1)
                task2.append(pkt[labeling].prediction_2)
                task3.append(pkt[labeling].prediction_3)
                task4.append(pkt[labeling].prediction_4)
                task5.append(pkt[labeling].prediction_5)
                task6.append(pkt[labeling].prediction_6)
                print(f'{pkt[IP].id}th packet ==> Task1: {task1[-1]}, Task2: {task2[-1]}, Task3: {task3[-1]}, Task4: {task4[-1]}, Task5: {task5[-1]}, Task6: {task6[-1]}')
            elif args.t == 5:
                task2.append(pkt[labeling_2].prediction_2)
                task6.append(pkt[labeling_1].prediction_6)
                task10.append(pkt[labeling_2].prediction_10)
                task12.append(pkt[labeling_1].prediction_12)
                task13.append(pkt[labeling_3].prediction_13)
                print(f'{pkt[IP].id}th packet ==> Task2: {task2[-1]}, Task6: {task6[-1]}, Task10: {task10[-1]}, Task12: {task12[-1]}, Task13: {task13[-1]}')

            sleep(2)
            flag = 1

def sending_packets():
    global pkts, send_iface, flag
    i = 0
    while True:
        if flag == 1:
            try:
                sleep(1)
                sendp(pkts[i], iface=send_iface, verbose=False)
                flag = 0
                i += 1
            except Exception as e:
                print(f"Error sending packet: {e}")
                flag = 3
 
        if flag ==3:
            print("All tasks completed. Exiting...")
            print_accuracy_results()
            break

def main():
    global pkts, recv_pkts
    global send_iface, recv_iface
    global flag
    global task1, task2, task3, task4, task5, task6, task10, task12, task13

    flag = 1
    recv_pkts = []
    pkts = []
    task1 = []
    task2 = []
    task3 = []
    task4 = []
    task5 = []
    task6 = []
    task10 = []
    task12 = []
    task13 = []

    send_iface = "veth0" 
    recv_iface = "veth2"

    input_features_file_path = f"../data/{args.d}/input/input_f{args.f}.txt"
    features = read_features(input_features_file_path)
    print("prepared!")
    src_ip = "10.10.0.1"
    dst_ip = "10.10.0.2"

    for i, feature in enumerate(features):
        pkt = create_packet(send_iface, src_ip, dst_ip, feature, i)
        pkts.append(pkt)
    print("created!")
    
    receive_thread = threading.Thread(target=receive_packet, args=())
    receive_thread.daemon = True
    receive_thread.start()

    send_thread = threading.Thread(target=sending_packets, args=())
    send_thread.daemon = True
    send_thread.start()
    
    count = 0
    try:
        while True:
            count += 1
            sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Calculating final accuracy...")
        print_accuracy_results()
        sys.exit(0)

if __name__ == '__main__':
    main()
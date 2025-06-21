#!/usr/bin/env python 
import sys
import os
import argparse
import time
import threading

from scapy.all import sniff, bind_layers
from scapy.all import Packet, BitField
from scapy.all import Ether, IP, UDP

parser = argparse.ArgumentParser(description='receiver parser')
parser.add_argument('--mode', help='MTL or STL', type=str, required=True)
parser.add_argument('--f', help='Number of features', type=int, required=True)
parser.add_argument('--t', help='Number of tasks', type=int, required=True)
parser.add_argument('--task_id', help='Task ID', type=int, default=0)
args = parser.parse_args()

TASKS = [2, 6, 10, 12, 13]
LABELS = {}

# per-task accuracy
task_correct_predictions = {task: 0 for task in TASKS}
task_total_predictions = {task: 0 for task in TASKS}
task_accuracies = {task: 0.0 for task in TASKS}

correct_predictions = 0
total_predictions = 0
packet_count = 0 
lock = threading.Lock()  
log_entries = [] 

def load_labels():
    global LABELS
    label_dir = "../data/census/test_labels/"

    for task in TASKS:
        label_file = os.path.join(label_dir, f"te_task{task}_label_i.txt")
        if os.path.exists(label_file):
            with open(label_file, "r") as f:
                LABELS[task] = [int(line.strip()) for line in f.readlines()]
        else:
            print(f"Warning: Label file {label_file} not found!")
            LABELS[task] = []

class Features_15(Packet):
    name = "Features"
    fields_desc = [BitField("features", 0, 90), BitField("padding", 0, 6)]

class Features_11(Packet):
    name = "Features"
    fields_desc = [BitField("features", 0, 66), BitField("padding", 0, 6)]

class Features_10(Packet):
    name = "Features"
    fields_desc = [BitField("features", 0, 60), BitField("padding", 0, 4)]

class Features_5(Packet):
    name = "Features"
    fields_desc = [BitField("features", 0, 30), BitField("padding", 0, 2)]

class Labelling_1(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4), BitField("task_id", 0, 4)
    ]

class Labelling_3(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4), BitField("prediction_2", 0, 4), 
        BitField("prediction_3", 0, 4), BitField("task_id", 0, 4)
    ]

class Labelling_5(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4), BitField("prediction_2", 0, 4), 
        BitField("prediction_3", 0, 4), BitField("prediction_4", 0, 4),
        BitField("prediction_5", 0, 4), BitField("task_id", 0, 4)
    ]

def bind_feature_layers(features, tasks):
    if features == 15:
        bind_layers(IP, Features_15, proto=200)
        bind_task_layers(Features_15, tasks)
    elif features == 10:
        bind_layers(IP, Features_10, proto=200)
        bind_task_layers(Features_10, tasks)
    elif features == 5:
        bind_layers(IP, Features_5, proto=200)
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
    else:
        print("Invalid number of tasks")
        sys.exit(1)

def update_accuracy(predictions, packet_idx, task_id):
    global correct_predictions, total_predictions, task_correct_predictions, task_total_predictions

    if packet_idx < len(next(iter(LABELS.values()))):
        if task_id == 0:
            correct = sum(1 for i, task in enumerate(TASKS) if predictions[i] == LABELS[task][packet_idx])
            with lock:
                correct_predictions += correct
                total_predictions += len(TASKS)
                for i, task in enumerate(TASKS):
                    if predictions[i] == LABELS[task][packet_idx]:
                        task_correct_predictions[task] += 1
                    task_total_predictions[task] += 1
        elif task_id in TASKS:
            task_idx = TASKS.index(task_id)
            if predictions[task_idx] == LABELS[task_id][packet_idx]:
                with lock:
                    correct_predictions += 1
                    total_predictions += 1
                    task_correct_predictions[task_id] += 1
                    task_total_predictions[task_id] += 1
            else:
                with lock:
                    total_predictions += 1
                    task_total_predictions[task_id] += 1

def print_packet_info(pkt, features, tasks, idx, start_time):
    task_id = pkt[f'Labelling_{tasks}'].task_id
    
    if tasks == 1:
        prediction = [pkt[Labelling_1].prediction_1]
    elif tasks == 3:
        if task_id == 0:
            prediction = [
                pkt[Labelling_3].prediction_1, pkt[Labelling_3].prediction_2,
                pkt[Labelling_3].prediction_3
            ]
        else:
            prediction = [0] * 3
            if task_id == 2:
                prediction[0] = pkt[Labelling_3].prediction_1
            elif task_id == 6:
                prediction[1] = pkt[Labelling_3].prediction_2
            elif task_id == 10:
                prediction[2] = pkt[Labelling_3].prediction_3
    elif tasks == 5:
        if task_id == 0:
            prediction = [
                pkt[Labelling_5].prediction_1, pkt[Labelling_5].prediction_2,
                pkt[Labelling_5].prediction_3, pkt[Labelling_5].prediction_4,
                pkt[Labelling_5].prediction_5
            ]
        # read predictions for task_id only
        else:
            prediction = [0] * 5
            if task_id == 2:
                prediction[0] = pkt[Labelling_5].prediction_1
            elif task_id == 6:
                prediction[1] = pkt[Labelling_5].prediction_2
            elif task_id == 10:
                prediction[2] = pkt[Labelling_5].prediction_3
            elif task_id == 12:
                prediction[3] = pkt[Labelling_5].prediction_4
            elif task_id == 13:
                prediction[4] = pkt[Labelling_5].prediction_5         

    str_format_prediction = f"({' '.join(map(str, prediction))})"

    update_accuracy(prediction, idx, task_id)

    with lock:
        accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0

    mac_addr = pkt[Ether].dst
    sec = int(mac_addr.replace(':', ''), 16) / 1000

    print(f"No: {pkt[IP].id}, Task ID: {task_id}, Classification label: {str_format_prediction}, Hop latency [us]: {sec:.3f},  Accuracy [%]: {accuracy:.3f}", flush=True)

    log_entry = "{:<10} {:<10} {:<15} {:<20.3f} {:<20.3f}".format(
        pkt[IP].id, task_id, str_format_prediction, sec, accuracy
    )

    log_entries.append(log_entry)

    with open(log_file, "a") as f:
        f.write(log_entry + "\n")


def handle_pkt(pkt, start_time):
    global packet_count
    if pkt.haslayer(IP) and pkt[IP].proto == 200:
        print_packet_info(pkt, args.f, args.t, packet_count, start_time)
        packet_count += 1

def receive_packet():
    sniff(iface=iface, prn=lambda pkt: handle_pkt(pkt, start_time), store = False)

def print_task_accuracies():
    print("\n=== Task-wise Accuracies ===")
    total_task_accuracy = 0
    valid_tasks = 0 
    # packet w/ task_id
    if args.task_id != 0:
        task = args.task_id
        if task_total_predictions[task] > 0:
            task_accuracies[task] = (task_correct_predictions[task] / task_total_predictions[task]) * 100
            print(f"Task {task}: {task_accuracies[task]:.3f}%")
            total_task_accuracy = task_accuracies[task]
            valid_tasks = 1
    # packet w/o task_id
    else:
        for task in TASKS:
            if task_total_predictions[task] > 0:
                task_accuracies[task] = (task_correct_predictions[task] / task_total_predictions[task]) * 100
                print(f"Task {task}: {task_accuracies[task]:.3f}%")
                total_task_accuracy += task_accuracies[task]
                valid_tasks += 1
    
    if valid_tasks > 0:
        avg_task_accuracy = total_task_accuracy / valid_tasks
        print(f"\nAverage Task Accuracy: {avg_task_accuracy:.3f}%")
    else:
        print("\nAverage Task Accuracy: 0.000%")
    
    overall_accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0
    print(f"Overall Accuracy: {overall_accuracy:.3f}%")

def main():
    global iface, start_time, log_file, packet_count
    packet_count = 0
    start_time = time.time()
    load_labels()

    # log_file = f"/mnt/hgfs/MyResearch_vmawre/Research_MALOI/MALOI-master/results/RecvPkt_{args.mode}_f{args.f}_t{args.t}.txt"
    

    iface = "veth2"
    bind_feature_layers(args.f, args.t)

    log_header = "{:<10} {:<10} {:<15} {:<20} {:<20}".format(
        "No", "Task ID", "Predictions", "Hop latency [us]", "Accuracy [%]"
    )

    print(log_header)

    receive_thread = threading.Thread(target=receive_packet, args=())
    receive_thread.daemon = True
    receive_thread.start()

    try:
        while True:
            time.sleep(0.1)  
    except KeyboardInterrupt:
        # per-task accuracy
        print_task_accuracies()
        with open(log_file, "w") as f:
            f.write("Predictions: (Task 2, Task 6, Task 10, Task 12, Task 13)\n\n")
            f.write(log_header + '\n')
            for entry in log_entries:
                f.write(entry + "\n")
            f.write("\n=== Task-wise Accuracies ===\n")
            for task in TASKS:
                f.write(f"Task {task}: {task_accuracies[task]:.3f}%\n")
            f.write(f"\nAverage Task Accuracy: {sum(task_accuracies.values()) / len(TASKS):.3f}%\n")
            f.write(f"Overall Accuracy: {(correct_predictions / total_predictions) * 100:.3f}%\n")
        print(f"\nlog saved complete: {log_file}")

if __name__ == '__main__':
    main()

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
args = parser.parse_args()

# 사용할 태스크 목록
TASKS = [2, 6, 10, 12, 13]
LABELS = {}

# Accuracy 계산을 위한 변수
correct_predictions = 0
total_predictions = 0
packet_count = 0  # 패킷 개수 카운트
lock = threading.Lock()  # Accuracy 갱신 시 동기화
log_entries = []  # 로그를 저장할 리스트

# 정답 라벨 파일을 로드하는 함수
def load_labels():
    global LABELS
    label_dir = "/home/mnc/mnc/MARTINI/magazine/data/test_labels"

    for task in TASKS:
        label_file = os.path.join(label_dir, f"te_task{task}_label_i.txt")
        if os.path.exists(label_file):
            with open(label_file, "r") as f:
                LABELS[task] = [int(line.strip()) for line in f.readlines()]
        else:
            print(f"Warning: Label file {label_file} not found!")
            LABELS[task] = []

# 패킷 구조 정의
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
    fields_desc = [BitField("prediction_1", 0, 4), BitField("padding", 0, 4)]

class Labelling_3(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4), BitField("prediction_2", 0, 4),
        BitField("prediction_3", 0, 4), BitField("padding", 0, 4)
    ]

class Labelling_5(Packet):
    name = "Prediction results"
    fields_desc = [
        BitField("prediction_1", 0, 4), BitField("prediction_2", 0, 4),
        BitField("prediction_3", 0, 4), BitField("prediction_4", 0, 4),
        BitField("prediction_5", 0, 4), BitField("padding", 0, 4)
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

# Accuracy 업데이트
def update_accuracy(predictions, packet_idx):
    global correct_predictions, total_predictions

    if packet_idx < len(next(iter(LABELS.values()))):  # 모든 task에서 동일한 패킷 수를 가정
        correct = sum(1 for i, task in enumerate(TASKS) if predictions[i] == LABELS[task][packet_idx])

        with lock:  # 동기화
            correct_predictions += correct
            total_predictions += len(TASKS)

# 패킷 정보 출력 및 로그 저장
# 패킷 정보 출력 및 로그 저장
def print_packet_info(pkt, features, tasks, idx, start_time):
    if tasks == 1:
        prediction = [pkt[Labelling_1].prediction_1]
    elif tasks == 3:
        prediction = [
            pkt[Labelling_3].prediction_1, pkt[Labelling_3].prediction_2,
            pkt[Labelling_3].prediction_3
        ]
    elif tasks == 5:
        prediction = [
            pkt[Labelling_5].prediction_1, pkt[Labelling_5].prediction_2,
            pkt[Labelling_5].prediction_3, pkt[Labelling_5].prediction_4,
            pkt[Labelling_5].prediction_5
        ]

    # **튜플을 "(a b c d e)" 형태의 문자열로 변환**
    str_format_prediction = f"({' '.join(map(str, prediction))})"

    # Accuracy 업데이트
    update_accuracy(prediction, idx)

    # Accuracy 계산
    with lock:
        accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0

    mac_addr = pkt[Ether].dst
    sec = int(mac_addr.replace(':', ''), 16) / 1000

    # **터미널 출력 형식**
    print(f"No: {pkt[IP].id}, Classification label: {str_format_prediction}, Hop latency [us]: {sec:.3f},  Accuracy [%]: {accuracy:.3f}", flush=True)

    # **로그 저장 형식 (테이블 형식 유지)**
    log_entry = "{:<10} {:<15} {:<20.3f} {:<20.3f}".format(
        pkt[IP].id, str_format_prediction, sec, accuracy
    )

    # 로그 리스트에 추가
    log_entries.append(log_entry)

    # **실시간 로그 파일 저장**
    with open(log_file, "a") as f:
        f.write(log_entry + "\n")


def handle_pkt(pkt, start_time):
    global packet_count
    if pkt.haslayer(IP) and pkt[IP].proto == 200:
        print_packet_info(pkt, args.f, args.t, packet_count, start_time)
        packet_count += 1

def receive_packet():
    sniff(iface=iface, prn=lambda pkt: handle_pkt(pkt, start_time), store = False) # store option false로 해서 먼저 해보자.

def main():
    global iface, start_time, log_file, packet_count
    packet_count = 0
    start_time = time.time()
    # 정답 라벨 로드
    load_labels()

    log_file = f"/home/mnc/mnc/MARTINI/magazine/results/RecvPkt_{args.mode}_f{args.f}_t{args.t}.txt"

    # ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    # iface = ifaces[0]
    iface = "veth2"
    bind_feature_layers(args.f, args.t)

    log_header = "{:<10} {:<15} {:<20} {:<20}".format(
        "No", "Predictions", "Hop latency [us]", "Accuracy [%]"
    )

    print(log_header)

    receive_thread = threading.Thread(target=receive_packet, args=())
    receive_thread.daemon = True
    receive_thread.start()

    try:
        while True:
            time.sleep(0.1)  # 계속 실행
    except KeyboardInterrupt:
        # 종료 시 로그 파일에 한 번에 기록
        with open(log_file, "w") as f:
            f.write("Predictions: (Task 2, Task 6, Task 10, Task 12, Task 13)\n\n")
            f.write(log_header + '\n')
            for entry in log_entries:
                f.write(entry + "\n")
        print(f"\nlog saved complete: {log_file}")

if __name__ == '__main__':
    main()

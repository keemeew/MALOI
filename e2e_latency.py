import sys
import argparse

def read_results(filepath):
    results = []
    with open(filepath, 'r') as f:
        for line in f:
            result = line.strip().split()
            results.append(result)
    return results

def main(args):
    file_name = f"/home/mnc/mnc/MARTINI/magazine/results/e2e_{args.mode}_f{args.f}_t{args.t}.txt"
    sys.stdout = open(file_name,'w')

    recv_file = f"/home/mnc/mnc/MARTINI/magazine/results/RecvPkt_{args.mode}_f{args.f}_t{args.t}.txt"
    # send_file = f"/home/mnc/mnc/MARTINI/magazine/results/SendPkt_{args.mode}_f{args.f}_t{args.t}.txt"

    recv_results = read_results(recv_file)
    # send_results = read_results(send_file)

    for recv_pkt in recv_results[1:]:
        packet_id = recv_pkt[0]
        # for send_pkt in send_results[1:]:
        #     if packet_id == send_pkt[0]:
        #         latency = (float(recv_pkt[-2]) - float(send_pkt[1])) * 1000
        #         print(f"{packet_id}, {latency:.3f}, {float(recv_pkt[-1])/1000}")
        #         break
    
    hop_latency = []
    for result in recv_results[1:]:
        hop_latency.append(float(result[-1])/1000)
    
    print(f"average hop latency = {sum(hop_latency)/len(hop_latency)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='receiver parser')
    parser.add_argument('--mode', help='mtl or stl', type=str, required=True)
    parser.add_argument('--f', help='Number of features', type=int, required=True)
    parser.add_argument('--t', help='Number of tasks', type=int, required=True)
    args = parser.parse_args()
    main(args)

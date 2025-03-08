import argparse
from p4utils.mininetlib.network_API import NetworkAPI
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.link import TCLink
from multiprocessing import Process
from time import sleep
import subprocess
import sys

# # 로그 파일 저장 경로
# log_file_path = "/home/mnc/mnc/MARTINI/magazine/log/p4_log.txt"
# sys.stdout = open(log_file_path, "a")  # 기존 로그 파일에 추가 (append)
# sys.stderr = sys.stdout  # 에러 로그도 동일한 파일에 저장

## Run command on Mininet node
def run_command_on_host(host_node, command):
    result = host_node.cmd(command)

# Configure Network
def config_network(p4, f, t):
    net = NetworkAPI()

    # If want to use Mininet CLI, modify to True
    net.cli_enabled = False
    
    # Link option
    linkops = dict(bw=1000, delay='1ms', loss=0, use_htb=True)

    # Network general options
    net.setLogLevel('info')  # 여기에 출력되는 정보도 log_file_path에 저장됨

    # Add p4 switches
    net.addP4Switch('s1')

    # Execute P4 program on switch
    net.setP4SourceAll(p4)

    # Add hosts
    hosts = []
    for i in range (0,2):
        hosts.append(net.addHost('h%d' % (i+1)))

    # Construct Network Topology : Linear with 3 hops
    net.addLink('h1', 's1',**linkops)
    net.addLink('h2', 's1',**linkops)
        
    # Assignment strategy
    net.mixed()

    return net

# Parser for P4 program and number of sending packets
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', help='MTL or STL', type=str, required=True)
    parser.add_argument('--f', help='Number of features', type=int, required=True)
    parser.add_argument('--t', help='Number of tasks', type=int, required=True)
    parser.add_argument('--p4', help='P4 source code for INT mode', type=str, required=True)
    return parser.parse_args()

def main():
    args = get_args()

    print(f"[INFO] Running Network with mode={args.mode}, features={args.f}, tasks={args.t}, p4_file={args.p4}")

    net = config_network(args.p4, args.f, args.t)
    net.startNetwork()

    sleep(60)

    # # Execute command on Mininet nodes simultaneously
    commands = []
    processes = []

    command1 = f'python3 /home/mnc/mnc/MARTINI/magazine/packets/send.py --mode {args.mode} --f {args.f} --t {args.t}'
    command2 = f'python3 /home/mnc/mnc/MARTINI/magazine/packets/receive.py --mode {args.mode} --f {args.f} --t {args.t}'
    commands.append(command1)
    commands.append(command2)

    print(f"[INFO] Running commands: {commands}")

    for idx, command in enumerate(commands):
        process = Process(target=run_command_on_host, args=(net.net.get(f'h{idx+1}'), command))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()
    
    # # Turn off the Mininet
    net.stopNetwork()

if __name__ == '__main__':
    main()

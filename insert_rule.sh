#!/bin/bash

MODE=$1
FEATURE=$2
TASK=$3

sleep 1m
echo "/home/mnc/mnc/behavioral-model/targets/simple_switch/simple_switch_CLI < /home/mnc/mnc/MARTINI/magazine/p4src/rule/$MODE"_f"$FEATURE"_t"$TASK.txt --thrift-port 9090 >> /home/mnc/mnc/MARTINI/magazine/results/rule_log.txt"
/home/mnc/mnc/behavioral-model/targets/simple_switch/simple_switch_CLI < /home/mnc/mnc/MARTINI/magazine/p4src/rule/$MODE"_f"$FEATURE"_t"$TASK.txt --thrift-port 9090 >> /home/mnc/mnc/MARTINI/magazine/results/rule_log.txt


scripts=("receive.py" "send.py" "network.py")

# 특정 스크립트들을 종료할 때까지 기다림
while true; do
    all_stopped=true
    
    # 종료를 기다릴 스크립트들
    for script in "receive.py" ; do
        pids=$(ps -ef | grep $script | grep -v grep | awk '{print $2}')
        if [ ! -z "$pids" ]; then
            all_stopped=false
            echo "$script is still running with PID(s): $pids"
            break
        fi
    done
    
    # 만약 모든 스크립트가 종료되었다면 루프를 종료
    if [ "$all_stopped" = true ]; then
        echo "All target scripts are stopped. Proceeding to kill network.py."
        break
    fi
    
    sleep 10
done

# 각 스크립트에 대해 처리
for script in "${scripts[@]}"
do
    pids=$(ps -ef | grep $script | grep -v grep | awk '{print $2}')
    
    if [ ! -z "$pids" ]; then
        echo "$script is running with PID(s): $pids"
        
        # network.py는 모든 스크립트가 종료된 후에만 종료됨
        if [ "$script" = "network.py" ] || [ "$script" = "ps_mem" ]; then
            for pid in $pids
            do
                echo "Killing process $pid"
                kill -9 $pid
            done
        fi
    else
        echo "$script is not running."
    fi
done
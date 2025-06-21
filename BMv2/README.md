## Folder Structure

### `p4src`
Contains P4 code implementing MALOI’s in-network inference logic. The files define the data plane processing for multi-task classification using XNOR-based BNNs.

### `rule`
Stores task-specific model weights and lookup tables used for inference. These rules guide the execution of MALOI within the switch pipeline.

### `packets`
Handles core networking functionalities, including:
- Packet sending and receiving.
- Logging and result collection.

### `results`
Contains inference results, including per-task accuracy and latency measurements. These results are processed for performance evaluation and comparison with software-based baselines.

## Dependencies
To run MARLOI, the following dependencies must be installed:
- **p4c**: [https://github.com/p4lang/p4c](https://github.com/p4lang/p4c)
- **Bmv2**: [https://github.com/p4lang/behavioral-model](https://github.com/p4lang/behavioral-model)
- **Mininet**: [https://github.com/mininet/mininet](https://github.com/mininet/mininet)

## Simulation 
For each classification data in a packet, inference switch simultaneously conducts inference for 5 classification tasks (i.e., Workclass, Marital-status, Sex, Capital-loss, Hours-per-week).

This repository includes the following three in-network inference schemes. 
- STL w/ 15 features (P4-BNN)
- MTL w/ 15 features (MALOI)
- MTL w/ 11 features (MALOI)

## Execution Steps
Use the following command to compile and deploy MALOI on the programmable switch:

### Clone Repository
```bash
git clone https://github.com/keemeew/MALOI
```
---
### Compile P4 Program [Terminal 1]

*Enter p4src folder*
```bash
cd p4src
```
*STL 15 features*
```bash
p4c-bm2-ss --target bmv2 --arch v1model -o stl_f15_t5.json stl_f15_t5.p4
```
*MTL 15 features*
```bash
p4c-bm2-ss --target bmv2 --arch v1model -o mtl_f15_t5.json mtl_f15_t5.p4
```
*MTL 11 features*
```bash
p4c-bm2-ss --target bmv2 --arch v1model -o mtl_f11_t5.json mtl_f11_t5.p4
```
### Execute Programmable Switch [Terminal 2]

*Enter p4src folder*
```bash
cd p4src
```
*STL 15 features*
```bash
sudo simple_switch --log-console -i 0@veth0 -i 2@veth2 --thrift-port 9090 stl_f15_t5.json
```
*MTL 15 features*
```bash
sudo simple_switch --log-console -i 0@veth0 -i 2@veth2 --thrift-port 9090 mtl_f15_t5.json
```
*MTL 11 features*
```bash
sudo simple_switch --log-console -i 0@veth0 -i 2@veth2 --thrift-port 9090 mtl_f11_t5.json
```

### Load Model Weights on the Switch [Terminal 3]

*Enter rule folder*
```bash
cd ./p4src/rule
```
*STL 15 features*
```bash
~/behavioral-model/targets/simple_switch/simple_switch_CLI --thrift-port 9090 < ~/p4src/rule/stl_f15_t5.txt
```
*MTL 15 features*
```bash
~/behavioral-model/targets/simple_switch/simple_switch_CLI --thrift-port 9090 < ~/p4src/rule/mtl_f15_t5.txt
```
*MTL 11 features*
```bash
~/behavioral-model/targets/simple_switch/simple_switch_CLI --thrift-port 9090 < ~/p4src/rule/mtl_f11_t5.txt
```

### Start Packet Sending and Receiving

*Enter packets folder*
```bash
cd packets
```
*STL 15 features*
```bash
[Terminal 4]
sudo python3 receive.py --mode stl --f 15 --t 5
[Terminal 5]
sudo python3 send.py --mode stl --f 15 --t 5
```
*MTL 15 features*
```bash
[Terminal 4]
sudo python3 receive.py --mode mtl --f 15 --t 5
[Terminal 5]
sudo python3 send.py --mode mtl --f 15 --t 5
```
*MTL 11 features*
```bash
[Terminal 4]
sudo python3 receive.py --mode mtl --f 11 --t 5
[Terminal 5]
sudo python3 send.py --mode mtl --f 11 --t 5
```

### Task Selection Mode
We provide the task selection mode to support the case when you only want to know inference result of specific task. While the overall operational progress is similar with the normal mode, please make the following changes:
*Compile and execute task selection P4 code*
```bash
p4c-bm2-ss --target bmv2 --arch v1model -o mtl_f11_t5_task_selection.json mtl_f11_t5_task selection.p4
sudo simple_switch --log-console -i 0@veth0 -i 2@veth2 --thrift-port 9090 mtl_f11_t5_task_selection.json
```
*Specify desired task ID on sender and receiver*
```bash
sudo python3 send.py --mode mtl --f 15 --t 5 --task_id 2
sudo python3 receive.py --mode mtl --f 15 --t 5 --task_id 2
``` 
Note that if you don't specify any task ID on sender and receiver or use task ID 0, they will perform as normal mode (i.e., show evey task result).
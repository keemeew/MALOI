# MALOI: Multi-Task-Aware Low-Overhead In-Network Inference using Programmable Switch

## Overview of MALOI

<p align="center">
<img src="figures/MTL.png" alt="MALOI Overview" width="600">

MALOI applies multi-task learning (MTL) in programmable data planes (PDP) to efficiently handle multiple inference tasks with minimal overhead (e.g., memory and processing delay). Furthermore, MALOI selects a part of essential features and compresses the inference model accordingly. By sharing hidden layer parameters and selecting essential features, MALOI reduces memory usage and inference delay while maintaining comparable accuracy. 

## Evaluation Results

We conducted tests on an Wedge100BF-32X Tofino switch. Memory usage and processing delay correspond to # of SRAM blocks and end-to-end delay to escape recirculation in the switch, respectively. We considered two datasets, Census Income and ISCXVPN2016 + ISCXTor2016, for real-world scenario and network scenario, respectively.

### Accuracy and Memory Reduction According to # of Tasks 
| Census Income | ISCX VPN and Tor | 
|------------------|------------------|
| <img src="figures/graph_1.png" alt="Census Income Tasks" width="400"> | <img src="figures/graph_1_network.png" alt="ISCX VPN and Tor Tasks" width="400"> | 

### Accuracy and Memory Reduction According to # of Features 
| Census Income | ISCX VPN and Tor | 
|------------------|------------------|
| <img src="figures/graph_2.png" alt="Census Income Features" width="400"> | <img src="figures/graph_2_network.png" alt="ISCX VPN and Tor Features" width="400"> | 

### Processing Delays 
| Census Income | 
|------------------|
| <img src="figures/graph_3.png" alt="Census Income Delay" width="400"> |


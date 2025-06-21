# Folder Structure
### p4src

Contains P4 code implementing MALOI's in-network inference logic. The files define the data plane processing for multi-taks classification using XNOR-based BNNs.

### rule

Inserts task-specific model weights and lookup tables used for inference. These rules guide the execution of MALOI within the switch pipeline


## Tofino Instructions

Use the following command to compile and deploy MALOI on the programmable switch. Note that our code is available in SDE 9.13.3.

1. Download the repository to the local.

2. Compile P4 program
   ```
   ./build_tofino.sh [abs_path for the cloned directory]/MALOI/Tofino/[datasets]/[model]/p4src/[model].p4 maloi_[model]

   e.g., ./build_tofino.sh ~/MALOI/Tofino/Network_data/mtl_f5_t6/p4src/mtl_f5_t6_net.p4 mtl_f5_t6_net
   ```
   
3. Run Tofino model
   ```
   $SDE/run_tofino_model.sh -p [model]
   ```
   
4. Run switch driver
   ```
   $SDE/run_switchd.sh -p maloi_[model]
   bfshell> bfrt_python [abs_path for the cloned directory]/MALOI/Tofino/[datasets]/[model]/rule/bfrt_rule_[model].py

   e.g., bfshell> bfrt_python ~/MALOI/Tofino/Network_data/mtl_f5_t6/rule/bfrt_rule_mtl_f5_t6_net.py
   ```
   
5. Packet generation
   ```
   python3 [abs_path for the cloned directory]/MALOI/Tofino/send_and_receive.py --d [datasets] --m [stl or mtl] --f [the number of features] --t [the number of tasks]

   e.g., python3 ~/MALOI/Tofino/send_and_receive.py --d network --m mtl --f 11 --t 6
   ```

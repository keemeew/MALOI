
PCAP_DIR 	= 	pcap
LOG_DIR 	= 	log

all: run

stl_15_1:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/stl_f15_t1.p4 --mode stl --f 15 --t 1

stl_15_3:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/stl_f15_t3.p4 --mode stl --f 15 --t 3

stl_15_5:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/stl_f15_t5.p4 --mode stl --f 15 --t 5

stl_15_7:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/stl_f15_t7.p4 --mode stl --f 15 --t 7

stl_15_9:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/stl_f15_t9.p4 --mode stl --f 15 --t 9

mtl_15_1:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f15_t1.p4 --mode mtl --f 15 --t 1

mtl_15_3:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f15_t3.p4 --mode mtl --f 15 --t 3

mtl_15_5:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f15_t5.p4 --mode mtl --f 15 --t 5

mtl_15_7:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f15_t7.p4 --mode mtl --f 15 --t 7

mtl_15_9:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f15_t9.p4 --mode mtl --f 15 --t 9

mtl_11_5:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f11_t5.p4 --mode mtl --f 11 --t 5

mtl_10_1:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f10_t1.p4 --mode mtl --f 10 --t 1

mtl_10_3:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f10_t3.p4 --mode mtl --f 10 --t 3

mtl_10_5:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f10_t5.p4 --mode mtl --f 10 --t 5

mtl_10_7:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f10_t7.p4 --mode mtl --f 10 --t 7

mtl_10_9:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f10_t9.p4 --mode mtl --f 10 --t 9

mtl_5_1:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f5_t1.p4 --mode mtl --f 5 --t 1

mtl_5_3:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f5_t3.p4 --mode mtl --f 5 --t 3

mtl_5_5:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f5_t5.p4 --mode mtl --f 5 --t 5

mtl_5_7:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f5_t7.p4 --mode mtl --f 5 --t 7

mtl_5_9:
	sudo python3 network.py --p4 /home/mnc/mnc/MARTINI/magazine/p4src/mtl_f5_t9.p4 --mode mtl --f 5 --t 9

stop:
	sudo mn -c

clean: stop
	sudo rm -f *.pcap
	# rm -rf $(PCAP_DIR) $(LOG_DIR) $(RULE_DIR)/rule*
	sudo rm -rf $(PCAP_DIR) $(LOG_DIR)

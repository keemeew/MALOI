action preprocessing(bit<16> weight_1, bit<16> weight_2, bit<16> weight_3, 
                     bit<16> weight_4, bit<16> weight_5, bit<16> weight_6,
                     bit<16> weight_7) {
    ig_md.meta.weight_1 = weight_1;
    ig_md.meta.weight_2 = weight_2;
    ig_md.meta.weight_3 = weight_3;
    ig_md.meta.weight_4 = weight_4;
    ig_md.meta.weight_5 = weight_5;
    ig_md.meta.weight_6 = weight_6;
    ig_md.meta.weight_7 = weight_7;
}

#define POP_COUNT(i)\
action popcount##i##(bit<8> x){\
    ig_md.meta.x_##i## = x;\
}\

#define XNOR_SHARED_1(i)\
action XNOR_shared_1_##i##(){\
    ig_md.meta.XNOROutput_##i## = ~(ig_md.meta.weight_##i## ^ hdr.features.features_##i##);\
}\

#define XNOR_SHARED_2(i)\
action XNOR_shared_2_##i##(){\
    ig_md.meta.XNOROutput_##i## = ~(ig_md.meta.weight_##i## ^ hdr.intermediate_data1.intermediate_data_##i##);\
}\

#define XNOR_TASK(i)\
action XNOR_task_specific_##i##(){\
    ig_md.meta.XNOROutput_##i## = ~(ig_md.meta.weight_##i## ^ hdr.intermediate_data2.intermediate_data_##i##);\
}\

POP_COUNT(1)
POP_COUNT(2)
POP_COUNT(3)
POP_COUNT(4)
POP_COUNT(5)
POP_COUNT(6)
POP_COUNT(7)

XNOR_SHARED_1(1)
XNOR_SHARED_1(2)
XNOR_SHARED_1(3)
XNOR_SHARED_1(4)
XNOR_SHARED_1(5)
XNOR_SHARED_1(6)
XNOR_SHARED_1(7)

XNOR_SHARED_2(1)
XNOR_SHARED_2(2)
XNOR_SHARED_2(3)
XNOR_SHARED_2(4)
XNOR_SHARED_2(5)
XNOR_SHARED_2(6)
XNOR_SHARED_2(7)

XNOR_TASK(1)
XNOR_TASK(2)
XNOR_TASK(3)
XNOR_TASK(4)
XNOR_TASK(5)
XNOR_TASK(6)
XNOR_TASK(7)

action set_egress_port(bit<9> egress_spec) {
    ig_tm_md.ucast_egress_port = egress_spec;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    hdr.maloi.cnt = hdr.maloi.cnt + 1;
    hdr.maloi.layer = 3;
}

action do_recirculation1() {
    ig_tm_md.ucast_egress_port = 68;
    hdr.maloi.cnt = hdr.maloi.cnt + 1;
    
}
action do_recirculation2() {
    ig_tm_md.ucast_egress_port = 68;
    hdr.maloi.cnt = hdr.maloi.cnt + 1;
}
action set_inteermediate_data_1_tst(){ 
    hdr.maloi.layer = 1;
    hdr.intermediate_data1.setValid();
    hdr.ethernet.srcAddr = ig_intr_md.ingress_mac_tstamp;
}
action set_inteermediate_data_2(){
    hdr.intermediate_data2.setValid();
    hdr.maloi.layer = 2;
}

action total_popcount1(){
    ig_md.meta.PopCountOut1 = ig_md.meta.x_1 + ig_md.meta.x_2;
}
action total_popcount2(){
    ig_md.meta.PopCountOut2 = ig_md.meta.x_3 + ig_md.meta.x_4;
}
action total_popcount3(){
    ig_md.meta.PopCountOut3 = ig_md.meta.x_5 + ig_md.meta.x_6;
}
action total_popcount4(){
    ig_md.meta.PopCountOut2 = ig_md.meta.PopCountOut2 + ig_md.meta.PopCountOut3;
}
action total_popcount5(){
    ig_md.meta.PopCountOut1 = ig_md.meta.PopCountOut1 + ig_md.meta.x_7;
}
action total_popcount6(){
    ig_md.meta.PopCountOut1 = ig_md.meta.PopCountOut1 + ig_md.meta.PopCountOut2;
}
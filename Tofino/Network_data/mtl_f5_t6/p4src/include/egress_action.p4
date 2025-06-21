
action task1_predict(){
    eg_md.meta.test = (bit<8>)(task1_prediction.execute(0));
}
action task2_predict(){
    eg_md.meta.test = (bit<8>)(task2_prediction.execute(0));
}
action task3_predict(){
    eg_md.meta.test = (bit<8>)(task3_prediction.execute(0));
}
action task4_predict(){
    eg_md.meta.test = (bit<8>)(task4_prediction.execute(0));
}
action task5_predict(){
    eg_md.meta.test = (bit<8>)(task5_prediction.execute(0));
}
action task6_predict(){
    eg_md.meta.test = (bit<8>)(task6_prediction.execute(0));
}

action reset_register_task1(){
    task1_reset.execute(0);
}
action reset_register_task2(){
    task2_reset.execute(0);
}
action reset_register_task3(){
    task3_reset.execute(0);
}
action reset_register_task4(){
    task4_reset.execute(0);
}
action reset_register_task5(){
    task5_reset.execute(0);
}
action reset_register_task6(){
    task6_reset.execute(0);
}

action invalid_header(){
    hdr.intermediate_data1.setInvalid();
    hdr.intermediate_data2.setInvalid();
    hdr.maloi.layer = 0;
}

#define ACTIVATE_ONE(i,j)\
action activate##i##_##j##_one(){\
    hdr.intermediate_data##i##.intermediate_data_##j## = hdr.intermediate_data##i##.intermediate_data_##j## + 1;\
}\

#define ACTIVATE_ZERO(i,j)\
action activate##i##_##j##_zero(){\
    hdr.intermediate_data##i##.intermediate_data_##j## = hdr.intermediate_data##i##.intermediate_data_##j## << 1;\
}\

#define PREDICT(i)\
action real_task##i##_predict(bit<2> x){\
    hdr.labeling.prediction##i## = x;\
}\

ACTIVATE_ONE(1,1)
ACTIVATE_ONE(1,2)
ACTIVATE_ONE(1,3)
ACTIVATE_ONE(1,4)
ACTIVATE_ONE(1,5)
ACTIVATE_ONE(1,6)
ACTIVATE_ONE(1,7)

ACTIVATE_ONE(2,1)
ACTIVATE_ONE(2,2)
ACTIVATE_ONE(2,3)
ACTIVATE_ONE(2,4)
ACTIVATE_ONE(2,5)
ACTIVATE_ONE(2,6)
ACTIVATE_ONE(2,7)

ACTIVATE_ZERO(1,1)
ACTIVATE_ZERO(1,2)
ACTIVATE_ZERO(1,3)
ACTIVATE_ZERO(1,4)
ACTIVATE_ZERO(1,5)
ACTIVATE_ZERO(1,6)
ACTIVATE_ZERO(1,7)

ACTIVATE_ZERO(2,1)
ACTIVATE_ZERO(2,2)
ACTIVATE_ZERO(2,3)
ACTIVATE_ZERO(2,4)
ACTIVATE_ZERO(2,5)
ACTIVATE_ZERO(2,6)
ACTIVATE_ZERO(2,7)

PREDICT(1)
PREDICT(2)
PREDICT(3)
PREDICT(4)
PREDICT(5)
PREDICT(6)
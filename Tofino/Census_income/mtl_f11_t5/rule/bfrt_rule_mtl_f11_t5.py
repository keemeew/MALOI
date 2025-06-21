import csv

#############################################################
################## Ingress pipeline rules ###################
#############################################################

file_path = 'weight_f11.csv'

p4_ingress = bfrt.maloi_f11_t5.pipe.SwitchIngress

tb_preprocess = p4_ingress.tb_preprocess
tb_XNOR_1 = p4_ingress.tb_XNOR_1
tb_XNOR_2 = p4_ingress.tb_XNOR_2
tb_XNOR_3 = p4_ingress.tb_XNOR_3
tb_XNOR_4 = p4_ingress.tb_XNOR_4
tb_XNOR_5 = p4_ingress.tb_XNOR_5
tb_forward = p4_ingress.tb_forward
tb_popcount1 = p4_ingress.tb_popcount1
tb_popcount2 = p4_ingress.tb_popcount2
tb_popcount3 = p4_ingress.tb_popcount3
tb_popcount4 = p4_ingress.tb_popcount4
tb_popcount5 = p4_ingress.tb_popcount5
tb_set_spaces = p4_ingress.tb_set_spaces

with open(f'{file_path}','r') as file:
    csv_file = csv.reader(file)
    next(csv_file)
    for i, line in enumerate(csv_file):
        cnt = int(line[0])
        weight1 = int(line[1])
        weight2 = int(line[2])
        weight3 = int(line[3])
        weight4 = int(line[4])
        weight5 = int(line[5])

        tb_preprocess.add_with_preprocessing(
            cnt = i,

            weight_1 = weight1,
            weight_2 = weight2,
            weight_3 = weight3,
            weight_4 = weight4,
            weight_5 = weight5,
        )
    
        if i < 66:
            tb_XNOR_1.add_with_XNOR_shared_1_1(
                cnt = i
            )
            tb_XNOR_2.add_with_XNOR_shared_1_2(
                cnt = i
            )
            tb_XNOR_3.add_with_XNOR_shared_1_3(
                cnt = i
            )
            tb_XNOR_4.add_with_XNOR_shared_1_4(
                cnt = i
            )
            tb_XNOR_5.add_with_XNOR_shared_1_5(
                cnt = i
            )
            tb_forward.add_with_do_recirculation1(
                cnt = i,
            )
        elif i < 132:
            tb_XNOR_1.add_with_XNOR_shared_2_1(
                cnt = i
            )
            tb_XNOR_2.add_with_XNOR_shared_2_2(
                cnt = i
            )
            tb_XNOR_3.add_with_XNOR_shared_2_3(
                cnt = i
            )
            tb_XNOR_4.add_with_XNOR_shared_2_4(
                cnt = i
            )
            tb_XNOR_5.add_with_XNOR_shared_2_5(
                cnt = i
            )
            tb_forward.add_with_do_recirculation2(
                cnt = i,
            )
        else:
            tb_XNOR_1.add_with_XNOR_task_specific_1(
                cnt = i
            )
            tb_XNOR_2.add_with_XNOR_task_specific_2(
                cnt = i
            )
            tb_XNOR_3.add_with_XNOR_task_specific_3(
                cnt = i
            )
            tb_XNOR_4.add_with_XNOR_task_specific_4(
                cnt = i
            )
            tb_XNOR_5.add_with_XNOR_task_specific_5(
                cnt = i
            )
            if i != 160:
                tb_forward.add_with_do_recirculation2(
                    cnt = i,
                )

tb_forward.add_with_set_egress_port(
    cnt = 160,
    egress_spec = 1
)

tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 0,
)

tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 66,
)

for i in range(4):
    binary_str = format(i, '02b')
    cnt = binary_str.count('1')
    tb_popcount1.add_with_popcount1(
        XNOROutput_1 = i,
        x = cnt
    )

m1  = 0x5555
m2  = 0x3333
m4  = 0x0f0f
m8  = 0x00ff

for i in range(65536):
    cnt = (i & m1 ) + ((i >> 1 ) & m1 )
    cnt = (cnt & m2 ) + ((cnt >> 2 ) & m2 )
    cnt = (cnt & m4 ) + ((cnt >> 4 ) & m4 )
    cnt = (cnt & m8 ) + ((cnt >> 8 ) & m8 )
    tb_popcount2.add_with_popcount2(
        XNOROutput_2 = i,
        x = cnt
    )
    tb_popcount3.add_with_popcount3(
        XNOROutput_3 = i,
        x = cnt
    )
    tb_popcount4.add_with_popcount4(
        XNOROutput_4 = i,
        x = cnt
    )
    tb_popcount5.add_with_popcount5(
        XNOROutput_5 = i,
        x = cnt
    )

#############################################################
################### Egress pipeline rules ###################
#############################################################

p4_egress = bfrt.maloi_f11_t5.pipe.SwitchEgress

tb_activate_one = p4_egress.tb_activate_one
tb_activate_zero = p4_egress.tb_activate_zero
tb_predict_task6 = p4_egress.tb_predict_task6
tb_predict_task12 = p4_egress.tb_predict_task12
tb_predict_task10 = p4_egress.tb_predict_task10
tb_predict_task2 = p4_egress.tb_predict_task2
tb_predict_task13 = p4_egress.tb_predict_task13
tb_real_predict_task6 = p4_egress.tb_real_predict_task6
tb_real_predict_task12 = p4_egress.tb_real_predict_task12
tb_real_predict_task10 = p4_egress.tb_real_predict_task10
tb_real_predict_task2 = p4_egress.tb_real_predict_task2
tb_real_predict_task13 = p4_egress.tb_real_predict_task13
tb_reset_registers6 = p4_egress.tb_reset_registers6
tb_reset_registers12 = p4_egress.tb_reset_registers12
tb_reset_registers10 = p4_egress.tb_reset_registers10
tb_reset_registers2 = p4_egress.tb_reset_registers2
tb_reset_registers13 = p4_egress.tb_reset_registers13

for i in range(1,162):
    if i < 3:
        tb_activate_one.add_with_activate1_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_1_zero(
            cnt = i
        )
    elif i < 19:
        tb_activate_one.add_with_activate1_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_2_zero(
            cnt = i
        )
    elif i < 35:
        tb_activate_one.add_with_activate1_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_3_zero(
            cnt = i
        )
    elif i < 51:
        tb_activate_one.add_with_activate1_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_4_zero(
            cnt = i
        )
    elif i < 67:
        tb_activate_one.add_with_activate1_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_5_zero(
            cnt = i
        )
    elif i < 69:
        tb_activate_one.add_with_activate2_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_1_zero(
            cnt = i
        )
    elif i < 85:
        tb_activate_one.add_with_activate2_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_2_zero(
            cnt = i
        )
    elif i < 101:
        tb_activate_one.add_with_activate2_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_3_zero(
            cnt = i
        )
    elif i < 117:
        tb_activate_one.add_with_activate2_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_4_zero(
            cnt = i
        )
    elif i < 133:
        tb_activate_one.add_with_activate2_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_5_zero(
            cnt = i
        )
    elif i < 141:
        tb_predict_task6.add_with_task6_predict(
            cnt = i
        )
        tb_real_predict_task6.add_with_real_task6_predict(
            cnt = i,
            x = i-133
        )
    elif i < 147:
        tb_predict_task12.add_with_task12_predict(
            cnt = i
        )
        tb_real_predict_task12.add_with_real_task12_predict(
            cnt = i,
            x = i-141
        )
    elif i < 150:
        tb_predict_task10.add_with_task10_predict(
            cnt = i
        )
        tb_real_predict_task10.add_with_real_task10_predict(
            cnt = i,
            x = i-147
        )
    elif i < 158:
        tb_predict_task2.add_with_task2_predict(
            cnt = i
        )
        tb_real_predict_task2.add_with_real_task2_predict(
            cnt = i,
            x = i-150
        )
    else:
        tb_predict_task13.add_with_task13_predict(
            cnt = i
        )
        tb_real_predict_task13.add_with_real_task13_predict(
            cnt = i,
            x = i-158
        )
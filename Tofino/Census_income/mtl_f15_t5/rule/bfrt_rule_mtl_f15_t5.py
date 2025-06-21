import csv

f = 15
t = 5

shared_layer = {15: 90}
total_task_layer = {5: 29}
task_seq = [13, 2, 10, 6, 12]
task_specific_layer = {13: 4,
                       2: 8,
                       10: 3,
                       6: 8,
                       12: 6}

#############################################################
################## Ingress pipeline rules ###################
#############################################################

file_path = 'weight_f15.csv'

p4_ingress = bfrt.maloi_f15_t5.pipe.SwitchIngress

tb_preprocess = p4_ingress.tb_preprocess
tb_forward = p4_ingress.tb_forward
tb_set_spaces = p4_ingress.tb_set_spaces

tb_XNOR_1 = p4_ingress.tb_XNOR_1
tb_XNOR_2 = p4_ingress.tb_XNOR_2
tb_popcount1 = p4_ingress.tb_popcount1
tb_popcount2 = p4_ingress.tb_popcount2
tb_XNOR_3 = p4_ingress.tb_XNOR_3
tb_XNOR_4 = p4_ingress.tb_XNOR_4
tb_popcount3 = p4_ingress.tb_popcount3
tb_popcount4 = p4_ingress.tb_popcount4
tb_XNOR_5 = p4_ingress.tb_XNOR_5
tb_XNOR_6 = p4_ingress.tb_XNOR_6
tb_popcount5 = p4_ingress.tb_popcount5
tb_popcount6 = p4_ingress.tb_popcount6

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
        weight6 = int(line[6])

        tb_preprocess.add_with_preprocessing(
            cnt = i,

            weight_1 = 0,
            weight_2 = 0,
            weight_3 = 0,
            weight_4 = 0,
            weight_5 = 0,
            weight_6 = 0
        )

        if i < shared_layer[f]:
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
            tb_XNOR_6.add_with_XNOR_shared_1_6(
                cnt = i
            )
            tb_forward.add_with_do_recirculation1(
                cnt = i,
            )
        elif i < 2* shared_layer[f]:
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
            tb_XNOR_6.add_with_XNOR_shared_1_6(
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
            tb_XNOR_6.add_with_XNOR_task_specific_6(
                cnt = i
            )
            if i != 2* shared_layer[f] + total_task_layer[t] - 1:
                tb_forward.add_with_do_recirculation2(
                    cnt = i,
                )

tb_forward.add_with_set_egress_port(
    cnt = 2* shared_layer[f] + total_task_layer[t] - 1,
    egress_spec = 185
)

tb_set_spaces.add_with_set_inteermediate_data_1_tst(
    cnt = 0,
)

tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = shared_layer[f],

)
for i in range(1024):
    binary_str = format(i, '010b')
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
    tb_popcount6.add_with_popcount6(
        XNOROutput_6 = i,
        x = cnt
    )

#############################################################
################### Egress pipeline rules ###################
#############################################################

p4_egress = bfrt.maloi_f15_t5.pipe.SwitchEgress

tb_activate_one = p4_egress.tb_activate_one
tb_activate_zero = p4_egress.tb_activate_zero
tb_predict_task13 = p4_egress.tb_predict_task13
tb_real_predict_task13 = p4_egress.tb_real_predict_task13
tb_reset_registers13 = p4_egress.tb_reset_registers13
tb_predict_task2 = p4_egress.tb_predict_task2
tb_predict_task10 = p4_egress.tb_predict_task10
tb_real_predict_task2 = p4_egress.tb_real_predict_task2
tb_real_predict_task10 = p4_egress.tb_real_predict_task10
tb_reset_registers2 = p4_egress.tb_reset_registers2
tb_reset_registers10 = p4_egress.tb_reset_registers10
tb_predict_task6 = p4_egress.tb_predict_task6
tb_predict_task12 = p4_egress.tb_predict_task12
tb_real_predict_task6 = p4_egress.tb_real_predict_task6
tb_real_predict_task12 = p4_egress.tb_real_predict_task12
tb_reset_registers6 = p4_egress.tb_reset_registers6
tb_reset_registers12 = p4_egress.tb_reset_registers12
tb_invalid = p4_egress.tb_invalid

for i in range(1,2* shared_layer[f] + total_task_layer[t] + 1):
    if i < 11:
        tb_activate_one.add_with_activate1_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_1_zero(
            cnt = i
        )
    elif i < 27:
        tb_activate_one.add_with_activate1_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_2_zero(
            cnt = i
        )
    elif i < 43:
        tb_activate_one.add_with_activate1_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_3_zero(
            cnt = i
        )
    elif i < 59:
        tb_activate_one.add_with_activate1_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_4_zero(
            cnt = i
        )
    elif i < 75:
        tb_activate_one.add_with_activate1_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_5_zero(
            cnt = i
        )
    elif i < 91:
        tb_activate_one.add_with_activate1_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_6_zero(
            cnt = i
        )
    elif i < 101:
        tb_activate_one.add_with_activate2_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_1_zero(
            cnt = i
        )
    elif i < 117:
        tb_activate_one.add_with_activate2_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_2_zero(
            cnt = i
        )
    elif i < 133:
        tb_activate_one.add_with_activate2_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_3_zero(
            cnt = i
        )
    elif i < 149:
        tb_activate_one.add_with_activate2_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_4_zero(
            cnt = i
        )
    elif i < 165:
        tb_activate_one.add_with_activate2_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_5_zero(
            cnt = i
        )
    elif i < 181:
        tb_activate_one.add_with_activate2_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_6_zero(
            cnt = i
        )
    elif i < 181 + task_specific_layer[13]:
        tb_predict_task13.add_with_task13_predict(
            cnt = i
        )
        tb_real_predict_task13.add_with_real_task13_predict(
            cnt = i,
            x = i-181
        )
    elif i < 181 + task_specific_layer[13] + task_specific_layer[2]:
        tb_predict_task2.add_with_task2_predict(
            cnt = i
        )
        tb_real_predict_task2.add_with_real_task2_predict(
            cnt = i,
            x = i-181-task_specific_layer[13]
        )
    elif i < 181 + task_specific_layer[13] + task_specific_layer[2] + task_specific_layer[10]:
        tb_predict_task10.add_with_task10_predict(
            cnt = i
        )
        tb_real_predict_task10.add_with_real_task10_predict(
            cnt = i,
            x = i-181-task_specific_layer[13]-task_specific_layer[2]
        )
    elif i < 181 + task_specific_layer[13] + task_specific_layer[2] + task_specific_layer[10] + task_specific_layer[6]:
        tb_predict_task6.add_with_task6_predict(
            cnt = i
        )
        tb_real_predict_task6.add_with_real_task6_predict(
            cnt = i,
            x = i-181-task_specific_layer[13]-task_specific_layer[2]-task_specific_layer[10]
        )
    elif i < 181 + task_specific_layer[13] + task_specific_layer[2] + task_specific_layer[10] + task_specific_layer[6] + task_specific_layer[12]:
        tb_predict_task12.add_with_task12_predict(
            cnt = i
        )
        tb_real_predict_task12.add_with_real_task12_predict(
            cnt = i,
            x = i-181-task_specific_layer[13]-task_specific_layer[2]-task_specific_layer[10]-task_specific_layer[6]
        )

cumulative_task_layer = 0
for i in range(t):
    cumulative_task_layer += task_specific_layer[task_seq[i]]

tb_invalid.add_with_invalid_header(
    cnt = shared_layer[f] * 2 + cumulative_task_layer
)
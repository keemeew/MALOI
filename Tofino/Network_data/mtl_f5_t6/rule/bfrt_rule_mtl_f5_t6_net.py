import csv

f = 5
t = 6
task_seq = [1, 2, 3, 4, 5, 6]
shared_layer = {5: 112}
total_task_layer = {6: 13}
task_specific_layer = {1: 2,
                       2: 2,
                       3: 2,
                       4: 2,
                       5: 2,
                       6: 3}

#############################################################
################## Ingress pipeline rules ###################
#############################################################

file_path = 'weight_f5.csv'

p4_ingress = bfrt.maloi_f5_t6_net.pipe.SwitchIngress

tb_preprocess = p4_ingress.tb_preprocess
tb_XNOR_1 = p4_ingress.tb_XNOR_1
tb_XNOR_2 = p4_ingress.tb_XNOR_2
tb_XNOR_3 = p4_ingress.tb_XNOR_3
tb_XNOR_4 = p4_ingress.tb_XNOR_4
tb_XNOR_5 = p4_ingress.tb_XNOR_5
tb_XNOR_6 = p4_ingress.tb_XNOR_6
tb_XNOR_7 = p4_ingress.tb_XNOR_7
tb_forward = p4_ingress.tb_forward
tb_popcount1 = p4_ingress.tb_popcount1
tb_popcount2 = p4_ingress.tb_popcount2
tb_popcount3 = p4_ingress.tb_popcount3
tb_popcount4 = p4_ingress.tb_popcount4
tb_popcount5 = p4_ingress.tb_popcount5
tb_popcount6 = p4_ingress.tb_popcount6
tb_popcount7 = p4_ingress.tb_popcount7
tb_set_spaces = p4_ingress.tb_set_spaces

with open(f'{file_path}','r') as file:
    csv_file = csv.reader(file)
    for i, line in enumerate(csv_file):
        
        weight1 = int(line[0])
        weight2 = int(line[1])
        weight3 = int(line[2])
        weight4 = int(line[3])
        weight5 = int(line[4])
        weight6 = int(line[5])
        weight7 = int(line[6])

        tb_preprocess.add_with_preprocessing(
            cnt = i,

            weight_1 = weight1,
            weight_2 = weight2,
            weight_3 = weight3,
            weight_4 = weight4,
            weight_5 = weight5,
            weight_6 = weight6,
            weight_7 = weight7
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
            tb_XNOR_7.add_with_XNOR_shared_1_7(
                cnt = i
            )
            tb_forward.add_with_do_recirculation1(
                cnt = i,
            )
        elif i < shared_layer[f] * 2:
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
            tb_XNOR_6.add_with_XNOR_shared_2_6(
                cnt = i
            )
            tb_XNOR_7.add_with_XNOR_shared_2_7(
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
            tb_XNOR_7.add_with_XNOR_task_specific_7(
                cnt = i
            )
            if i != shared_layer[f] * 2 + total_task_layer[t] - 1:
                tb_forward.add_with_do_recirculation2(
                    cnt = i,
                )

tb_forward.add_with_set_egress_port(
    cnt = shared_layer[f] * 2 + total_task_layer[t] - 1,
    egress_spec = 1
)

tb_set_spaces.add_with_set_inteermediate_data_1_tst(
    cnt = 0,
)

tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = shared_layer[f],
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
    tb_popcount1.add_with_popcount1(
        XNOROutput_1 = i,
        x = cnt
    )
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
    tb_popcount7.add_with_popcount7(
        XNOROutput_7 = i,
        x = cnt
    )

#############################################################
################### Egress pipeline rules ###################
#############################################################

p4_egress = bfrt.maloi_f5_t6_net.pipe.SwitchEgress

tb_activate_one = p4_egress.tb_activate_one
tb_activate_zero = p4_egress.tb_activate_zero
tb_predict_task1 = p4_egress.tb_predict_task1
tb_real_predict_task1 = p4_egress.tb_real_predict_task1
tb_predict_task2 = p4_egress.tb_predict_task2
tb_real_predict_task2 = p4_egress.tb_real_predict_task2
tb_predict_task3 = p4_egress.tb_predict_task3
tb_real_predict_task3 = p4_egress.tb_real_predict_task3
tb_predict_task4 = p4_egress.tb_predict_task4
tb_real_predict_task4 = p4_egress.tb_real_predict_task4
tb_predict_task5 = p4_egress.tb_predict_task5
tb_real_predict_task5 = p4_egress.tb_real_predict_task5
tb_predict_task6 = p4_egress.tb_predict_task6
tb_real_predict_task6 = p4_egress.tb_real_predict_task6
tb_invalid = p4_egress.tb_invalid

for i in range(1,2*shared_layer[f] + total_task_layer[t] + 1):
    if i < 17:
        tb_activate_one.add_with_activate1_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_1_zero(
            cnt = i
        )
    elif i < 33:
        tb_activate_one.add_with_activate1_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_2_zero(
            cnt = i
        )
    elif i < 49:
        tb_activate_one.add_with_activate1_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_3_zero(
            cnt = i
        )
    elif i < 65:
        tb_activate_one.add_with_activate1_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_4_zero(
            cnt = i
        )
    elif i < 81:
        tb_activate_one.add_with_activate1_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_5_zero(
            cnt = i
        )
    elif i < 97:
        tb_activate_one.add_with_activate1_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_6_zero(
            cnt = i
        )
    elif i < 113:
        tb_activate_one.add_with_activate1_7_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_7_zero(
            cnt = i
        )
    elif i < 129:
        tb_activate_one.add_with_activate2_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_1_zero(
            cnt = i
        )
    elif i < 145:
        tb_activate_one.add_with_activate2_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_2_zero(
            cnt = i
        )
    elif i < 161:
        tb_activate_one.add_with_activate2_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_3_zero(
            cnt = i
        )
    elif i < 177:
        tb_activate_one.add_with_activate2_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_4_zero(
            cnt = i
        )
    elif i < 193:
        tb_activate_one.add_with_activate2_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_5_zero(
            cnt = i
        )
    elif i < 209:
        tb_activate_one.add_with_activate2_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_6_zero(
            cnt = i
        )
    elif i < 225:
        tb_activate_one.add_with_activate2_7_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_7_zero(
            cnt = i
        )
    elif i < 227:
        tb_predict_task1.add_with_task1_predict(
            cnt = i
        )
        tb_real_predict_task1.add_with_real_task1_predict(
            cnt = i,
            x = i-225
        )
    elif i < 229:
        tb_predict_task2.add_with_task2_predict(
            cnt = i
        )
        tb_real_predict_task2.add_with_real_task2_predict(
            cnt = i,
            x = i-225-task_specific_layer[1]
        )
    elif i < 231:
        tb_predict_task3.add_with_task3_predict(
            cnt = i
        )
        tb_real_predict_task3.add_with_real_task3_predict(
            cnt = i,
            x = i-225-task_specific_layer[1]-task_specific_layer[2]
        )
    elif i < 233:
        tb_predict_task4.add_with_task4_predict(
            cnt = i
        )
        tb_real_predict_task4.add_with_real_task4_predict(
            cnt = i,
            x = i-225-task_specific_layer[1]-task_specific_layer[2]-task_specific_layer[3]
        )
    elif i < 235:
        tb_predict_task5.add_with_task5_predict(
            cnt = i
        )
        tb_real_predict_task5.add_with_real_task5_predict(
            cnt = i,
            x = i-225-task_specific_layer[1]-task_specific_layer[2]-task_specific_layer[3]-task_specific_layer[4]
        )
    elif i < 238:
        tb_predict_task6.add_with_task6_predict(
            cnt = i
        )
        tb_real_predict_task6.add_with_real_task6_predict(
            cnt = i,
            x = i-225-task_specific_layer[1]-task_specific_layer[2]-task_specific_layer[3]-task_specific_layer[4]-task_specific_layer[5]
        )

cumulative_task_layer = 0
for i in range(t):
    cumulative_task_layer += task_specific_layer[task_seq[i]]

tb_invalid.add_with_invalid_header(
    cnt = shared_layer[f] * 2 + cumulative_task_layer
)
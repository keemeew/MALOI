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

p4_ingress = bfrt.stl_f15_t5.pipe.SwitchIngress

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

weight1 = []
weight2 = []
weight3 = []
weight4 = []
weight5 = []
weight6 = []

with open(f'{file_path}','r') as file:
    csv_file = csv.reader(file)
    next(csv_file)
    for line in csv_file:
        weight1.apeend(int(line[0]))
        weight2.append(int(line[1]))
        weight3.append(int(line[2]))
        weight4.append(int(line[3]))
        weight5.append(int(line[4]))
        weight6.append(int(line[5]))

for i in range(2*shared_layer[f]*t + total_task_layer[t]):
    tb_preprocess.add_with_preprocessing(
            cnt = i,

            weight_1 = weight1[i%len(weight1)],
            weight_2 = weight2[i%len(weight2)],
            weight_3 = weight3[i%len(weight3)],
            weight_4 = weight4[i%len(weight4)],
            weight_5 = weight5[i%len(weight5)],
            weight_6 = weight6[i%len(weight6)],
    )

    if 0 <= i <= 89 or \
        184 <= i <= 273 or \
        372 <= i <= 461 or \
        555 <= i <= 644 or \
        743 <= i <= 832:
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
    elif 90 <= i <= 179 or \
         274 <= i <= 363 or \
         462 <= i <= 551 or \
         645 <= i <= 734 or \
         833 <= i <= 922:
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
        if i !=2* shared_layer[f] * t + total_task_layer[t] - 1:
            tb_forward.add_with_do_recirculation1(
                cnt = i,
            )
tb_forward.add_with_set_egress_port(
    cnt = 2* shared_layer[f] * t + total_task_layer[t] - 1,
    egress_spec = 185 
)

tb_set_spaces.add_with_set_inteermediate_data_1_tst(
    cnt = 0,
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 90,
)
tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 180+task_specific_layer[13],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 270+task_specific_layer[13],
)
tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 360 + task_specific_layer[13]+task_specific_layer[2],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 450 + task_specific_layer[13]+task_specific_layer[2],
)
tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 540 + task_specific_layer[13]+task_specific_layer[2]+task_specific_layer[10],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 630 + task_specific_layer[13]+task_specific_layer[2]+task_specific_layer[10],
)
tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 720 + task_specific_layer[13]+task_specific_layer[2]+task_specific_layer[10]+task_specific_layer[6],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 810 + task_specific_layer[13]+task_specific_layer[2]+task_specific_layer[10]+task_specific_layer[6],
)

for i in range(1024):
        binary_str = format(i, '010b')
        cnt = binary_str.count('1')
        tb_popcount1.add_with_popcount1(
            XNOROutput_1 = i,
            x = cnt
        )
print("finish popcount1")

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

p4_egress = bfrt.stl_f15_t5.pipe.SwitchEgress

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

for i in range(1, 2* shared_layer[f]*t + total_task_layer[t] + 1):
    if 1 <= i <= 10 or 185 <= i <= 194 or 373 <= i <= 382 or 556 <= i <= 565 or \
        744 <= i <= 753:
        tb_activate_one.add_with_activate1_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_1_zero(
            cnt = i
        )

    elif 91 <= i <= 100 or 275 <= i <= 284 or 463 <= i <= 472 or 646 <= i <= 655 or \
            834 <= i <= 843:
        tb_activate_one.add_with_activate2_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_1_zero(
            cnt = i
        )

    elif 11 <= i <= 26 or 195 <= i <= 210 or 383 <= i <= 398 or 566 <= i <= 581 or \
            754 <= i <= 769:
        tb_activate_one.add_with_activate1_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_2_zero(
            cnt = i
        )

    elif 101 <= i <= 116 or 285 <= i <= 300 or 473 <= i <= 488 or 656 <= i <= 671 or \
            844 <= i <= 859:
        tb_activate_one.add_with_activate2_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_2_zero(
            cnt = i
        )

    elif 27 <= i <= 42 or 211 <= i <= 226 or 399 <= i <= 414 or 582 <= i <= 597 or \
            770 <= i <= 785:
        tb_activate_one.add_with_activate1_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_3_zero(
            cnt = i
        )

    elif 117 <= i <= 132 or 301 <= i <= 316 or 489 <= i <= 504 or 672 <= i <= 687 or \
            860 <= i <= 875:
        tb_activate_one.add_with_activate2_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_3_zero(
            cnt = i
        )

    elif 43 <= i <= 58 or 227 <= i <= 242 or 415 <= i <= 430 or 598 <= i <= 613 or \
            786 <= i <= 801:
        tb_activate_one.add_with_activate1_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_4_zero(
            cnt = i
        )

    elif 133 <= i <= 148 or 317 <= i <= 332 or 505 <= i <= 520 or 688 <= i <= 703 or \
            876 <= i <= 891:
        tb_activate_one.add_with_activate2_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_4_zero(
            cnt = i
        )

    elif 59 <= i <= 74 or 243 <= i <= 258 or 431 <= i <= 446 or 614 <= i <= 629 or \
            802 <= i <= 817:
        tb_activate_one.add_with_activate1_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_5_zero(
            cnt = i
        )

    elif 149 <= i <= 164 or 333 <= i <= 348 or 521 <= i <= 536 or 704 <= i <= 719 or \
            892 <= i <= 907:
        tb_activate_one.add_with_activate2_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_5_zero(
            cnt = i
        )

    elif 75 <= i <= 90 or 259 <= i <= 274 or 447 <= i <= 462 or 630 <= i <= 645 or \
            818 <= i <= 833:
        tb_activate_one.add_with_activate1_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_6_zero(
            cnt = i
        )

    elif 165 <= i <= 180 or 349 <= i <= 364 or 537 <= i <= 552 or 720 <= i <= 735 or \
            908 <= i <= 923:
        tb_activate_one.add_with_activate2_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_6_zero(
            cnt = i
        )
    
    elif 2*shared_layer[f] + 1 <= i <= 2*shared_layer[f] + task_specific_layer[task_seq[0]]:
        tb_predict_task13.add_with_task13_predict(
            cnt = i
        )
        tb_real_predict_task13.add_with_real_task13_predict(
            cnt = i,
            x = i-180
        )
    elif 365 <= i <= 372:
        tb_predict_task2.add_with_task2_predict(
            cnt = i
        )
        tb_real_predict_task2.add_with_real_task2_predict(
            cnt = i,
            x = i-364
        )
    elif 553 <= i <= 555:
        tb_predict_task10.add_with_task10_predict(
            cnt = i
        )
        tb_real_predict_task10.add_with_real_task10_predict(
            cnt = i,
            x = i-552
        )
    elif 736 <= i <= 743:
        tb_predict_task6.add_with_task6_predict(
            cnt = i
        )
        tb_real_predict_task6.add_with_real_task6_predict(
            cnt = i,
            x = i-735
        )
    elif 924 <= i <= 929:
        tb_predict_task12.add_with_task12_predict(
            cnt = i
        )
        tb_real_predict_task12.add_with_real_task12_predict(
            cnt = i,
            x = i-923
        )

cumulative_task_layer = 0
for i in range(t):
    cumulative_task_layer += task_specific_layer[task_seq[i]]
    tb_invalid.add_with_invalid_header(
        cnt = (i+1)*shared_layer[f] * 2 + cumulative_task_layer
    )
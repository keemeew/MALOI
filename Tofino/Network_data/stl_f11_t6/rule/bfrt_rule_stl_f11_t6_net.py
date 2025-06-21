import csv

f = 11
t = 6
task_seq = [1, 2, 3, 4, 5, 6]
shared_layer = {11: 169}
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

file_path = 'weight_f11.csv'

p4_ingress = bfrt.stl_f11_t6_net.pipe.SwitchIngress

tb_preprocess1 = p4_ingress.tb_preprocess1
tb_preprocess2 = p4_ingress.tb_preprocess2
tb_XNOR_1 = p4_ingress.tb_XNOR_1
tb_XNOR_2 = p4_ingress.tb_XNOR_2
tb_XNOR_3 = p4_ingress.tb_XNOR_3
tb_XNOR_4 = p4_ingress.tb_XNOR_4
tb_XNOR_5 = p4_ingress.tb_XNOR_5
tb_XNOR_6 = p4_ingress.tb_XNOR_6
tb_XNOR_7 = p4_ingress.tb_XNOR_7
tb_XNOR_8 = p4_ingress.tb_XNOR_8
tb_XNOR_9 = p4_ingress.tb_XNOR_9
tb_XNOR_10 = p4_ingress.tb_XNOR_10
tb_XNOR_11 = p4_ingress.tb_XNOR_11
tb_forward = p4_ingress.tb_forward
tb_popcount1 = p4_ingress.tb_popcount1
tb_popcount2 = p4_ingress.tb_popcount2
tb_popcount3 = p4_ingress.tb_popcount3
tb_popcount4 = p4_ingress.tb_popcount4
tb_popcount5 = p4_ingress.tb_popcount5
tb_popcount6 = p4_ingress.tb_popcount6
tb_popcount7 = p4_ingress.tb_popcount7
tb_popcount8 = p4_ingress.tb_popcount8
tb_popcount9 = p4_ingress.tb_popcount9
tb_popcount10 = p4_ingress.tb_popcount10
tb_popcount11 = p4_ingress.tb_popcount11
tb_set_spaces = p4_ingress.tb_set_spaces

weight1 = []
weight2 = []
weight3 = []
weight4 = []
weight5 = []
weight6 = []
weight7 = []
weight8 = []
weight9 = []
weight10 = []
weight11 = []

with open(f'{file_path}','r') as file:
    csv_file = csv.reader(file)
    for line in csv_file:
        weight1.apeend(int(line[0],2))
        weight2.append(int(line[1],2))
        weight3.append(int(line[2],2))
        weight4.append(int(line[3],2))
        weight5.append(int(line[4],2))
        weight6.append(int(line[5],2))
        weight7.append(int(line[6],2))
        weight8.append(int(line[7],2))
        weight9.append(int(line[8],2))
        weight10.append(int(line[9],2))
        weight11.append(int(line[10],2))

for i in range(2*shared_layer[f]*t + total_task_layer[t]):
    tb_preprocess1.add_with_preprocessing1(
        cnt = i,

        weight_1 = weight1[i%len(weight1)],
        weight_2 = weight2[i%len(weight2)],
        weight_3 = weight3[i%len(weight3)],
        weight_4 = weight4[i%len(weight4)],
        weight_5 = weight5[i%len(weight5)],
        weight_6 = weight6[i%len(weight6)]
    )
    tb_preprocess2.add_with_preprocessing2(
        cnt = i,

        weight_7 = weight7[i%len(weight7)],
        weight_8 = weight8[i%len(weight8)],
        weight_9 = weight9[i%len(weight9)],
        weight_10 = weight10[i%len(weight10)],
        weight_11 = weight11[i%len(weight11)]
    )

    if 0 <= i <= shared_layer[f]-1 or \
        2*shared_layer[f] + task_specific_layer[0] <= i <= 3 * shared_layer[f] + task_specific_layer[0] - 1 or \
        4*shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] <= i <= 5 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] - 1 or \
        6*shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] <= i <= 7 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] - 1 or \
        8*shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] <= i <= 9 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] - 1 or \
        10*shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] + task_specific_layer[4] <= i <= 11 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] + task_specific_layer[4] - 1:
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
        tb_XNOR_8.add_with_XNOR_shared_1_8(
            cnt = i
        )
        tb_XNOR_9.add_with_XNOR_shared_1_9(
            cnt = i
        )
        tb_XNOR_10.add_with_XNOR_shared_1_10(
            cnt = i
        )
        tb_XNOR_11.add_with_XNOR_shared_1_11(
            cnt = i
        )
        tb_forward.add_with_do_recirculation1(
            cnt = i,
        )
    elif 1 * shared_layer[f] <= i <= 2 * shared_layer[f] - 1 or \
        3 * shared_layer[f] + task_specific_layer[0] <= i <= 4 * shared_layer[f] + task_specific_layer[0] - 1 or \
        5 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] <= i <= 6 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] - 1 or \
        7 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] <= i <= 8 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] - 1 or \
        9 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] <= i <= 10 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] - 1 or \
        11 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] + task_specific_layer[4] <= i <= 12 * shared_layer[f] + task_specific_layer[0] + task_specific_layer[1] + task_specific_layer[2] + task_specific_layer[3] + task_specific_layer[4] - 1:
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
        tb_XNOR_8.add_with_XNOR_shared_2_8(
            cnt = i
        )
        tb_XNOR_9.add_with_XNOR_shared_2_9(
            cnt = i
        )
        tb_XNOR_10.add_with_XNOR_shared_2_10(
            cnt = i
        )
        tb_XNOR_11.add_with_XNOR_shared_2_11(
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
        tb_XNOR_8.add_with_XNOR_task_specific_8(
            cnt = i
        )
        tb_XNOR_9.add_with_XNOR_task_specific_9(
            cnt = i
        )
        tb_XNOR_10.add_with_XNOR_task_specific_10(
            cnt = i
        )
        tb_XNOR_11.add_with_XNOR_task_specific_11(
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
    cnt = 1 * shared_layer[f],
)

tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 2 * shared_layer[f] + total_task_layer[1],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 3 * shared_layer[f] + total_task_layer[1],
)

tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 4 * shared_layer[f] + total_task_layer[1] + total_task_layer[2],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 5 * shared_layer[f]+ total_task_layer[1] + total_task_layer[2],
)

tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 6 * shared_layer[f] + total_task_layer[1] + total_task_layer[2]+ total_task_layer[3],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 7 * shared_layer[f] + total_task_layer[1] + total_task_layer[2]+ total_task_layer[3],
)

tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 8 * shared_layer[f] + total_task_layer[1] + total_task_layer[2]+ total_task_layer[3] + total_task_layer[4],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 9 * shared_layer[f] + total_task_layer[1] + total_task_layer[2]+ total_task_layer[3] + total_task_layer[4],
)

tb_set_spaces.add_with_set_inteermediate_data_1(
    cnt = 10 * shared_layer[f] + total_task_layer[1] + total_task_layer[2]+ total_task_layer[3] + total_task_layer[4] + total_task_layer[5],
)
tb_set_spaces.add_with_set_inteermediate_data_2(
    cnt = 11 * shared_layer[f] + total_task_layer[1] + total_task_layer[2]+ total_task_layer[3] + total_task_layer[4] + total_task_layer[5],
)

for i in range(512):
    binary_str = format(i, '09b')
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
    tb_popcount7.add_with_popcount7(
        XNOROutput_7 = i,
        x = cnt
    )
    tb_popcount8.add_with_popcount8(
        XNOROutput_8 = i,
        x = cnt
    )
    tb_popcount9.add_with_popcount9(
        XNOROutput_9 = i,
        x = cnt
    )
    tb_popcount10.add_with_popcount10(
        XNOROutput_10 = i,
        x = cnt
    )
    tb_popcount11.add_with_popcount11(
        XNOROutput_11 = i,
        x = cnt
    )

#############################################################
################### Egress pipeline rules ###################
#############################################################

p4_egress = bfrt.stl_f11_t6_net.pipe.SwitchEgress

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

for i in range(1,2*shared_layer[f]+t + total_task_layer[t] + 1):
    if  1 <= i <= 9 or \
        341 <= i <= 349 or \
        681 <= i <= 689 or \
        1021 <= i <= 1029 or \
        1361 <= i <= 1369 or \
        1701 <= i <= 1709:
        tb_activate_one.add_with_activate1_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_1_zero(
            cnt = i
        )
    elif 10 <= i <= 25 or \
         350 <= i <= 365 or \
         690 <= i <= 705 or \
         1030 <= i <= 1045 or \
         1370 <= i <= 1385 or \
         1710 <= i <= 1725:
        tb_activate_one.add_with_activate1_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_2_zero(
            cnt = i
        )
    elif 26 <= i <= 41 or \
         366 <= i <= 381 or \
         706 <= i <= 721 or \
         1046 <= i <= 1061 or \
         1386 <= i <= 1401 or \
         1726 <= i <= 1741:
        tb_activate_one.add_with_activate1_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_3_zero(
            cnt = i
        )
    elif 42 <= i <= 57 or \
         382 <= i <= 397 or \
         722 <= i <= 737 or \
         1062 <= i <= 1077 or \
         1402 <= i <= 1417 or \
         1742 <= i <= 1757:
        tb_activate_one.add_with_activate1_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_4_zero(
            cnt = i
        )
    elif 58 <= i <= 73 or \
         398 <= i <= 413 or \
         738 <= i <= 753 or \
         1078 <= i <= 1093 or \
         1418 <= i <= 1433 or \
         1758 <= i <= 1773:
        tb_activate_one.add_with_activate1_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_5_zero(
            cnt = i
        )
    elif 74 <= i <= 89 or \
         414 <= i <= 429 or \
         754 <= i <= 769 or \
         1094 <= i <= 1109 or \
         1434 <= i <= 1449 or \
         1774 <= i <= 1789:
        tb_activate_one.add_with_activate1_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_6_zero(
            cnt = i
        )
    elif 90 <= i <= 105 or \
         430 <= i <= 445 or \
         770 <= i <= 785 or \
         1110 <= i <= 1125 or \
         1450 <= i <= 1465 or \
         1790 <= i <= 1805:
        tb_activate_one.add_with_activate1_7_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_7_zero(
            cnt = i
        )
    elif 106 <= i <= 121 or \
         446 <= i <= 461 or \
         786 <= i <= 801 or \
         1126 <= i <= 1141 or \
         1466 <= i <= 1481 or \
         1806 <= i <= 1821:
        tb_activate_one.add_with_activate1_8_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_8_zero(
            cnt = i
        )
    elif 122 <= i <= 137 or \
         462 <= i <= 477 or \
         802 <= i <= 817 or \
         1142 <= i <= 1157 or \
         1482 <= i <= 1497 or \
         1822 <= i <= 1837:
        tb_activate_one.add_with_activate1_9_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_9_zero(
            cnt = i
        )
    elif 138 <= i <= 153 or \
         478 <= i <= 493 or \
         818 <= i <= 833 or \
         1158 <= i <= 1173 or \
         1498 <= i <= 1513 or \
         1838 <= i <= 1853:
        tb_activate_one.add_with_activate1_10_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_10_zero(
            cnt = i
        )
    elif 154 <= i <= 169 or \
         494 <= i <= 509 or \
         834 <= i <= 849 or \
         1174 <= i <= 1189 or \
         1514 <= i <= 1529 or \
         1854 <= i <= 1869:    
        tb_activate_one.add_with_activate1_11_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate1_11_zero(
            cnt = i
        )
    elif 170 <= i <= 178 or \
         510 <= i <= 518 or \
         850 <= i <= 858 or \
         1190 <= i <= 1198 or \
         1530 <= i <= 1538 or \
         1870 <= i <= 1878:
        tb_activate_one.add_with_activate2_1_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_1_zero(
            cnt = i
        )
    elif 179 <= i <= 194 or \
         519 <= i <= 534 or \
         859 <= i <= 874 or \
         1199 <= i <= 1214 or \
         1539 <= i <= 1554 or \
         1879 <= i <= 1894:
        tb_activate_one.add_with_activate2_2_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_2_zero(
            cnt = i
        )
    elif 195 <= i <= 210 or \
         535 <= i <= 550 or \
         875 <= i <= 890 or \
         1215 <= i <= 1230 or \
         1555 <= i <= 1570 or \
         1895 <= i <= 1910:
        tb_activate_one.add_with_activate2_3_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_3_zero(
            cnt = i
        )
    elif 211 <= i <= 226 or \
         551 <= i <= 566 or \
         891 <= i <= 906 or \
         1231 <= i <= 1246 or \
         1571 <= i <= 1586 or \
         1911 <= i <= 1926:
        tb_activate_one.add_with_activate2_4_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_4_zero(
            cnt = i
        )
    elif 227 <= i <= 242 or \
         567 <= i <= 582 or \
         907 <= i <= 922 or \
         1247 <= i <= 1262 or \
         1587 <= i <= 1602 or \
         1927 <= i <= 1942:
        tb_activate_one.add_with_activate2_5_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_5_zero(
            cnt = i
        )
    elif 243 <= i <= 258 or \
         583 <= i <= 598 or \
         923 <= i <= 938 or \
         1263 <= i <= 1278 or \
         1603 <= i <= 1618 or \
         1943 <= i <= 1958:
        tb_activate_one.add_with_activate2_6_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_6_zero(
            cnt = i
        )
    elif 259 <= i <= 274 or \
         599 <= i <= 614 or \
         939 <= i <= 954 or \
         1279 <= i <= 1294 or \
         1619 <= i <= 1634 or \
         1959 <= i <= 1974:
        tb_activate_one.add_with_activate2_7_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_7_zero(
            cnt = i
        )
    elif 275 <= i <= 290 or \
         615 <= i <= 630 or \
         955 <= i <= 970 or \
         1295 <= i <= 1310 or \
         1635 <= i <= 1650 or \
         1975 <= i <= 1990:
        tb_activate_one.add_with_activate2_8_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_8_zero(
            cnt = i
        )
    elif 291 <= i <= 306 or \
         631 <= i <= 646 or \
         971 <= i <= 986 or \
         1311 <= i <= 1326 or \
         1651 <= i <= 1666 or \
         1991 <= i <= 2006:
        tb_activate_one.add_with_activate2_9_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_9_zero(
            cnt = i
        )
    elif 307 <= i <= 322 or \
         647 <= i <= 662 or \
         987 <= i <= 1002 or \
         1327 <= i <= 1342 or \
         1667 <= i <= 1682 or \
         2007 <= i <= 2022:
        tb_activate_one.add_with_activate2_10_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_10_zero(
            cnt = i
        )
    elif 323 <= i <= 338 or \
         663 <= i <= 678 or \
         1003 <= i <= 1018 or \
         1343 <= i <= 1358 or \
         1683 <= i <= 1698 or \
         2023 <= i <= 2038:
        tb_activate_one.add_with_activate2_11_one(
            cnt = i
        )
        tb_activate_zero.add_with_activate2_11_zero(
            cnt = i
        )
    elif 339 <= i <= 340:
        tb_predict_task1.add_with_task1_predict(
            cnt = i
        )
        tb_real_predict_task1.add_with_real_task1_predict(
            cnt = i,
            x = i-339
        )
    elif 679 <= i <= 680:
        tb_predict_task2.add_with_task2_predict(
            cnt = i
        )
        tb_real_predict_task2.add_with_real_task2_predict(
            cnt = i,
            x = i-679
        )
    elif 1019 <= i <= 1020:
        tb_predict_task3.add_with_task3_predict(
            cnt = i
        )
        tb_real_predict_task3.add_with_real_task3_predict(
            cnt = i,
            x = i-1019
        )
    elif 1359 <= i <= 1360:
        tb_predict_task4.add_with_task4_predict(
            cnt = i
        )
        tb_real_predict_task4.add_with_real_task4_predict(
            cnt = i,
            x = i-1359
        )
    elif 1699 <= i <= 1700:
        tb_predict_task5.add_with_task5_predict(
            cnt = i
        )
        tb_real_predict_task5.add_with_real_task5_predict(
            cnt = i,
            x = i-1699
        )
    elif 2039 <= i <= 2041:
        tb_predict_task6.add_with_task6_predict(
            cnt = i
        )
        tb_real_predict_task6.add_with_real_task6_predict(
            cnt = i,
            x = i-2039
        )

cumulative_task_layer = 0
for i in range(t):
    cumulative_task_layer += task_specific_layer[task_seq[i]]
    tb_invalid.add_with_invalid_header(
        cnt = (i+1)*shared_layer[f] * 2 + cumulative_task_layer
    )
#!/bin/bash
MODE=$1

if [ "${MODE}" == "mtl" ] ; then
    for FEATURE in {11..11..5}
    do
        for TASK in {5..5..2}
        do
            cd /home/mnc/mnc/MARTINI/magazine
            make clean
            wait

            echo "nohup /home/mnc/mnc/MARTINI/magazine/insert_rule.sh $MODE $FEATURE $TASK &" >> /home/mnc/mnc/MARTINI/magazine/results/log.txt
            nohup /home/mnc/mnc/MARTINI/magazine/insert_rule.sh $MODE $FEATURE $TASK &

            echo "make $MODE"_"$FEATURE"_"$TASK" >> /home/mnc/mnc/MARTINI/magazine/results/log.txt
            make $MODE"_"$FEATURE"_"$TASK

            wait

            python3 /home/mnc/mnc/MARTINI/magazine/e2e_latency.py --mode $MODE --f $FEATURE --t $TASK
        done
    done
fi

if [ "${MODE}" == "stl" ] ; then
    for FEATURE in {15..15..5}
    do
        for TASK in {5..5..2}
        do
            cd /home/mnc/mnc/MARTINI/magazine
            make clean
            wait

            echo "nohup /home/mnc/mnc/MARTINI/magazine/insert_rule.sh $MODE $FEATURE $TASK &" >> /home/mnc/mnc/MARTINI/magazine/results/log.txt
            nohup /home/mnc/mnc/MARTINI/magazine/insert_rule.sh $MODE $FEATURE $TASK &

            echo "make $MODE"_"$FEATURE"_"$TASK" >> /home/mnc/mnc/MARTINI/magazine/results/log.txt
            make $MODE"_"$FEATURE"_"$TASK

            wait

            python3 /home/mnc/mnc/MARTINI/magazine/e2e_latency.py --mode $MODE --f $FEATURE --t $TASK
        done
    done
fi
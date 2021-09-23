#!/usr/bin/env python
# coding: utf-8

import pandas
import load
from pyod.models.feature_bagging import FeatureBagging # 90
from pyod.models.hbos import HBOS ## 90
import warnings
import joblib


def train_conn_FeatureBagging(conn,con):

    df_conn = pandas.DataFrame(conn)
    features = [
        'duration', 'orig_bytes', 'resp_bytes', 'orig_ip_bytes', 
        'resp_pkts', 'resp_ip_bytes', 'id_resp_p'
    ]
    # HBOS is the base detector
    # HBOS -> n_bins = 3 / 4 
    clf = FeatureBagging(base_estimator = HBOS(n_bins = 4),contamination = con)
    clf.fit(df_conn[features])
    # get the prediction on the test data
    # outlier labels (0 or 1)
    predictions = clf.predict(df_conn[features])
    # outlier scores
    outlier_scores = clf.decision_function(df_conn[features])
    # save model
    joblib.dump(clf, 'FeatureBagging')

    df_conn['score'] = pandas.Series(outlier_scores)
    df_conn['prediction'] = pandas.Series(predictions)
    anomaly = df_conn[df_conn['prediction']==1]
    anomaly = anomaly.sort_values(by='score',ascending=False)
    display_amomaly = anomaly.copy()
    print('odd_df length', len(anomaly))


    display_amomaly = display_amomaly.drop(['proto','service','proto','duration','orig_bytes','resp_bytes',
                                    'orig_ip_bytes','resp_pkts','resp_ip_bytes','prediction'], axis=1)
    display_amomaly.to_csv('anomaly_FeatureBagging.csv', encoding='utf-8')
    #g = list(display_amomaly.groupby(['id_resp_h','score']))
    g = list(display_amomaly.groupby(['id_resp_h']))
    # sort by the score in descending order
    ttt = sorted(g, key=lambda x: x[0][1],reverse=True)
    print('%-15s' %'destination ip\t  anomaly number')

    for name, group in g:
        print('%-15s' % str(name), '\t', len(group))
    print('\n')

    index = list(display_amomaly['idx'])
    return index


''' train conn.log'''
attacker_ip = '192.168.2.30'
f1 = open('./attack/zip/attack_zeek_conn.json', 'r', encoding='utf-8')
conn_attack,t1, idx = load.load_conn(f1,0,'192.168.2.30')
f1.close()

# f2 = open('./normal/normal_zeek_conn.json', 'r', encoding='utf-8')
# conn_normal,t2,idx = load.load_conn(f2,idx,'192.168.2.30')
# #conn_normal,idx = load_conn(f2,0)
# f2.close()
#conn = conn_normal

f2 = open('./normal/normal_conn_0426.json', 'r', encoding='utf-8')
conn_normal, true_anomaly_2, idx = load.load_conn(f2,idx,attacker_ip)
f2.close()

f3 = open('./normal/normal_conn_0427.json', 'r', encoding='utf-8')
conn_normal_1, true_anomaly_3, idx = load.load_conn(f3,idx,attacker_ip)
f3.close()

f4 = open('./normal/normal_conn_0428.json', 'r', encoding='utf-8')
conn_normal_2, true_anomaly_4, idx = load.load_conn(f4,idx,attacker_ip)
f4.close()

f5 = open('./normal/normal_conn_0429.json', 'r', encoding='utf-8')
conn_normal_3, true_anomaly_5, idx = load.load_conn(f5,idx,attacker_ip)
f5.close()

f6 = open('./normal/normal_conn_0430.json', 'r', encoding='utf-8')
conn_normal_4, true_anomaly_6, idx = load.load_conn(f6,idx,attacker_ip)
f6.close()


# ignore all warnings
warnings.filterwarnings("ignore")
#loadfile()

conn = conn_attack + conn_normal + conn_normal_1 + conn_normal_2 + conn_normal_3 + conn_normal_4
# use featurebagging to train model
conn_FeatureBagging = train_conn_FeatureBagging(conn,0.03)

# conn = conn_attack + conn_normal # -> 14 ~ 105

# table = [[conn1,0.01,0.03,0.07,0.01],[conn2,0.01,0.02,0.06,0.01],[conn3,0.01,0.01,0.06,0.01],
#         [conn4,0.01,0.01,0.05,0.01],[conn5,0.01,0.05,0.12,0.01],
#         [conn6,0.01,0.02,0.07,0.01],[conn,0.001,0.003,0.05,0.001]]





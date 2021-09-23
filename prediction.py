#!/usr/bin/env python
# coding: utf-8


import pandas
import load
import os
import sys
import joblib
import warnings


def predict_conn(conn,model):
    index_list = []
    df_conn = pandas.DataFrame(conn)

    features = [
        'duration', 'orig_bytes', 'resp_bytes', 'orig_ip_bytes', 
        'resp_pkts', 'resp_ip_bytes', 'id_resp_p'
    ]

    clf = joblib.load(model)
    predictions = clf.predict(df_conn[features])
    # outlier scores
    outlier_scores = clf.decision_function(df_conn[features])

    df_conn['score'] = pandas.Series(outlier_scores)
    df_conn['prediction'] = pandas.Series(predictions)
    anomaly = df_conn[df_conn['prediction']==1]
    anomaly = anomaly.sort_values(by='score',ascending=False)
    display_amomaly = anomaly.copy()
    print('odd_df length', len(anomaly))


    display_amomaly = display_amomaly.drop(['proto','service','proto','duration','orig_bytes','resp_bytes',
                                    'orig_ip_bytes','resp_pkts','resp_ip_bytes','prediction'], axis=1)
    
    #display_amomaly.to_csv('./test/normal/'+'anomaly_'+conn_name+'_'+model[5:5+len(model)-12]+'.csv', 
    #                        encoding='utf-8')
    g = display_amomaly['idx'].groupby(display_amomaly['id_resp_h'])
    print('destination ip \t\t anomaly number')
    for name, group in g:
        print('%-15s' % name, '\t', len(group))

    index = list(display_amomaly['idx'])
    
    return index

def relation(conn_index,conn,sysmon,security):

    sysmon_3 = []
    security_5156 = []
    for conn_idx in conn_index:
        conn_info = list(filter(lambda i: i['idx'] == conn_idx ,conn))
        candidates_3 = list(
            filter(
                lambda i: conn_info[0]['proto'] == i['Protocol'] and conn_info[0]['id_orig_h']
                == i['SourceIp'] and str(conn_info[0]['id_orig_p']) == str(
                    i['SourcePort']) and conn_info[0]['id_resp_h'] == i[
                        'DestinationIp'] and str(conn_info[0]['id_resp_p']) == str(
                            i['DestinationPort']), sysmon))
        #print(candidates_3)
        for i in candidates_3:
            #print(abs((conn_info['time'] - i['time']).total_seconds()))
            if (abs((conn_info[0]['time'] - i['time']).total_seconds()) < 60):
                if ((i['record_id'],int(i['ProcessId']))) not in sysmon_3:
                    sysmon_3.append((i['record_id'],int(i['ProcessId'])))
                
        #############################################################################
        candidates_5156 = list(
            filter(
                lambda i: conn_info[0]['proto'] == i['Protocol'] and conn_info[0]['id_orig_h']
                == i['SourceIp'] and str(conn_info[0]['id_orig_p']) == str(
                    i['SourcePort']) and conn_info[0]['id_resp_h'] == i[
                        'DestinationIp'] and str(conn_info[0]['id_resp_p']) == str(
                            i['DestinationPort']), security))
        
        for i in candidates_5156:
            #print(abs((conn_info['time'] - i['time']).total_seconds()))
            if (abs((conn_info[0]['time'] - i['time']).total_seconds()) < 60):
                tmp = (i['record_id'],int(i['ProcessId']))
                if tmp not in security_5156:
                    security_5156.append(tmp)
                
    return sysmon_3

def network_performance(detected_anomaly,true_anomaly,conn_len):
    #print('True Positive: ', end = '')
    tp=0
    tp_idx = []
    # detected_anomaly -> detected anomaly log
    # true_anomaly -> true anomaly log
    for log in detected_anomaly:
        if log in true_anomaly:
            tp += 1
            tp_idx.append(log)
    #print(tp)

    #print('False Positive: ', end = '')
    #fp-> log in detected anomaly but not true anomaly log
    fp = len(detected_anomaly) - tp
    fp_idx = []
    for log in detected_anomaly:
        if log not in true_anomaly:
            fp_idx.append(log)
    #print(fp)

    #print('False Negative: ', end = '')
    #fn-> true anomaly logs without being detected
    fn = 0
    fn_idx = []
    for log in true_anomaly:
        if log not in detected_anomaly:
            fn_idx.append(log)
            fn += 1
    #print(fn) 

    #print('True Negative: ', end = '')
    tn = conn_len - tp - fp - fn
    #print(tn)

    #print("--------------------")
    print('accuracy: ',(tp+tn)/(tp+fp+fn+tn))
    print('precision: ',tp/(tp+fp))
    print('recall: ',tp/(tp+fn))
    print('F1: ',(2*tp)/(2*tp+fp+fn))
#!/usr/bin/env python
# coding: utf-8

# In[1]:


def draw(parent_key,threshold,real_source,zip_source,malicious):
    from graphviz import Digraph
    print("THRESHOLD:",threshold)
    visit=[]
    attack_loop = 0
    for i in range(len(parent_key)):
        #print("#############THIS IS ",i+1," LOOPS ######################")
        draw = False
        q=[parent_key[i]]
        if parent_key[i] in visit:
            continue
        dot = Digraph(comment='Log Traceback Loop')
        horizontal_sysmon(parent_key[i],i+1)
        index=-1
#     for j in range(len(ancestor)):
#         if q[0][0]==ancestor[j][0] and q[0][1]==ancestor[j][3]:
#             dot.edge(str(ancestor[j][-1]),str(q[0][1]))
        while q:
            current=q.pop()
        #print("visit:",visit)
            #print("current:",current)
            if current==threshold:
                attack_loop=i+1
                horizontal_sysmon(current,i+1)
                #print("source found")
                dot.edge(str(real_source[1]),str(current[1]))
                horizontal_sysmon(real_source,i+1)
                if current in malicious:
                    draw=True
                    dot.attr('node',color="red")
                else:
                    dot.attr('node',color="black")
                if zip_source != (-1,-1):
                    #print("zip source found")
                    #print("zip source:",zip_source)
                    horizontal_sysmon(zip_source,i+1)
                    dot.edge(str(zip_source[1]),str(real_source[1]))
                    if zip_source in malicious:
                        dot.attr('node',color="red")
                    else:
                        dot.attr('node',color="black")
                
            
            visit.append(current)
            try:
                for child in horizontal_relationship[current]:
                #dot.node()
                    horizontal_sysmon(child,i+1)
                    if child in malicious:
                        #draw = True
                        dot.attr('node',color="red")
                    else:
                        dot.attr('node',color="black")
                    dot.edge(str(current[1]),str(child[1]))
                    q.append(child)
                    visit.append(child)
            except:
                #print("no child!")
                continue
        #print(dot.source)
        if draw:
            filename="traceback_"+str(i+1)+".gv"
            dot.render("./trace_graph/"+filename, view=True)
    #break
        
    return attack_loop


# In[2]:


def horizontal_security(tryy,time_end,group_num):
    #print(tryy,time_end)
    #get the start time of the program
    ######################
    conn_db = sqlite3.connect("log_mix.db")
    conn = conn_db.cursor()
    conn.execute("SELECT time from sysmon WHERE record_id==? AND pid==?",tryy)
    ti=conn.fetchall()
#     print(ti)
#     print("end time:", time_end)
    
    #print(ti[0][0])
    separate=ti[0][0].split(":")
    #print(separate)
    minute=str(int(separate[1])-1)
    time_start=separate[0]+":"+minute+":"+separate[2]
    #print("timestart:",time_start)
    ################################
    t=(tryy[1],time_start,time_end,)
    conn.execute("SELECT record_id,pid FROM security WHERE pid==? AND time BETWEEN ? And ? ORDER BY time",t)
    res=conn.fetchall()
    #print("-------")
    #print(len(res))
#     for i in res:
#         print(i)
    t=(group_num,tryy[1],time_start,time_end)
    conn_db.execute("UPDATE security SET group_id=? WHERE pid==? AND time BETWEEN ? And ?",t)
    conn_db.commit()
    #print("----------------------")
    conn.execute("SELECT group_id,record_id,pid FROM security WHERE group_id>0")
    res=conn.fetchall()
    #print(res)


# In[3]:


## new part
#tryy is a tuple (record_id,pid)
def horizontal_sysmon(tryy,group_num):
    conn_db = sqlite3.connect("log_mix.db")
    #for i in range(1):
    conn=conn_db.cursor()
    #get the range of data
    t=(tryy[1],tryy[0],)
    conn.execute("SELECT record_id,pid,time FROM sysmon where sysmon.event_id==1 AND sysmon.pid==? and sysmon.record_id >?",t)
    result=conn.fetchall()
    result.sort()
    try:
        end_rid = result[0][0]
        time_end = result[0][2]
    except:
        end_rid = 99999999999999
        time_end = '3021-05-14T15:27:42.749Z'
#     print("end record id:",end_rid)
#     print("end time:",time_end)
    t=(tryy[1],tryy[0]-100,end_rid,)
    ####### extend to windows security log ######
    horizontal_security(tryy,time_end,group_num)
    ####### extend end ##########################
    conn.execute("SELECT event_id,pid,record_id FROM sysmon where sysmon.pid==? and sysmon.record_id BETWEEN ? And ?",t)
    result=conn.fetchall()
    #print("result",result)
    for dat in result:
        t=(group_num,dat[1],dat[2],)
        #print("t=",t)
        conn_db.execute("UPDATE sysmon SET group_id=? WHERE sysmon.pid==? AND sysmon.record_id==?",t)
        conn_db.commit()
    
    t=(group_num,)
    conn.execute("SELECT group_id,event_id,pid,record_id FROM sysmon where sysmon.group_id==?",t)
    res=conn.fetchall()
#     print("LENGTH IS ", len(res))
#     print("succeed?:",res)
#     print("--------------------------")


# In[4]:


import json
import pandas
import datetime
import time
import math
import os,sys
import joblib
import warnings
import threading
import queue
import load
import prediction
import system_prediction
import sqlite3
import trace_back
#from graphviz import Digraph


# In[5]:




def system(x_test, out_queue):
    system_idx = system_prediction.predict(x_test)
    out_queue.put(system_idx)

def network(conn, true_anomaly, network_model,out_queue):
    conn_idx = prediction.predict_conn(conn, network_model)
    '''network performance'''
    prediction.network_performance(conn_idx,true_anomaly,len(conn))
    sysmon_3 = sysmon_attack_3 + sysmon_normal_3
    security_5156 = security_attack_5156 + security_normal_5156

    # network index -> traceback
    network_idx = prediction.relation(conn_idx, conn,sysmon_3, security_5156)
    # put into a queue
    out_queue.put(network_idx)
    

warnings.filterwarnings("ignore")
network_model = './joblib/conn_FeatureBagging.joblib'
attacker_ip = '192.168.2.30'

'''load file'''
# nework attack 
f1 = open('./log/attack/zip/attack_zeek_conn.json', 'r', encoding='utf-8')
conn_attack, true_anomaly_1, idx = load.load_conn(f1,0,attacker_ip)
f1.close()
# network normal
f2 = open('./log/normal/normal_conn_0410.json', 'r', encoding='utf-8')
conn_normal, true_anomaly_2, idx = load.load_conn(f2,idx,attacker_ip)
f2.close()

# system attack
f3 = open('./log/attack/zip/attack_system.json', 'r', encoding='utf-8')
system_attack, sysmon_attack_3,security_attack_5156, sysmon_attack, microsoft_powershell_attack, powershell_attack, security_trace_attack, idx= load.load_system(f3,0)
f3.close()
# system normal
f4 = open('./log/normal/normal_system_0410.json', 'r', encoding='utf-8')
system_normal, sysmon_normal_3,security_normal_5156, sysmon_normal, microsoft_powershell_normal, powershell_normal, security_trace_normal, idx= load.load_system(f4,idx)
f4.close()

'''prediction'''


# a new thread for predicting network
# network
conn = conn_attack + conn_normal
true_anomaly = true_anomaly_1 + true_anomaly_2 

network_que = queue.Queue()
network_thread = threading.Thread(target = network,args=(conn, true_anomaly, network_model,network_que))
network_thread.start()


# a new thread for predicting system
# system
x_test = system_attack + system_normal[:10000]
sys_que = queue.Queue()
system_thread = threading.Thread(target = system,args=(x_test, sys_que))
system_thread.start()

'''traceback'''
sysmon = sysmon_attack + sysmon_normal
microsoft_powershell = microsoft_powershell_attack + microsoft_powershell_normal
powershell = powershell_attack + powershell_normal
security_trace = security_trace_attack + security_trace_normal
print("sysmon length:",len(sysmon))
print("security length:",len(security_trace))
################
# insert table #
################

# get anomaly list from queue and put into mal

network_thread.join()
network_idx = network_que.get()
system_thread.join()
sys_idx = sys_que.get()
mal_sysmon,mal_security,mal_powershell,mal_m_powershell = trace_back.sort_detected_log(sys_idx)
mal = network_idx + mal_sysmon
#mal = network_idx
print("Suspicious logs:",mal)

# traceback ...





# In[6]:


#print(mal)


# In[7]:


# trace_back.create_table()
# trace_back.insert_table(sysmon,security_trace,powershell,microsoft_powershell)


# In[8]:


trace_back.powershell_pid()


# In[9]:


# LIST PIDS [record_id,pid,parent_id]
conn_db = sqlite3.connect("log_mix.db")
conn = conn_db.cursor()
conn.execute("SELECT record_id,pid,parent_id,process_cmd from sysmon WHERE event_id==1"+
             " ORDER BY record_id DESC")
pids=conn.fetchall()
#print(len(pids))


# In[10]:


#Get the suspicious logs with pid =1 to do traceback
malicious=list()
#detected log is in mal
for element in mal:
    ##ancestor:['2021-05-04T16:11:44.976Z', 1, 15922624, 12616, 8640, ['C:\\Program Files\\Winlogbeat\\winlogbeat.exe', '-e']]
    for logs in pids:#rev_ancestor:
        if logs[1] == element[1] and logs[0] <= element[0]:
            trace_key= tuple(list([logs[0],logs[1]]))
            malicious.append(trace_key)
            break
malicious=list(set(malicious))
print("malicious:",malicious)


# In[11]:


source_1, threshold = trace_back.get_oldest_sysmon_1(pids,malicious)


# In[12]:


real_source,zip_source = trace_back.get_source(source_1,pids)


# In[13]:


horizontal_relationship,parent_key = trace_back.chain_logs_for_draw(pids)


# In[14]:


attack_loop = draw(parent_key,threshold,real_source,zip_source,malicious)


# In[15]:


anomaly_sysmon = trace_back.extend_powershells(attack_loop)


# In[16]:


#print(anomaly_sysmon)


# In[17]:


print("############ SYSTEM SYSMON ###############")
print("True Positive")
tp_sysmon=0
for log in mal:
    if log in anomaly_sysmon:
        tp_sysmon+=1
        print(log)
print("TP:",tp_sysmon)
print("--------------------")
print("False Positive")
fp_sysmon=len(mal)-tp_sysmon
for log in mal:
    if log not in anomaly_sysmon:
        print(log)
print("FP:",fp_sysmon)
print("--------------------")
print("False Negative")
fn_sysmon=0
for log in anomaly_sysmon:
    if log not in mal:
        print(log)
        fn_sysmon+=1
print("FN:",fn_sysmon) 
print("--------------------")
print("True Negative")
#size of normal sysmon log + attack sysmon log out of tree - fp
#normal log not added

tn_sysmon = len(sysmon) -fp_sysmon -len(anomaly_sysmon)
#if include normal
#tn_sysmon = len(sysmon) - fp_sysmon
print("TN:",tn_sysmon) 
print("--------------------")
print('accuracy: ',(tp_sysmon+tn_sysmon)/(tp_sysmon+fp_sysmon+fn_sysmon+tn_sysmon))
print('precision: ',tp_sysmon/(tp_sysmon+fp_sysmon))
print('recall: ',tp_sysmon/(tp_sysmon+fn_sysmon))
print('F1: ',(2*tp_sysmon)/(2*tp_sysmon+fp_sysmon+fn_sysmon))
print("############ SYSTEM SYSMON END ###############")


# In[18]:


#anomaly security
print("attack loop:",attack_loop)
conn_db = sqlite3.connect("log_mix.db")
conn=conn_db.cursor()
t=(attack_loop,)
conn.execute("SELECT record_id,pid FROM security where group_id==?",t)
anomaly_security=conn.fetchall()


# In[19]:


#SYSTEM 
print("############ SYSTEM SECURITY ###############")
print("True Positive")
tp_security=0
#mal_security->detected anomaly log
#anomaly_security-> true anomaly log
for log in mal_security:
    if log in anomaly_security:
        tp_security+=1
        print(log)
print("TP:",tp_security)
print("--------------------")
print("False Positive")
#fp-> log in detected anomaly but not true anomaly log
fp_security=len(mal_security)-tp_security
for log in mal_security:
    if log not in anomaly_security:
        print(log)
print("FP:",fp_security)
print("--------------------")
print("False Negative")
#fn-> true anomaly logs without being detected
fn_security=0
for log in anomaly_security:
    if log not in mal_security:
        print(log)
        fn_security+=1
print("FN:",fn_security) 
print("--------------------")
print("True Negative")
#size of normal security log + attack security log out of tree - fp
#normal log not added
tn_security = len(security_trace) -fp_security - len(anomaly_security)
#if include normal
#tn_security = len(security) - fp_security
print("TN:",tn_security) 
print("--------------------")
print('accuracy: ',(tp_security+tn_security)/(tp_security+fp_security+fn_security+tn_security))
print('precision: ',tp_security/(tp_security+fp_security))
print('recall: ',tp_security/(tp_security+fn_security))
print('F1: ',(2*tp_security)/(2*tp_security+fp_security+fn_security))
print("############ SYSTEM SECURITY END ###############")


# In[20]:


#anomaly powershell
#print("attack loop:",attack_loop)
conn_db = sqlite3.connect("log_mix.db")
conn=conn_db.cursor()
t=(attack_loop,)
conn.execute("SELECT record_id FROM powershell where group_id==?",t)
anomaly_powershell=conn.fetchall()
# print(type(anomaly_powershell))
# for element in anomaly_powershell:
#     print(element)


# In[21]:


#anomaly microsoft_powershell
print("attack loop:",attack_loop)
conn_db = sqlite3.connect("log_mix.db")
conn=conn_db.cursor()
t=(attack_loop,)
conn.execute("SELECT record_id FROM microsoft_powershell where group_id==?",t)
anomaly_m_powershell=conn.fetchall()
print(type(anomaly_powershell))
for element in anomaly_m_powershell:
    print(element)


# In[22]:


#SYSTEM
print("############ SYSTEM powershell ###############")
print("True Positive")
tp_powershell=0
for log in mal_powershell:
    if log in anomaly_powershell:
        tp_powershell+=1
        print(log)

tp_m_powershell=0
for log in mal_m_powershell:
    if log in anomaly_m_powershell:
        tp_m_powershell+=1
        print(log)
two_powershell_tp = tp_powershell+tp_m_powershell
print("TP:",two_powershell_tp)
print("--------------------")
print("False Positive")
fp_powershell=len(mal_powershell)-tp_powershell
for log in mal_powershell:
    if log not in anomaly_powershell:
        print(log)
fp_m_powershell=len(mal_m_powershell)-tp_m_powershell
for log in mal_m_powershell:
    if log not in anomaly_m_powershell:
        print(log)
two_powershell_fp = fp_powershell+fp_m_powershell
print("FP:",two_powershell_fp)
print("--------------------")
print("False Negative")
fn_powershell=0
for log in anomaly_powershell:
    if log not in mal_powershell:
        print(log)
        fn_powershell+=1
fn_m_powershell=0
for log in anomaly_m_powershell:
    if log not in mal_m_powershell:
        print(log)
        fn_m_powershell+=1
two_powershell_fn = fn_powershell+fn_m_powershell
print("FN:",two_powershell_fn) 
print("--------------------")
print("True Negative")
#size of normal powershell log + attack powershell log out of tree - fp
#normal log not added
#!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!
tn_powershell = len(powershell) -fp_powershell - len(anomaly_powershell)
tn_m_powershell=len(microsoft_powershell)-fp_m_powershell- len(anomaly_m_powershell)  
#if include normal  
#tn_powershell = len(powershell) - fp_powershell
two_powershell_tn = tn_powershell+tn_m_powershell
print("TN:",two_powershell_tn) 
print("--------------------")
print('accuracy: ',(two_powershell_tp+two_powershell_tn)/(two_powershell_tp+two_powershell_fp+two_powershell_fn+two_powershell_tn))
print('precision: ',two_powershell_tp/(two_powershell_tp+two_powershell_fp))
print('recall: ',two_powershell_tp/(two_powershell_tp+two_powershell_fn))
print('F1: ',(2*two_powershell_tp)/(2*two_powershell_tp+two_powershell_fp+two_powershell_fn))
# print("TN:",two_powershell_tn) 
# print("--------------------")
# print('accuracy: ',(tp_powershell+tn_powershell)/(tp_powershell+fp_powershell+fn_powershell+tn_powershell))
# print('precision: ',tp_powershell/(tp_powershell+fp_powershell))
# print('recall: ',tp_powershell/(tp_powershell+fn_powershell))
# print('F1: ',(2*tp_powershell)/(2*tp_powershell+fp_powershell+fn_powershell))
print("############ SYSTEM powershell END ###############")


# In[23]:


#SYSTEM 
print("############ SYSTEM overall ###############")
print("True Positive")
total_tp = tp_sysmon + tp_security +two_powershell_tp
total_fp = fp_sysmon + fp_security +two_powershell_fp
total_fn =fn_sysmon + fn_security +two_powershell_fn
total_tn = tn_sysmon + tn_security +two_powershell_tn
print('accuracy: ',(total_tp+total_tn)/(total_tp+total_fp+total_fn+total_tn))
print('precision: ',total_tp/(total_tp+total_fp))
print('recall: ',total_tp/(total_tp+total_fn))
print('F1: ',(2*total_tp)/(2*total_tp+total_fp+total_fn))
print("############ SYSTEM overall END ###############")


# In[ ]:





#!/usr/bin/env python
# coding: utf-8


import json
import pandas
import datetime
import time
import math
import os,sys
import joblib
import warnings
import sqlite3
#put in another .py file
def hello():
    print("hello")
def create_table():
    
    ## CREATE TABLE MICROSOFT POWERSHELL
    conn_db = sqlite3.connect("log_mix.db")
    ######################################
    conn_db.execute("DROP table IF EXISTS microsoft_powershell")
    ######################################
    conn_db.execute('''CREATE TABLE microsoft_powershell(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    winlog_pid INTEGER,
    time TEXT,
    record_id INTEGER,
    group_id INTEGER,
    sysmon_record INTEGER,
    message TEXT);''')
    
    ## CREATE TABLE MICROSOFT POWERSHELL
    conn_db = sqlite3.connect("log_mix.db")
    ######################################
    conn_db.execute("DROP table IF EXISTS powershell")
    ######################################
    conn_db.execute('''CREATE TABLE powershell(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    pid INTEGER,
    process_cmd TEXT,
    time TEXT,
    record_id INTEGER,
    group_id INTEGER,
    sysmon_record INTEGER);''')
    
    ## CREATE TABLE SYSMON
    conn_db = sqlite3.connect("log_mix.db")
    #######################################
    conn_db.execute("DROP table IF EXISTS sysmon")
    ########################################
    conn_db.execute('''CREATE TABLE sysmon(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    pid INTEGER,
    parent_id INTEGER,
    time TEXT,
    record_id INTEGER,
    group_id INTEGER,
    path TEXT,
    rule_name TEXT,
    content TEXT,
    process_executable TEXT,
    process_arg TEXT,
    process_cmd TEXT);''')
    
    ## CREATE TABLE SECURITY
    conn_db = sqlite3.connect("log_mix.db")
    conn_db.execute("DROP table IF EXISTS security")
    conn_db.execute('''CREATE TABLE security(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    pid INTEGER,
    time TEXT,
    record_id INTEGER,
    group_id INTEGER,
    message TEXT);''')

def insert_table(sysmon,security,powershell,microsoft_powershell):
    #INSERT SYSMON
    for i in range(len(sysmon)):
    #row=list()
        num=0
        time=sysmon[i]['@timestamp']
        event_id=sysmon[i]['winlog']['event_id']
        record_id=sysmon[i]['winlog']['record_id']
        group_id= -1
        try:
            process_pid=sysmon[i]['process']['pid']
        except:
            process_pid=-1
        try:
            parent_pid=sysmon[i]['process']['parent']['pid']
        except:
            parent_pid=-1
        try:
            path= sysmon[i]['file']['path']
       # print("path:",path)
        except:
            path = "no"
        try:
            rule_name=sysmon[i]['rule']['name']
        #print("rulename: ", rule_name)
        except:
            rule_name = "no"
        try:
            content = sysmon[i]['winlog']['event_data']['Contents']
       # print("Content:",content)
        except:
            content = "no"
        
        try:
            process_cmd = sysmon[i]['process']['command_line']
        #cmd_count+=1
        except:
            process_cmd = "no"
        try:
            process_arg = sysmon[i]['process']['args'][-1]
            #print("process_arg:",process_arg)
            cmd_count+=1
        except:
            process_arg = "no"
        try:
            process_executable = sysmon[i]['process']['executable']
        except:
            process_executable = ""

    

        #else:  
        try:
        #print("db")
            conn_db = sqlite3.connect("log_mix.db")
        
            t=(event_id,process_pid,parent_pid,time,record_id,group_id,path,rule_name,content,process_executable,process_arg,process_cmd,)
            conn_db.execute("INSERT INTO sysmon (event_id,pid,parent_id,time,record_id,group_id,path,rule_name,content,process_executable,process_arg,process_cmd) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",t)            
            conn_db.commit()
        except:
            num+=1
    print("num fail :",num)
    print("finish insert sysmon")
    #INSERT SECURITY
    count=0
    fail=0

    for logs in security:
        #network_flag=False
        event_id = logs['event']['code']
        time = logs['@timestamp']
        record_id = logs['winlog']['record_id']
        group_id = -1
        message = logs['message']
        try:
            pid = logs['process']['pid']
        except:
            try:
                pid = logs['winlog']['event_data']['ProcessID']
#                 if event_id == 5156:
#                 #print("5156")
#                 dest_ip=logs['winlog']['event_data']['DestAddress']
#                 src_ip=logs['winlog']['event_data']['SourceAddress']
#                 network_flag=True
            #counts+=1
            except:
                pid = -1
    
#     process_cmd = logs['process']['command_line']
    
    
        conn_db = sqlite3.connect("log_mix.db")
        t=(event_id,pid,time,record_id,group_id,message,)
    #print("t:",t)
        #if network_flag:
#         try:
#             t=(pid,time,record_id,dest_ip,src_ip,group_id)
#             #print("pid:",pid)
#             conn_db.execute("INSERT INTO network_security (pid,time,record_id,dest_ip,src_ip,group_id) VALUES (?,?,?,?,?,?)",t)
#             conn_db.commit()
#         except:
#             print("fail")
#     else:      
        try:
            conn_db.execute("INSERT INTO security (event_id,pid,time,record_id,group_id,message) VALUES (?,?,?,?,?,?)",t)
            conn_db.commit()
            num+=1
        except:
            fail+=1
    #conn_db.commit()
    print("fail is ",fail," count is ",count)
    print("finish insert security")
    #INSERT powershell
    for logs in powershell:
        event_id = logs['event']['code']
        pid = -1
        process_cmd = logs['process']['command_line']
        time = logs['@timestamp']
        record_id = logs['winlog']['record_id']
        group_id = -1
        sysmon_record = -1
    
        conn_db = sqlite3.connect("log_mix.db")
        t=(event_id,pid,process_cmd,time,record_id,group_id,sysmon_record)
    #print("t:",t)
        conn_db.execute("INSERT INTO powershell (event_id,pid,process_cmd,time,record_id,group_id,sysmon_record) VALUES (?,?,?,?,?,?,?)",t)  
        conn_db.commit()
    print("finish insert powershell")
    #INSERT microsoft_powershell
    for logs in microsoft_powershell:
        event_id = logs['event']['code']
        winlog_pid = logs['winlog']['process']['pid']
        time = logs['@timestamp']
        record_id = logs['winlog']['record_id']
        group_id = -1
        sysmon_record = -1
        message = logs['message']
        conn_db = sqlite3.connect("log_mix.db")
        t=(event_id,winlog_pid,time,record_id,group_id,sysmon_record,message)
        #print("t:",t)
        conn_db.execute("INSERT INTO microsoft_powershell (event_id,winlog_pid,time,record_id,group_id,sysmon_record,message) VALUES (?,?,?,?,?,?,?)",t) 
        conn_db.commit()
        #conn_db.commit()
    print("finish insert microsoft powershell")
    
def sort_detected_log(result1):
    #mal is for sysmon
#store (record_id,process.pid)
    mal_sysmon=list()
#mal_security is for windows security
#store (record_id,process.pid)
    mal_security=list()
#mal_powershell is for powershell
    mal_powershell=list()
#mal_m_powershell is for microsoft-windows-powershell
    mal_m_powershell=list()
#powershell_rid = list()
    for element in result1:
    #print(element)
        record_id = int(element[0])
        if "Security" in element[2]:
        #print("SECURITY")
            tmp=(record_id,int(element[1]))
        #print(tmp)
            mal_security.append(tmp)
        elif element[2]=='Microsoft-Windows-Sysmon':
            #print("SYSMON")
            tmp=(record_id,int(element[1]))
           # print(tmp)
            mal_sysmon.append(tmp)
        elif element[2]=='Microsoft-Windows-PowerShell':
            #print("Microsoft-Windows-PowerShell")
            tmp=(record_id,)
            #print(tmp)
            mal_m_powershell.append(tmp)
        elif element[2]=='PowerShell':
           # print("PowerShell")
            tmp=(record_id,)
            #print(tmp)
            mal_powershell.append(tmp)
    return mal_sysmon,mal_security,mal_powershell,mal_m_powershell
    #print("--------------------------")
    
def powershell_pid():
    #match a process pid to powershell log
    conn_db = sqlite3.connect("log_mix.db")
    conn=conn_db.cursor()
    conn.execute("SELECT s.record_id,mp.winlog_pid,s.process_cmd from sysmon s,microsoft_powershell mp "+
             "WHERE mp.winlog_pid == s.pid AND s.event_id==1 "+ 
             "AND s.process_executable=="+
             "'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'")
    match_pid_powershell=conn.fetchall()

    for ids in match_pid_powershell:
        malicious_sequence=ids[2].split("-noP -sta -w 1 -enc")
        if len(malicious_sequence)<2:
        
            temporary=ids[2].split("'")
            temporary.pop()
            #C:\Users\USER\AppData\Local\Temp\launcher.bat is temporary[-1]
            print(temporary[-1])
            var3 = "'%"+temporary[-1]+"%\'"
            t=(ids[0],ids[1],)#"'%"+mal_string)
            conn_db.execute("UPDATE powershell SET sysmon_record=?,pid=? WHERE process_cmd like "+var3,t)
            conn_db.commit()
            conn.execute("SELECT record_id,pid,sysmon_record FROM powershell ORDER BY record_id")
            tmp=conn.fetchall()
        
        else:
            mal_string=malicious_sequence[1].strip()
            #print(mal_string)
            var3="'%"+mal_string+"%\'"
        #print("-------------------------")
        t=(ids[0],ids[1],)#"'%"+mal_string)
        conn_db.execute("UPDATE powershell SET sysmon_record=?,pid=? WHERE process_cmd like "+var3,t)
        conn_db.commit()
        conn.execute("SELECT record_id,pid,sysmon_record FROM powershell ORDER BY record_id")
        tmp=conn.fetchall()

        #microsoft powershell
        t=(ids[0],ids[1],)
        conn_db.execute("UPDATE microsoft_powershell SET sysmon_record=? "+
                    "WHERE microsoft_powershell.winlog_pid ==?",t)
        conn_db.commit()
    
def get_oldest_sysmon_1(pids,malicious):
    source_1 = list()
    for anomaly in malicious:
        start_idx=-1
        end_idx=len(pids)
        for i in range(len(pids)):
            if pids[i][1]==anomaly[1] and pids[i][0]==anomaly[0]:
                start_idx=i
            elif pids[i][1]==anomaly[1] and pids[i][0]<anomaly[0]:
                end_idx=i
                break
        need=pids[start_idx:end_idx]
    #print(need)
    #print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
        trace_back=list()
    #print(need)
    #print("-----------------------------------")
        index=0
        current=need[0][1]
        trace_back.append(current)
        threshold=(-1,-1)
        for i in range(len(need)):
        
            if need[i][1] != current:
                continue
            for j in range(i+1,len(need)):
                if need[i][2]==need[j][1]:
                    current=need[j][1]
                    trace_back.append(current)
                    threshold = tuple(need[j][:2])
                    break
    #print("threshold:",threshold)
        if threshold != (-1,-1) and threshold not in source_1:
        #print("source!")
            source_1.append(tuple(threshold))
    #print("traceback:",trace_back)
    print("source1:",source_1)
    return source_1,threshold

def get_source(source_1,pids):
    #print(source_candidate)
    zip_source= (-1,-1)
    for source in source_1:
        conn_db = sqlite3.connect("log_mix.db")
        conn = conn_db.cursor()
        t=(source[0],)
        conn.execute("SELECT record_id,time,event_id,path,rule_name,content,pid from sysmon WHERE content!='no' AND record_id < ?",t)#" OR rule_name !='no')   
        src=conn.fetchall()
        conn.execute("SELECT record_id,time,event_id,path,rule_name,content,pid from sysmon WHERE rule_name!='no' AND path !='no' AND record_id < ? ",t)
        ss=conn.fetchall()
    
    #find source candidate now
        source_candidate = src+ss
        print("source:",source)
    
        pids.sort()
        for log in pids:
            if source[0]==log[0]:
                arguments=log[3].split(" ")[-1]
                arguments = arguments[1:len(arguments)-1]

        path = arguments.split('\\') 
        filename= path[-1]
        print(filename)
    
        for data in source_candidate:
        #print("data[3]:",data[3])
            if arguments in data[3]:
                if len(data[4])==0 and len(data[5])<=3:
                    continue
                
                if len(data[5])>3:
                    url = data[5].split("HostUrl=")
                    if len(url)>1:
                        #print("@@@@@@@@@@@@@@@@@@@@@@@@@@")
                        real_source=(data[0],data[-1])
                        print("The path is:",data[3])
                        print("malicious url is: ",url[1])
                        print("---------------------------")
                        url_unzip = url[1] 
                        for element in source_candidate:
                            #print(element[5])
                            #print("00000000000000000000000000000")
                            if element[5]==data[5] and element[0]!=data[0]:
                                zip_source = (element[0],element[-1])
                                print("zip source:",zip_source)
                                return real_source,zip_source
                        
            elif filename in data[3]:
                if len(data[4])>3:
                    real_source=(data[0],data[-1])
                    print("The path is:",data[3])
                    print("rule name is :",data[4])
                    return real_source,zip_source
            
def chain_logs_for_draw(pids):
    pids.sort(reverse=True)
    relative=[]
    for i in range(len(pids)):

        for j in range(i+1,len(pids)):
            if pids[i][2]==pids[j][1]:
                relative.append([pids[i],pids[j]])
                break
    
    pids.sort()
    parentpid=list()
    for i in range(len(pids)):
        tmp=pids[i][2]
        if tmp not in parentpid:
            parentpid.append(tmp)
        
    # print (relative)
# print(len(relative))
    parent_key=list()
    horizontal_relationship=dict()
    for i in range(len(relative)):
        k=tuple(relative[i][1][:2])
        v=tuple(relative[i][0][:2])
        parent_key.append(k)
        try:
            horizontal_relationship[k].append(v)
        except:
            horizontal_relationship[k]=[v]
    parent_key.sort()
    return horizontal_relationship,parent_key

def draw(parent_key,threshold,real_source,zip_source,malicious):
    from graphviz import Digraph
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
                        draw = True
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

def extend_powershells(attack_loop):
    #print("attack loop:",attack_loop)
    conn_db = sqlite3.connect("log_mix.db")
#for i in range(1):
    conn=conn_db.cursor()
    t=(attack_loop,)
    conn.execute("SELECT record_id,pid FROM sysmon where sysmon.group_id==?",t)
    anomaly_sysmon=conn.fetchall()

#microsoft powershell extension
    conn.execute("SELECT sysmon_record,winlog_pid FROM microsoft_powershell")
    p= conn.fetchall()
    #print(p)
    p=list(set(p))
    #print(p)
    #print("------------")
    for element in p:
        #print("element:",element)
        if element in anomaly_sysmon:
            t=(attack_loop,element[0],element[1],)
            conn_db.execute("UPDATE microsoft_powershell SET group_id=? WHERE sysmon_record==? AND winlog_pid==?",t)   
            conn_db.commit()
    conn.execute("SELECT group_id,record_id,winlog_pid,sysmon_record FROM microsoft_powershell ORDER BY record_id")
    p = conn.fetchall()
    #print(p)

    #powershell extension
    #print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    conn.execute("SELECT sysmon_record,pid FROM powershell")
    p= conn.fetchall()
    #print(p)
    p=list(set(p))
    #print(p)
    #print("------------")
    for element in p:
        #print("element:",element)
        if element in anomaly_sysmon:
            t=(attack_loop,element[0],element[1],)
            conn_db.execute("UPDATE powershell SET group_id=? WHERE sysmon_record==? AND pid==?",t)   
            conn_db.commit()
    conn.execute("SELECT group_id,record_id,pid,sysmon_record FROM powershell ORDER BY record_id")
    p = conn.fetchall()
    #print(p)
    return anomaly_sysmon

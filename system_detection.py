import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import make_pipeline
from pandas.io import json
import json
import joblib
import base64
import sklearn
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neighbors import NearestNeighbors
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder
from numpy import argmax
from array import array
from sklearn import svm 
import collections
from collections import Counter

def predict(x_test):
    pd.set_option('display.max_rows',None)
    pd.set_option('display.max_columns',None)
    pd.set_option('display.max_colwidth',160)

    field1 = '_source.process.command_line'
    field2 = '_source.process.parent.command_line'
    field3 = '_source.file.name'
    field4 = '_source.powershell.file.script_block_text'
    field5 = '_source.process.executable'
    field6 = '_source.message'
    field7 = '_source.winlog.task'
    field8 = '_source.registry.value'
    field9 = '_source.registry.path'
    field10 = '_source.winlog.event_data.TargetObject'
    field11 = '_source.rule.name'
    filed12 = '_source.registry.key'
    field13 = '_source.file.path'

    x_test = pd.json_normalize(x_test)
    x_test = x_test.replace(np.nan, '', regex=True)

    # SVM

    model_svm=make_pipeline(TfidfVectorizer(), svm.SVC(kernel = 'linear', C=10))
    model_svm=joblib.load('./joblib/svm_model_field1')
    x_test['result'] = model_svm.predict(x_test[field1])
    anomaly = x_test.loc[x_test['result'] == 'anomaly']
    normal = x_test.loc[x_test['result'] == 'normal']
    model_svm=joblib.load('./joblib/svm_model_field3')
    x_test['result2'] = model_svm.predict(x_test[field3])
    anomaly2 = x_test.loc[x_test['result2'] == 'anomaly']
    normal2 = x_test.loc[x_test['result2'] == 'normal']
   
    # decrease false negative

    anomaly_pid = []
    for i in range(anomaly.shape[0]):
        if anomaly.iloc[i].get('_source.process.pid') != '':
            anomaly_pid.append(anomaly.iloc[i].get('_source.process.pid'))

    for i in range(x_test.shape[0]):
        x_test.loc[i,'result_2'] = x_test.loc[i,'result']
        if x_test.iloc[i].get('_source.process.pid') in anomaly_pid:
            x_test.loc[i,'result_2'] = 'anomaly'  

    anomaly = x_test.loc[(x_test['result_2'] == 'anomaly')]
    normal = x_test.loc[(x_test['result_2'] == 'normal')]

    anomaly_pid2 = []
    for i in range(anomaly2.shape[0]):
        if anomaly2.iloc[i].get('_source.process.pid') != '':
            anomaly_pid2.append(anomaly2.iloc[i].get('_source.process.pid'))

    for i in range(x_test.shape[0]):
        x_test.loc[i,'result2_2'] = x_test.loc[i,'result2']
        if x_test.iloc[i].get('_source.process.pid') in anomaly_pid2:
            x_test.loc[i,'result2_2'] = 'anomaly'  

    anomaly2 = x_test.loc[(x_test['result2_2'] == 'anomaly')]
    normal2 = x_test.loc[(x_test['result2_2'] == 'normal')]
    
    # combine two results

    for i in range(x_test.shape[0]):
        if x_test.iloc[i].get('result_2')=='anomaly' or x_test.iloc[i].get('result2_2')=='anomaly': 
            x_test.loc[i,'result3']='anomaly'
        else:
            x_test.loc[i,'result3']='normal'

    anomaly = x_test.loc[(x_test['result3'] == 'anomaly')]
    normal = x_test.loc[(x_test['result3'] == 'normal')]

    # return result

    result1=list()
    for i1 in range(anomaly.shape[0]):
        result1.append((anomaly.iloc[i1].get("_source.winlog.record_id"),anomaly.iloc[i1].get("_source.process.pid"),anomaly.iloc[i1].get("_source.event.provider")))
    #print(result1)
    return result1
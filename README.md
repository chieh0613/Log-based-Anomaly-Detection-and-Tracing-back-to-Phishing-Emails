# Log-based-Anomaly-Detection-and-Tracing-back-to-Phishing-Emails
## First Part of this Project
* https://github.com/chieh0613/Attack-Emulation-of-the-Fore-Part-of-Doppelpaymer-Attack-Chain

## Introduction
    In the first part, we try to reproduce the attack scenario based on the fore part of Doppelpaymer attack chain.
    The techniques used in their attack may include phishing emails.
    Since it is hard to detect this kind of attack behavior with antivirus, 
    finding other detection method is an essential issue currently.
    We propose a log-based framwork and use machine learning methods to solve this problem.

## Framework
    First, we dump the logs from ELK. They are system logs and network logs respectively.
    These two kinds of log will be put into two machine learning models.
    Finally, the models will send suspicious logs and traceback to the source log.
   ![image](https://github.com/chieh0613/Log-based-Anomaly-Detection-and-Tracing-back-to-Phishing-Emails/blob/main/framework.png)


## Detection from system log
    We use supervised machine learning method to detect suspicious system activities from windows security logs and sysmon logs.
* System_train.py: 
    * Read system logs which contains normal and attack logs.
    * Do detection to find abnormal behaviors
    * The models are stored in the folder /joblib/svm_model_field1 and svm_model_field3
* system_detection.py: Return the suspicious log

## Detection from network log
    We use anomaly detection to detect suspicious network activities from conn.log.
* Network_train.py
    * Read connection logs which contains normal and attack logs
    * Do anomaly detection to find abnormal network flow
    * The model is stored in the folder /joblib/conn_FeatureBagging
* Prediction.py 
    * Do the anomaly network detection in function predict_conn.
    * Calculate network performance in function network performance.
    * Match sysmon logs with event id 3 and security logs with event id 5156 in function relation.

## Traceback
    Our goal is tracing back to the email link or attachment rule from the suspicious logs. Besides, it can also find out all the logs produced during the attack and visualize the detection result.
    We will use database as our data structure because it is easier to manage and it's also effective.
* Trace_back.py: Trace back to the source log and find all the logs associated with the attack.
* Log_mix.db: A database that store the log information.
* Trace_graph: A folder that store all the attack chain graph.

## main.py/ main.ipynb
* Read the log data by calling function in load.py and open two threads. 
* One is for detection from system logs while the other is for detection from network logs. 
* After two models return suspicious log. The main will call functions in trace_back.py and draw the attack chain.

## Requirement
* graphviz==0.16
* jupyter==1.0.0
* Scikit-learn==0.24.2
* combo==0.1.2
* DateTime==4.3
* ipaddress==1.0.23
* numpy==1.19.5
* pandas==1.0.4
* pyod==0.8.9
* regex==2021.4.4
* joblib==1.0.1
* queues==0.6.3
* imblearn==0.0
* sqlite3
* Python version 3.9.4

# Conclusion 
* Best model for anomaly system log detection is SVM.
* Best method for anomaly network log detection is Histogram-based Outlier Detection + FeatureBagging. 
* Using sysmon log’s pid to do traceback and find all attack logs are feasible.

# Contribution
* Interpret the attack in both system and network aspects, most of the related works only focus on one of them.
* Provide a novel framework to do anomaly detection of attack launched by DoppelPaymer.
* Find out all the logs produced during the attack, which can help us know more about the overall attack.



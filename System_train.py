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
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

pd.set_option('display.max_rows',None)
pd.set_option('display.max_columns',None)
pd.set_option('display.max_colwidth',160)

#vbaparser = VBA_Parser('C:\\Users\\Tina Wang\\Downloads')
#print("DETECT VBA MACROS")
#if vbaparser.detect_vba_macros():
#    print('VBA Macros found')
#else:
#    print('No VBA Macros found')
#print()

file = open('attack_system.json',encoding='utf-8')
file2 = open('normal_system.json',encoding='utf-8')
file3 = open('attack_system2.json',encoding='utf-8')
#file4 = open('normal_system_0411.json',encoding='utf-8')

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

x_train = []
y_train = []
x_test = []
#y_test=[]
true_positive = [13752,3724,8880,3664,10624,13772,8936,3876,11044,11632,11848,11956,9976,8652,5432,7524,10904,10320,10628,1892,13880]
true_positive2 = [5088,11228,6640,7572,4400,8304,8244,11324,7120,8812,10100,10528,8280,9168,8068,13072,10796,2444,8800,5028]
true_positive_tuples=[(59304785, 13380),
(59305233, 3724),
(59306811, 11632),
(59306812, 11632),
(59306816, 11632),
(59306818, 11848),
(59306832, 11044),
(59306819, 11848),
(59306823, 11848),
(59306831, 11044),
(59306883, 11956),
(59306905, 9976),
(59306913, 7524),
(59306915, 8652),
(59306917, 7524),
(59306935, 11044),
(59306884, 11956),
(59306910, 8652),
(59306912, 9976),
(59306914, 5432),
(59306916, 5432),
(59306842, 11044),
(59306843, 11044),
(59306946, 10320),
(59306953, 10320),
(59306962, 10628),
(59307469, 1892),
(59307470, 1892),
(59307504, 10904),
(59307505, 10904),
(59307580, 7524),
(59307579, 7524),
(59307581, 7524),
(59307582, 7524),
(59307583, 7524),
(59307584, 7524),
(59307585, 7524),
(59307586, 7524),
(59307587, 7524),
(59307588, 7524),
(59305416, 8880),
(59305418, 8880),
(59305420, 8880),
(59305422, 8880),
(59305424, 8880),
(59305426, 8880),
(59305428, 8880),
(59305430, 8880),
(59305432, 8880),
(59305434, 8880),
(59305436, 8880),
(59305438, 8880),
(59305440, 8880),
(59305442, 8880),
(59305444, 8880),
(59305446, 8880),
(59305348, 8880),
(59305353, 8880),
(59305415, 8880),
(59305417, 8880),
(59305419, 8880),
(59305421, 8880),
(59305423, 8880),
(59305425, 8880),
(59305427, 8880),
(59305429, 8880),
(59305431, 8880),
(59305433, 8880),
(59305435, 8880),
(59305437, 8880),
(59305439, 8880),
(59305441, 8880),
(59305443, 8880),
(59305445, 8880),
(59305447, 8880),
(59305657, 8880),
(59305658, 8880),
(59305651, 8880),
(59305652, 8880),
(59305655, 8880),
(59305656, 8880),
(59306151, 3664),
(59306311, 10624),
(59306318, 10624),
(59306611, 10624),
(59306613, 3664),
(59306670, 13772),
(59306669, 13772),
(59306749, 8936),
(59306753, 8936),
(59306763, 3876),
(59306748, 8936),
(59306764, 3876),
(59306768, 3876),
(59306160, 3664),
(59307466, 10628),
(15922639, 13380),
(15922653, 3724),
(15922665, 8880),
(15922741, 11632),
(15922745, 3876),
(15922747, 11044),
(15922742, 11848),
(15922746, 3876),
(15922748, 3876),
(15922754, 11956),
(15922756, 9976),
(15922757, 8652),
(15922758, 7524),
(15922759, 5432),
(15922760, 7524),
(15922770, 10320),
(15922776, 10628),
(15922811, 1892),
(15922834, 10904),
(15922839, 7524),
(15922844, 7524),
(15922657, 8880),
(15922660, 8880),
(15922661, 8880),
(15922666, 8880),
(15922680, 8880),
(15922684, 8880),
(15922676, 8880),
(15922675, 8880),
(15922703, 3664),
(15922705, 3664),
(15922707, 3664),
(15922708, 3664),
(15922709, 10624),
(15922710, 10624),
(15922711, 10624),
(15922712, 3664),
(15922702, 3664),
(15922704, 3664),
(15922706, 3664),
(15922715, 13772),
(15922720, 3876),
(15922717, 8936),
(15922719, 3876),
(15922716, 8880),
(15922718, 8936),
(59304785,13380),
(59304759,13380),
(59304760,13380),
(59304743,13380),
(59304742,13380),
(59304719,13380),
(59304720,13380),
(59304711,13380),
(59304705,13380),
(15922639,13380),
(15922638,13380),
(15922637,13380),
(15922636,13380),
(15922635,13380),
(15922634,13380),
(15922633,13380),
(15922653,3724),
(15922652,3724),
(15922651,3724),
(15922650,3724),
(15922648,3724),
(59305233,3724),
(59305048,3724),
(59305043,3724),
(1829,''),
(1830,''),
(1831,''),
(1832,''),
(1833,''),
(1834,''),
(1835,''),
(1836,''),
(1837,''),
(1838,''),
(1839,''),
(1840,''),
(1841,''),
(1842,''),
(1843,''),
(1844,''),
(1845,''),
(1846,''),
(1847,''),
(1848,''),
(1849,''),
(1850,''),
(1851,''),
(1852,''),
(1853,''),
(1854,''),
(1855,''),
(1856,''),
(1857,''),
(1858,''),
(1859,''),
(1860,''),
(1861,''),
(1862,''),
(1863,''),
(1864,''),
(1865,''),
(1866,''),
(1867,''),
(1787,''),
(1791,''),
(1795,'')]
true_positive_tuples2 = [(19422117, 5088),(19422130, 6640),(19422139, 6640),(19422141, 6640),(19422142, 6640),(19422128, 11228),(19422217, 10100),(19422218, 8812),(19422219, 11324),(19422220, 11324),(19422221, 7120),(19422230, 8280),(19422232, 10528),(19422233, 9168),(19422234, 13072),(19422235, 8068),(19422236, 13072),(19422222, 11324),(19422135, 6640),(19422147, 6640),(19422149, 6640),(19422181, 7572),(19422182, 6640),(19422183, 8304),(19422184, 8304),(19422185, 11324),(19422186, 11324),(19422168, 4400),(19422169, 4400),(19422170, 4400),(19422171, 4400),(19422172, 4400),(19422173, 4400),(19422174, 4400),(19422175, 8244),(19422176, 8244),(19422177, 8244),(19422178, 4400),(19422258, 5028),(19422266, 8800),(19422307, 2444),(19422331, 10796),(19422339, 13072),(19422336, 13072),(19422128,11228),(19422127,11228),(19422126,11228),(19422125,11228),(19422122,11228),(19422117,5088),(19422116,5088),(19422115,5088),(19422114,5088),(19422113,5088),(19422112,5088),(19422111,5088),(66224775,11228),(66224631,11228),(66224626,11228),(66224388,5088),(66224362,5088),(66224363,5088),(66224319,5088),(66224320,5088),(66224313,5088),(66224314,5088),(66224305,5088),(66224304,5088),(66224388, 5088),(66224775, 11228),(66227050, 7120),(66227051, 7120),(66227061, 7120),(66227062, 7120),(66227096, 8280),(66227097, 8280),(66227124, 10528),(66227129, 9168),
(66227131, 10528),
(66227132, 13072),
(66227133, 8068),
(66227134, 9168),
(66227135, 8068),
(66227136, 13072),
(66227154, 7120),
(66227030, 10100),
(66227031, 10100),
(66227035, 10100),
(66227037, 8812),
(66227038, 8812),
(66227042, 8812),
(66227407, 6640),
(66227408, 6640),
(66227409, 6640),
(66227543, 6640),
(66224950, 6640),
(66224955, 6640),
(66225022, 6640),
(66225024, 6640),
(66225026, 6640),
(66225028, 6640),
(66225030, 6640),
(66225032, 6640),
(66225034, 6640),
(66225036, 6640),
(66225038, 6640),
(66225023, 6640),
(66225025, 6640),
(66225027, 6640),
(66225029, 6640),
(66225031, 6640),
(66225033, 6640),
(66225035, 6640),
(66225037, 6640),
(66225039, 6640),
(66225040, 6640),
(66225041, 6640),
(66225042, 6640),
(66225043, 6640),
(66225044, 6640),
(66225045, 6640),
(66225046, 6640),
(66225047, 6640),
(66225048, 6640),
(66225049, 6640),
(66225050, 6640),
(66225051, 6640),
(66225052, 6640),
(66225053, 6640),
(66225054, 6640),
(66225248, 6640),
(66225249, 6640),
(66225252, 6640),
(66225253, 6640),
(66225254, 6640),
(66225255, 6640),
(66226256, 7572),
(66226334, 8304),
(66226350, 11324),
(66226354, 11324),
(66226255, 7572),
(66226335, 8304),
(66226339, 8304),
(66226349, 11324),
(66225740, 4400),
(66225749, 4400),
(66225904, 8244),
(66225897, 8244),
(66226197, 8244),
(66226199, 4400),
(66227210, 5028),
(66227217, 5028),
(66227225, 8800),
(66227309, 2444),
(66227310, 2444),
(66227308, 8800),
(66227343, 10796),
(66227344, 10796),
(66227357, 13072),
(66227358, 13072),
(66227359, 13072),
(66227360, 13072),
(66227361, 13072),
(66227362, 13072),
(66227363, 13072),
(66227364, 13072),
(66227365, 13072),
(66227366, 13072),(2087,''),(2088,''),(2089,''),(2090,''),(2091,''),(2092,''),(2093,''),(2094,''),(2095,''),(2096,''),(2097,''),(2098,''),(2099,''),(2100,''),(2101,''),(2102,''),(2103,''),(2104,''),(2105,''),(2106,''),(2107,''),(2108,''),(2109,''),(2110,''),(2111,''),(2112,''),(2113,''),(2114,''),(2115,''),(2116,''),(2117,''),(2118,''),(2119,''),(2120,''),(2121,''),(2122,''),(2123,''),(2124,''),(2125,''),]
#true_positive_tuples=[(15923674, 9292),
#(15923675, 9292),
#(15923676, 9292),
#(15923677, 9292),
#(15923729, 12852),
#(15923730, 12852),
#(15923731, 12852),
#(15923732, 12852),
#(15923733, 12852),
#(15923734, 12852),
#(15923735, 12852),
#(15923736, 7784),
#(15923737, 7784),
#(15923738, 7784),
#(15923739, 12852),
#(15923744, 13172),
#(15923746, 8368),
#(15923748, 1708),
#(15923745, 10984),
#(15923747, 8368),
#(15923749, 1708),
#(15923878, 3172),
#(15923903, 11508),
#(15923906, 1624),
#(15923673, 9292),
#(15923696, 10984),
#(15923699, 10984),
#(15923708, 10984),
#(15923710, 10984),
#(15923703, 10984),
#(15923704, 10984),
#(15923790, 7708),
#(15923791, 11224),
#(15923792, 1708),
#(15923793, 1708),
#(15923794, 12348),
#(15923804, 12108),
#(15923806, 12228),
#(15923795, 1708),
#(15923801, 8784),
#(15923803, 3628),
#(15923805, 1624),
#(15923807, 1624),
#(15923819, 10308),
#(15923823, 6428),
#(15923911, 1624),
#(59323277, 12852),
#(59323437, 7784),
#(59323444, 7784),
#(59323737, 7784),
#(59323739, 12852),
#(59323801, 13172),
#(59323879, 8368),
#(59323895, 1708),
#(59323899, 1708),
#(59323800, 13172),
#(59323880, 8368),
#(59323884, 8368),
#(59323894, 1708),
#(59323286, 12852),
#(59324300, 3172),
#(59324301, 3172),
#(59324297, 6428),
#(59324319, 11508),
#(59324320, 11508),
#(59322807, 10984),
#(59322809, 10984),
#(59322811, 10984),
#(59322813, 10984),
#(59322815, 10984),
#(59322817, 10984),
#(59322819, 10984),
#(59322821, 10984),
#(59322823, 10984),
#(59322825, 10984),
#(59322827, 10984),
#(59322829, 10984),
#(59322831, 10984),
#(59322833, 10984),
#(59322835, 10984),
#(59322837, 10984),
#(59322788, 10984),
#(59322802, 10984),
#(59322806, 10984),
#(59322808, 10984),
#(59322810, 10984),
#(59322812, 10984),
#(59322814, 10984),
#(59322816, 10984),
#(59322818, 10984),
#(59322820, 10984),
#(59322822, 10984),
#(59322824, 10984),
#(59322826, 10984),
#(59322828, 10984),
#(59322830, 10984),
#(59322832, 10984),
#(59322834, 10984),
#(59322836, 10984),
#(59322838, 10984),
#(59324043, 7708),
#(59324044, 7708),
#(59324048, 7708),
#(59324050, 11224),
#(59324051, 11224),
#(59324055, 11224),
#(59324063, 12348),
#(59324064, 12348),
#(59324074, 12348),
#(59324116, 8784),
#(59324142, 12108),
#(59324144, 3628),
#(59324146, 12228),
#(59324148, 12228),
#(59324075, 12348),
#(59324115, 8784),
#(59324137, 3628),
#(59324145, 1624),
#(59324147, 12108),
#(59324149, 1624),
#(59324167, 12348),
#(59324176, 10308),
#(59324183, 10308),
#(59324185, 6428),
#(59324333, 1624),
#(59324334, 1624),
#(59324335, 1624),
#(59324336, 1624),
#(59324337, 1624),
#(59324338, 1624),
#(59324339, 1624),
#(59324340, 1624),
#(59324341, 1624),
#(59324342, 1624),
#(1871,''),
#(1872,''),
#(1873,''),
#(1874,''),
#(1875,''),
#(1876,''),
#(1877,''),
#(1878,''),
#(1879,''),
#(1880,''),
#(1881,''),
#(1882,''),
#(1883,''),
#(1884,''),
#(1885,''),
#(1886,''),
#(1887,''),
#(1888,''),
#(1889,''),
#(1890,''),
#(1891,''),
#(1892,''),
#(1893,''),
#(1894,''),
#(1895,''),
#(1896,''),
#(1897,''),
#(1898,''),
#(1899,''),
#(1900,''),
#(1901,''),
#(1902,''),
#(1903,''),
#(1904,''),
#(1905,''),
#(1906,''),
#(1907,''),
#(1908,''),
#(1909,''),
#(1803,''),
#(1807,''),
#(1811,'')]
#true_positive_tuples2=[(19422592, 10840),
#(19422596, 10840),
#(19422595, 10840),
#(19422597, 10840),
#(19422618, 8604),
#(19422620, 8604),
#(19422613, 8604),
#(19422617, 8604),
#(19422661, 10060),
#(19422662, 8604),
#(19422663, 6436),
#(19422664, 6436),
#(19422667, 5856),
#(19422668, 5856),
#(19422648, 3168),
#(19422649, 3168),
#(19422650, 3168),
#(19422651, 3168),
#(19422652, 3168),
#(19422653, 3168),
#(19422654, 3168),
#(19422655, 4456),
#(19422658, 4456),
#(19422659, 4456),
#(19422660, 3168),
#(19422605, 8604),
#(19422688, 8332),
#(19422689, 3840),
#(19422690, 5856),
#(19422691, 5856),
#(19422692, 12024),
#(19422693, 5856),
#(19422699, 2640),
#(19422701, 11460),
#(19422702, 1672),
#(19422703, 6632),
#(19422704, 7764),
#(19422705, 6632),
#(19422717, 12576),
#(19422725, 11860),
#(19422762, 12964),
#(19422787, 8716),
#(19422795, 6632),
#(19422790, 6632),
# (19422592, 10840),
#(19422596, 10840),
#(19422595, 10840),
#(19422597, 10840),
#(19422618, 8604),
#(19422620, 8604),
#(19422613, 8604),
#(19422617, 8604),
#(19422661, 10060),
#(19422662, 8604),
#(19422663, 6436),
#(19422664, 6436),
#(19422667, 5856),
#(19422668, 5856),
#(19422648, 3168),
#(19422649, 3168),
#(19422650, 3168),
#(19422651, 3168),
#(19422652, 3168),
#(19422653, 3168),
#(19422654, 3168),
#(19422655, 4456),
#(19422658, 4456),
#(19422659, 4456),
#(19422660, 3168),
#(19422605, 8604),
#(19422688, 8332),
#(19422689, 3840),
#(19422690, 5856),
#(19422691, 5856),
#(19422692, 12024),
#(19422693, 5856),
#(19422699, 2640),
#(19422701, 11460),
#(19422702, 1672),
#(19422703, 6632),
#(19422704, 7764),
#(19422705, 6632),
#(19422717, 12576),
#(19422725, 11860),
#(19422762, 12964),
#(19422787, 8716),
#(19422795, 6632),
#(19422790, 6632),
#(2126,''),
#(2127,''),
#(2128,''),
#(2129,''),
#(2130,''),
#(2131,''),
#(2132,''),
#(2133,''),
#(2134,''),
#(2135,''),
#(2136,''),
#(2137,''),
#(2138,''),
#(2139,''),
#(2140,''),
#(2141,''),
#(2142,''),
#(2143,''),
#(2144,''),
#(2145,''),
#(2146,''),
#(2147,''),
#(2148,''),
#(2149,''),
#(2150,''),
#(2151,''),
#(2152,''),
#(2153,''),
#(2154,''),
#(2155,''),
#(2156,''),
#(2157,''),
#(2158,''),
#(2159,''),
#(2160,''),
#(2161,''),
#(2162,''),
#(2163,''),
#(2164,''),
#(2112,''),
#(2116,''),
#(2120,'')]

# load train logs - attack
for line in file.readlines():
    record = json.loads(line)
    x_train.append(record)

# load train logs and test logs - normal
# 0601 ppt better result - train/test all attack logs + 50000/20000 normal logs
count = 0
for line in file2.readlines():
    if count < 50000:
        record = json.loads(line)
        x_train.append(record)
        count = count + 1
    elif count < 60000: 
        record = json.loads(line)
        x_test.append(record)
        count = count + 1
    else:
        break

count=0
#load test logs - attack2
for line in file3.readlines():
    record = json.loads(line)
    x_test.append(record)

#for line in file4.readlines():
#    if count<50000:
#        record = json.loads(line)
#        x_test.append(record)
#        count=count+1
#    else:
#        break
## load test logs - normal
#count=0
#for line in file2.readlines():
#    if count<20000:
#        record=json.loads(line)
#        count=count+1
#        continue
#    if count==30000:
#        break
#    record=json.loads(line)
#    x_test.append(record)
#    count=count+1

x_train = pd.json_normalize(x_train)
x_train = x_train.replace(np.nan, '', regex=True)

#x_train=x_train[x_train['_source.process.pid']!=''] # not considering
#powershell logs
x_test = pd.json_normalize(x_test)
x_test = x_test.replace(np.nan, '', regex=True)
#x_test=x_test[x_test['_source.process.pid']!=''] # not considering powershell
#logs

# label the logs
for i in range(x_train.shape[0]):
    if i%1000==0:
        print("i: ",i)
    if (x_train.iloc[i].get("_source.winlog.record_id"),x_train.iloc[i].get('_source.process.pid')) in true_positive_tuples:
        y_train.append('anomaly')
    else:
        y_train.append('normal')

# train and test - Decision Tree
#model = make_pipeline(TfidfVectorizer(), DecisionTreeClassifier())
#model=make_pipeline(TfidfVectorizer(),KNeighborsClassifier())
#model.fit(x_train[field1], y_train)
#joblib.dump(model,'model_field1')
#model=joblib.load('model_field1')
#x_test['result'] = model.predict(x_test[field1])
#anomaly = x_test.loc[x_test['result'] == 'anomaly']
#normal = x_test.loc[x_test['result'] == 'normal']
#model.fit(x_train[field3], y_train)
#joblib.dump(model,'model_field3')
#model=joblib.load('model_field3')
#x_test['result2'] = model.predict(x_test[field3])
#anomaly2 = x_test.loc[x_test['result2'] == 'anomaly']
#normal2 = x_test.loc[x_test['result2'] == 'normal']
#model.fit(x_train[field2], y_train)
#x_test['result3'] = model.predict(x_test[field2])
#anomaly3 = x_test.loc[x_test['result3'] == 'anomaly']
#normal3 = x_test.loc[x_test['result3'] == 'normal']
#model = make_pipeline(TfidfVectorizer(), DecisionTreeClassifier())
#model.fit(x_train[field5], y_train)
#x_test['result4'] = model.predict(x_test[field5])
#anomaly4 = x_test.loc[x_test['result4'] == 'anomaly']
#normal4 = x_test.loc[x_test['result4'] == 'normal']
#model.fit(x_train[field13], y_train)
#x_test['result5'] = model.predict(x_test[field13])
#anomaly5 = x_test.loc[x_test['result5'] == 'anomaly']
#normal5 = x_test.loc[x_test['result5'] == 'normal']
#model = make_pipeline(TfidfVectorizer(), DecisionTreeClassifier())
#model.fit(x_train[field6], y_train)
#x_test['result6'] = model.predict(x_test[field6])
#anomaly6 = x_test.loc[x_test['result6'] == 'anomaly']
#normal6 = x_test.loc[x_test['result6'] == 'normal']

# nn
#model_nn = NearestNeighbors(n_neighbors = 3)
#value=np.array(x_train[[field1]])
#label_encoder = LabelEncoder()
#integer_encoded = label_encoder.fit_transform(value)
#x_train[[field1]]=np.reshape(integer_encoded.tolist(),(x_train.shape[0],1))
#value=np.array(x_train[[field2]])
#label_encoder = LabelEncoder()
#integer_encoded = label_encoder.fit_transform(value)
#x_train[[field2]]=np.reshape(integer_encoded.tolist(),(x_train.shape[0],1))
#df=x_train[[field1,field2]]
#model_nn.fit(df.values)
#distances, indexes = model_nn.kneighbors(df.values)
#outlier_index = np.where(distances.mean(axis = 1) > 0.15)
#anomaly = x_train.iloc[outlier_index]

# SVM
model_svm=make_pipeline(TfidfVectorizer(), svm.SVC(kernel = 'linear'))
model_svm.fit(x_train[field1], y_train)
joblib.dump(model_svm,'svm_model_field1')
model_svm=joblib.load('svm_model_field1')
x_test['result'] = model_svm.predict(x_test[field1])
anomaly = x_test.loc[x_test['result'] == 'anomaly']
normal = x_test.loc[x_test['result'] == 'normal']
print('after testing field1')
model_svm.fit(x_train[field3], y_train)
joblib.dump(model_svm,'svm_model_field3')
model_svm=joblib.load('svm_model_field3')
x_test['result2'] = model_svm.predict(x_test[field3])
anomaly2 = x_test.loc[x_test['result2'] == 'anomaly']
normal2 = x_test.loc[x_test['result2'] == 'normal']
print('after testing field2')
# decrease false negative
#print(x_test)
anomaly_pid = []
for i in range(anomaly.shape[0]):
    if anomaly.iloc[i].get('_source.process.pid') != '':
        anomaly_pid.append(anomaly.iloc[i].get('_source.process.pid'))

for i in range(x_test.shape[0]):
    x_test.loc[i,'result_2'] = x_test.loc[i,'result']
    if x_test.iloc[i].get('_source.process.pid') in anomaly_pid:
        x_test.loc[i,'result_2'] = 'anomaly'  

#anomaly = x_test.loc[(x_test['result_2'] == 'anomaly')]
#normal = x_test.loc[(x_test['result_2'] == 'normal')]
print(anomaly_pid)

anomaly_pid2 = []
for i in range(anomaly2.shape[0]):
    if anomaly2.iloc[i].get('_source.process.pid') != '':
        anomaly_pid2.append(anomaly2.iloc[i].get('_source.process.pid'))

for i in range(x_test.shape[0]):
    x_test.loc[i,'result2_2'] = x_test.loc[i,'result2']
    if x_test.iloc[i].get('_source.process.pid') in anomaly_pid2:
        x_test.loc[i,'result2_2'] = 'anomaly'  

#anomaly2 = x_test.loc[(x_test['result2_2'] == 'anomaly')]
#normal2 = x_test.loc[(x_test['result2_2'] == 'normal')]
print(anomaly_pid2)

#anomaly_pid3 = []
#for i in range(anomaly3.shape[0]):
#    if anomaly3.iloc[i].get('_source.process.pid') != '':
#        anomaly_pid3.append(anomaly3.iloc[i].get('_source.process.pid'))

#for i in range(x_test.shape[0]):
#    x_test.loc[i,'result3_2'] = x_test.loc[i,'result3']
#    if x_test.iloc[i].get('_source.process.pid') in anomaly_pid3:
#        x_test.loc[i,'result3_2'] = 'anomaly'  

#anomaly3 = x_test.loc[(x_test['result3_2'] == 'anomaly')]
#normal3 = x_test.loc[(x_test['result3_2'] == 'normal')]

#anomaly_pid4 = []
#for i in range(anomaly4.shape[0]):
#    if anomaly4.iloc[i].get('_source.process.pid') != '':
#        anomaly_pid4.append(anomaly4.iloc[i].get('_source.process.pid'))

#for i in range(x_test.shape[0]):
#    x_test.loc[i,'result4_2'] = x_test.loc[i,'result4']
#    if x_test.iloc[i].get('_source.process.pid') in anomaly_pid4:
#        x_test.loc[i,'result4_2'] = 'anomaly'  

#anomaly4 = x_test.loc[(x_test['result4_2'] == 'anomaly')]
#normal4 = x_test.loc[(x_test['result4_2'] == 'normal')]

#anomaly_pid5 = []
#for i in range(anomaly5.shape[0]):
#    if anomaly5.iloc[i].get('_source.process.pid') != '':
#        anomaly_pid5.append(anomaly5.iloc[i].get('_source.process.pid'))

#for i in range(x_test.shape[0]):
#    x_test.loc[i,'result5_2'] = x_test.loc[i,'result5']
#    if x_test.iloc[i].get('_source.process.pid') in anomaly_pid5:
#        x_test.loc[i,'result5_2'] = 'anomaly'  

#anomaly5 = x_test.loc[(x_test['result5_2'] == 'anomaly')]
#normal5 = x_test.loc[(x_test['result5_2'] == 'normal')]

for i in range(x_test.shape[0]):
    if x_test.iloc[i].get('result_2')=='anomaly' or x_test.iloc[i].get('result2_2')=='anomaly': 
        x_test.loc[i,'result3']='anomaly'
    else:
        x_test.loc[i,'result3']='normal'

# or x_test.iloc[i].get('result5')=='anomaly' or x_test.iloc[i].get('result6')=='anomaly':

#result_sum=[x_test.iloc[i].get('result_2'),x_test.iloc[i].get('result2_2'),x_test.iloc[i].get('result3_2'),x_test.iloc[i].get('result4_2'),x_test.iloc[i].get('result5_2')]
    #x_test.loc[i,'common_result']=Counter(result_sum).most_common(1)[0][0]
##result_sum=np.concatenate((x_test['result_2'],x_test['result2_2'],x_test['result3_2']), axis=0)

#anomaly = x_test.loc[(x_test['common_result'] == 'anomaly')]
#normal = x_test.loc[(x_test['common_result'] == 'normal')]
anomaly = x_test.loc[(x_test['result3'] == 'anomaly')]
normal = x_test.loc[(x_test['result3'] == 'normal')]
print('after combining two results')

# measure the performance
tp = 0.0
fp = 0.0
tn = 0.0
fn = 0.0
for i in range(anomaly.shape[0]):
    if (anomaly.iloc[i].get('_source.winlog.record_id'),anomaly.iloc[i].get('_source.process.pid')) in true_positive_tuples2:
        tp = tp + 1.0
        #if len(((anomaly.iloc[i]).loc[field1]).split('xlsm'))>1:
        #    path=(((anomaly.iloc[i]).loc[field1]).split('\"'))[len(((anoamly.iloc[i]).loc[field1]).split('\"'))-2]
        #    vbaparser = VBA_Parser(path)
    else:
        fp = fp + 1.0

        #print('fp',anomaly.iloc[i].get('_source.process.pid'))

for i in range(normal.shape[0]):
    if (normal.iloc[i].get('_source.winlog.record_id'),normal.iloc[i].get('_source.process.pid')) in true_positive_tuples2:
        fn = fn + 1.0
        #print('fn',normal.iloc[i].get('_source.process.pid'))
        #if(normal.iloc[i].get('_source.process.pid')==5088):
        #print(normal.iloc[i])
    else:
        tn = tn + 1.0

print('true positive: ',tp)
print('false positive: ',fp)
print('true negative: ',tn)
print('false negative: ',fn)
print('accuracy: ',(tp + tn) / (tp + fp + fn + tn))
print('precision: ',tp / (tp + fp))
print('recall: ',tp / (tp + fn))
print('F1: ',(2 * tp) / (2 * tp + fp + fn))
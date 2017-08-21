#from sklearn.ensemble import RandomForestClassifier
#from sklearn.metrics import roc_auc_score
import pickle
from sklearn import preprocessing
#from IPython.core.display import HTML
import pandas as pd
#import matplotlib.pyplot as plt
import numpy

f = open("RandomForestClassifier.pkl", 'rb')
model = pickle.load(f)
f.close()

#testData = pd.read_csv("cowrieTestingData.csv")
testData = pd.read_csv("cowrieProcessed.csv") #TODO: will need to change this to the actual filename (cowrieProcessed.csv)
#testData.drop(["DestinationIP", "DestinationPort", "Session"], axis = 1, inplace = True) #drop some variables
testData.drop(["DestinationIP", "DestinationPort", "Session", "Message", "EventID", "EncCS", "MacCS", "Version", "KexAlgs", "keyAlgs", "CompCS", "Date"], axis = 1, inplace = True) #drop some variables
sourceIP = testData.pop("SourceIP")
#testDataMalicious = testData.pop("Malicious") #TODO: will need to remove after testing

#testCat = pd.DataFrame([testData["Username"], testData["Password"], testData["Input"], testData["EventID"], testData["EncCS"], testData["MacCS"], testData["Version"], testData["KexAlgs"], testData["keyAlgs"], testData["CompCS"], testData["Date"], testData["Timestamp"], testData["Message"]]) #create the dataframe of categorical variables
testCat = pd.DataFrame([testData["Username"], testData["Password"], testData["Input"], testData["Timestamp"]]) #create the dataframe of categorical variables
testCat = testCat.transpose() #transpose the data frame bc how the constructor works

labelEncoder = preprocessing.LabelEncoder() #create label encoder - turn strings into labeled ints
testCat = testCat.apply(labelEncoder.fit_transform) #replace strings with ints (labels)

#testData.drop(["Username", "Password", "Input", "EventID", "EncCS", "MacCS", "Version", "KexAlgs", "keyAlgs", "CompCS", "Date", "Timestamp", "Message"], axis = 1, inplace = True) #remove categorical variables from testData
testData.drop(["Username", "Password", "Input", "Timestamp"], axis = 1, inplace = True) #remove categorical variables from testData

testNum = testData #get numerical variables

test = testNum.join(testCat) #combine the two dataframes


resultOutput = model.predict(test) #predict value

resultOutputDataFrame = pd.DataFrame(resultOutput)#, index = ["Prediction"])
sourceIPDataFrame = pd.DataFrame(sourceIP)#, index = ["Number", "SourceIP"])

combinedDataFrame = sourceIPDataFrame.join(resultOutputDataFrame)
#csvOutput = csvOutput[csvOutput.SourceIP != "SourceIP"]
#csvOutput.drop(csvOutput.columns[1], axis = 0, inplace = True)

csvOutput = combinedDataFrame.as_matrix()

numpy.savetxt("NewMLOutput.csv", csvOutput, delimiter=",", fmt="%s")

#csvOutput.to_csv("predictions.csv", sep = ',')
#print(csvOutput)
#numpy.savetxt("predictions.csv", resultOutput, delimiter=",") #save predictions array to a .csv file

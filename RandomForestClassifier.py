# coding: utf-8
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn import preprocessing
from IPython.core.display import HTML
import pandas as pd
import matplotlib.pyplot as plt
import numpy
x = pd.read_csv("cowrieTrainingData.csv", delimiter = ',')

y = x.pop("Malicious")
x.drop(["DestinationIP", "DestinationPort", "Session", "SourceIP"], axis = 1, inplace = True) #drop some variables (sourceIP would make it too easy in our case, since that's how we defined our good, which is why it's being dropped)

#fill missing numerical values with -1
x["SourcePort"].fillna(-1, inplace = True)
#x["DestinationPort"].fillna(-1, inplace = True)
x["Duration"].fillna(-1, inplace = True)

categorical_variables = ["Username", "Password", "Input", "EventID", "EncCS", "MacCS", "Version", "KexAlgs", "keyAlgs", "CompCS", "Timestamp", "Message"]
trainCat = pd.DataFrame([x["Username"], x["Password"], x["Input"], x["EventID"], x["EncCS"], x["MacCS"], x["Version"], x["KexAlgs"], x["keyAlgs"], x["CompCS"], x["Timestamp"], x["Message"]]) #create the dataframe of categorical variables
trainCat = trainCat.transpose() #transpose the data frame bc how the constructor works

labelEncoder = preprocessing.LabelEncoder() #create label encoder - turn strings into labeled ints
trainCat = trainCat.apply(labelEncoder.fit_transform) #replace strings with ints (labels)

x.drop(["Username", "Password", "Input", "EventID", "EncCS", "MacCS", "Version", "KexAlgs", "keyAlgs", "CompCS", "Timestamp", "Message"], axis = 1, inplace = True) #remove categorical variables from x

trainNum = x #get numerical variables

x = trainNum.join(trainCat) #combine the two dataframes

model = RandomForestClassifier(100, oob_score = True, n_jobs = -1, random_state = 42)
model.fit(x, y)

print(model.n_features_)

#print("C-stat: ", roc_auc_score(y, model.oob_prediction_))
model.feature_importances_

def graph_feature_importances(model, feature_names, autoscale=True, headroom=0.05, width=10, summarized_columns=None) :
    """
    By Mike Bernico

    Graphs the feature importances of a random decision forest using a horizontal bar chart.
    Probably works but untested on other sklearn.ensembles.

    Parameters
    ----------
    ensemble = Name of the ensemble whose features you would like graphed
    feature_names = A list of names of those features, displayed on the Y axis
    autoscale = True (Autoamatically adjust the X axis size to the largest feature + headroom) / False = scale from 0 to 1
    headroom = used with autoscale, .05 default
    width=figure width in inches
    summarized_columns = a list of column prefixes to summarize on, for dummy variables (e.g. [*day_*] would summarize all days
    """
    if autoscale:
        x_scale = model.feature_importances_.max()+ headroom
    else:
        x_scale = 1

    feature_dict = dict(zip(feature_names, model.feature_importances_))

    if summarized_columns:
        #some dummy columns need to be summarized
        for col_name in summarized_columns:
            #sum all the features that contain col_name, store in temp sum_value
            sum_value = sum(x for i, x in feature_dict.iteritems() if col_name in i )

            #now to remove all keys that are part of col_name
            keys_to_remove = [i for i in feature_dict.keys() if col_name in i ]
            for i in keys_to_remove:
                feature_dict.pop(i)
            #lastly, read the summarized field
            feature_dict[col_name] = sum_value

    results = pd.Series(feature_dict.values(), index=feature_dict.keys())
    results.sort(axis=1)
    results.plot.barh()
#    plt.show()


graph_feature_importances(model, x.columns, summarized_columns=categorical_variables)


#test different num trees
results = []
n_estimator_options = [30, 50, 100, 500, 1000, 2000]
treesROC = 0
treesIndex = 30
for trees in n_estimator_options:
    model = RandomForestClassifier(trees, oob_score = True, n_jobs = -1, random_state = 42)
    model.fit(x, y)
    print("trees: ", trees)
#    roc = roc_auc_score(y, model.oob_prediction_)
#    if (roc > treesROC):
#        treesIndex = trees
#    print("c-stat: ", roc)
#    results.append(roc)
    print("")

#pd.Series(results, n_estimator_options).plot() #plot the graph
#plt.show() #show the graph

#test different max features
results = []
max_features_options = ["auto", None, "sqrt", "log2", .9, .2]
maxFeaturesROC = 0
maxFeaturesIndex = "auto"
for feature in max_features_options:
    model = RandomForestClassifier(n_estimators = 50, oob_score = True, n_jobs = -1, random_state = 42, max_features = feature) #n_estimators should be max of what was found with last trial
    model.fit(x, y)
    print("option: ", feature)
 #   roc = roc_auc_score(y, model.oob_prediction_)
 #   if (roc > maxFeaturesROC):
#        maxFeaturesIndex = feature
#    print("c-stat: ", roc)
#    results.append(roc)
    print("")

#pd.Series(results, max_features_options).plot.barh()
#plt.show()


results = []
min_sample_leaf_options = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
minSampleROC = 0
minSampleIndex = 1
for min_sample in min_sample_leaf_options:
        model = RandomForestClassifier(n_estimators = 50, oob_score = True, n_jobs = -1, random_state = 42, max_features = maxFeaturesIndex, min_samples_leaf = min_sample) #n_estimators and max_features should be best options - change as necessary
        model.fit(x, y)
        print("min_sample: ", min_sample)
#        roc = roc_auc_score(y, model.oob_prediction_)
#        if (roc > minSampleROC):
#            minSampleIndex = min_sample
#        print("c-stat: ", roc)
#        results.append(roc)
        print("")

#pd.Series(results, min_sample_leaf_options).plot()
#plt.show()

model = RandomForestClassifier(n_estimators = treesIndex, oob_score = True, n_jobs = -1, random_state = 42, max_features = maxFeaturesIndex, min_samples_leaf = minSampleIndex) #n_estimators, max_features, and min_sample_leaf should be best options - TODO: change as necessary
model.fit(x, y)
#roc = roc_auc_score(y, model.oob_prediction_)
#print("final roc score: %f" % roc) #print final roc score

testData = pd.read_csv("cowrieTestingData.csv")
testData.drop(["DestinationIP", "DestinationPort", "Session", "SourceIP"], axis = 1, inplace = True) #drop some variables
testDataMalicious = testData.pop("Malicious")

testCat = pd.DataFrame([testData["Username"], testData["Password"], testData["Input"], testData["EventID"], testData["EncCS"], testData["MacCS"], testData["Version"], testData["KexAlgs"], testData["keyAlgs"], testData["CompCS"], testData["Timestamp"], testData["Message"]]) #create the dataframe of categorical variables
testCat = testCat.transpose() #transpose the data frame bc how the constructor works

labelEncoder = preprocessing.LabelEncoder() #create label encoder - turn strings into labeled ints
testCat = testCat.apply(labelEncoder.fit_transform) #replace strings with ints (labels)

testData.drop(["Username", "Password", "Input", "EventID", "EncCS", "MacCS", "Version", "KexAlgs", "keyAlgs", "CompCS", "Timestamp", "Message"], axis = 1, inplace = True) #remove categorical variables from testData

testNum = testData #get numerical variables

test = testNum.join(testCat) #combine the two dataframes


resultOutput = model.predict(test) #predict value


numpy.savetxt("predictions.csv", resultOutput, delimiter=",") #save predictions array to a .csv file
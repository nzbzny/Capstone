# coding: utf-8
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import roc_auc_score
from IPython.core.display import HTML
import pandas as pd
import matplotlib.pyplot as plt
x = pd.read_csv("cowrieProcessed.csv") #cowrie from 10-28
y = x.pop("Benign") #TODO: change this to the dependent variable
x.drop(["DestinationIP", "DestinationPort", "EncCS", "MacCS", "Version", "KexAlgs", "keyAlgs", "CompCS", "Session"], axis = 1, inplace = True) #drop some variables
x.describe()
print(x.describe())

#fill missing numerical values with -1
x["SourcePort"].fillna(-1, inplace = True)
#x["DestinationPort"].fillna(-1, inplace = True)
x["Duration"].fillna(-1, inplace = True)

#x.describe()
print(x)
numeric_variables = list(x.dtypes[x.dtypes != "object"].index)
x[numeric_variables].head()
model = RandomForestRegressor(n_estimators = 100, oob_score = True, random_state = 42) # build the model
model.fit(x[numeric_variables], y)
model.oob_score_ #oob is the r^2 value
model.oob_score_ #underscore at the end means it is only available after the fit method called
y_oob = model.oob_prediction_
print("c-stat: ", roc_auc_score(y, y_oob))
y_oob

def describe_categorical(x_in) :
    #just like describe but returns the results for the categorical variables only
    from IPython.display import display, HTML
    X = x_in #TODO: drop messages and eventID
    display(HTML(X[X.columns[x.dtypes == "object"]].describe().to_html()))

describe_categorical(x)
def clean_categorical(x): #fill empty categorical values with "None"
    try:
        return x[0]
    except TypeError:
        return "None"

categorical_variables = ["SourceIP", "Message", "Username", "Password", "Input", "EventID"]
for variable in categorical_variables:
    x[variable].fillna("Missing", inplace = True) #fill missing data with the word "Missing"
    dummies = pd.get_dummies(x[variable], prefix = variable) #create array of dummies
    x = pd.concat([x, dummies], axis = 1)
    x.drop([variable], axis = 1, inplace = True)

model = RandomForestRegressor(100, oob_score = True, n_jobs = -1, random_state = 42)
model.fit(x, y)
print("C-stat: ", roc_auc_score(y, model.oob_prediction_))
model.feature_importances_
feature_importances = pd.Series(model.feature_importances_, index = x.columns)
feature_importances.sort()
feature_importances.plot.barh()
plt.show() #this is what's needed to get the bar graph to show up

#test different num trees
results = []
n_estimator_options = [30, 50, 100, 500, 1000, 2000]
for trees in n_estimator_options:
    model = RandomForestRegressor(trees, oob_score = True, n_jobs = -1, random_state = 42)
    model.fit(x, y)
    print("trees: ", trees)
    roc = roc_auc_score(y, model.oob_prediction_)
    print("c-stat: ", roc)
    results.append(roc)
    print("")

pd.Series(results, n_estimator_options).plot() #plot the graph
plt.show() #show the graph

#test different max features
results = []
max_features_options = ["auto", None, "sqrt", "log2", .9, .2]
for feature in max_features_options:
    model = RandomForestRegressor(n_estimators = 50, oob_score = True, n_jobs = -1, random_state = 42, max_features = feature) #n_estimators should be max of what was found with last trial
    model.fit(x, y)
    print("option: ", feature)
    roc = roc_auc_score(y, model.oob_prediction_)
    print("c-stat: ", roc)
    results.append(roc)
    print("")

pd.Series(results, max_features_options).plot.barh()
plt.show()

results = []
min_sample_leaf_options = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
for min_sample in min_sample_leaf_options:
        model = RandomForestRegressor(n_estimators = 50, oob_score = True, n_jobs = -1, random_state = 42, max_features = "auto", min_samples_leaf = min_sample) #n_estimators and max_features should be best options - change as necessary
        model.fit(x, y)
        print("min_sample: ", min_sample)
        roc = roc_auc_score(y, model.oob_prediction_)
        print("c-stat: ", roc)
        results.append(roc)
        print("")

pd.Series(results, min_sample_leaf_options).plot()
plt.show()

model = RandomForestRegressor(n_estimators = 1000, oob_score = True, n_jobs = -1, random_state = 42, max_features = "auto", min_samples_leaf = 4) #n_estimators, max_features, and min_sample_leaf should be best options - change as necessary
model.fit(x, y)
roc = roc_auc_score(y, model.oob_prediction_)
print(roc)

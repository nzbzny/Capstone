# Capstone Project
Using machine learning to create a behavioral Intrusion Detection System. Data is being collected from a honeypot running Cowrie, which was branched off of Kippo.  
Currently the data collection and data parsing code is in C++, the machine learning code is in Python, and there is a script written in VBA to infill missing values, but that will eventually be converted to a different language so it doesn't need to be manually run by the user if there is time remaining before the year ends. All code is written for a Linux kernel and uses Linux terminal commands.  
SplitBigFiles.cpp exists because there were some extraordinarily large TCPDump files (> 2 million lines), so that code splits them up into quickly parseable 30,000 line files  
RunProcessCode.cpp runs the code for the TCPDump files after they were split up by SplitBigFiles.cpp - to avoid having to sit there for an hour and just continually type ./main.  
The VBA Infill Values Script infills missing values that were not successfully collected from Cowrie or TCPDump with a -1. Duration values, however are only written when the session is closed, so the script also infills the duration value for that session to every other event in the session (open, close, input commands, etc.)

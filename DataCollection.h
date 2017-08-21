/*
 * DataCollection.h
 * Created on October 24, 2016
 * Author: Noah Zbozny
 */
 #ifndef DATACOLLECTION_H
 #define DATACOLLECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <chrono>
#include <unistd.h>

class DataCollection {
  std::string workingDir;
  std::vector<std::string> nmapData; //deal with the vector stuff
  std::vector<std::string> logData;
  std::vector<std::string> tcpdumpData;
  std::vector<std::string> cowrieData;
  std::vector<std::string> oldCowrieFileNames;
  std::string currentCowrieFileName;
  int lastCowrieDataSize;

public:
  DataCollection(); //constructor
  bool hasNmap(); //determine if the computer has nmap
  bool hasIPTables(); //determine if the computer has iptables`
  bool hasTCPDump(); //determine if the computer has tcpdump
  void setup(); //sets up everything necessary for the class to run before it does anything else
  void updateApplications(); //updates all applications on the computer
  void findWorkingDir(); //find the working directory for the code
  void downloadNmap(); //download nmap
  void downloadIPTables(); //download iptables
  void downloadTCPDump(); //download tcpdump
  void setupIPTablesRules(); //give iptables rules for logging certain ports
  void runNmap(std::string ip); //run nmap against an ip
  void runTCPDump(int packetsToBeCaptured); //run tcpdump until a certain number of packets are captured
  void grabTCPDumpData(); //get the tcpdump data
  void getLogs(); //get iptables logs data
  void getLogsTesting();
  void getCowrie();
  void emptyNmapData();
  void emptyLogData();
  void emptyTCPDumpData();
  void emptyCowrieData();
  bool newCowrieFileName();
  bool newCowrieData();
  void collectNewCowrieData();
  std::vector<std::string> getNmapData();
  std::vector<std::string> getLogData();
  std::vector<std::string> getTCPDumpData();
  std::vector<std::string> getNewCowrieData();
  std::vector<std::string> getCowrieData();
  std::vector<std::string> getTCPDumpDataFile(); //temp for testing

};

#endif

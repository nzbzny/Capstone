/*
 * DataPreprocessing.h
 * Created on November 3, 2016
 * Author: Noah Zbozny
 */

#ifndef DATAPREPROCESSING_H
#define DATAPREPROCESSING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <math.h>
#include <fstream>
#include "DataCollection.h"
#include "TCPDumpProcessor.h"
#include "LogFileProcessor.h"
#include "CowrieProcessor.h"

class DataPreprocessing {
  TCPDumpProcessor tcpdump;
  LogFileProcessor logs;


public:
  DataPreprocessing();
  void runProcessTCPDump(std::vector<std::string> tcpdumpData);

  void processCowrie(std::vector<std::string> cowrieData);
  void processNmap(std::vector<std::string> nmapData);
  void runProcessLogs(std::vector<std::string> logsData);
  bool torRouter(std::string ip);
  void printTCP();
  void printLog();

  void checkTorRouter();
};

#endif

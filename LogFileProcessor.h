/*
 * LogFileProcessor.h
 * Created on December 12, 2016
 * Author: Noah Zbozny
 */

#ifndef LOGFILEPROCESSOR_H
#define LOGFILEPROCESSOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <math.h>
#include <fstream>

class LogFileProcessor {

std::vector<std::string> traffic;
std::vector<std::string> macAddress;
std::vector<std::string> srcIP;
std::vector<std::string> destIP;
std::vector<int> length;
std::vector<std::string> tosHex;
std::vector<int> tosDec;
std::vector<std::string> precHex;
std::vector<int> precDec;
std::vector<int> ttl;
std::vector<int> id;
std::vector<std::string> protocol;
std::vector<int> srcPort;
std::vector<int> destPort;
std::vector<int> window;
std::vector<std::string> resetHex;
std::vector<int> resetDec;
std::string logPrefix;


public:
  LogFileProcessor();
  int hexToDec(std::string hexValue);
  std::vector<std::string> breakUpLogFiles();
  void findTimestamp(std::string logString);
  int findTrafficType(std::string logString);
  void findMacAddress(std::string logString);
  void findSourceIP(std::string logString);
  void findDestinationIP(std::string logString);
  void findLength(std::string logString);
  void findTOS(std::string logString);
  void findPrecedence(std::string logString);
  void findTTL(std::string logString);
  void findID(std::string logString);
  void findFlags(std::string logString);
  void findProtocol(std::string logString);
  void findSourcePort(std::string logString);
  void findDestPort(std::string logString);
  void findWindow(std::string logString);
  void findReset(std::string logString);
  void processLogs(std::vector<std::string> logVector);
  void print();
  std::vector<std::string> getSrcIP();
  std::string findCSVFileNumber();
  void outputCSV();
};

#endif

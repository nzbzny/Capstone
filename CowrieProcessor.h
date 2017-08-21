/*
 * CowrieProcessor.h
 * Created on January 1, 2017
 * Author: Noah Zbozny
 */

#ifndef COWRIEPROCESSOR_H
#define COWRIEPROCESSOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <math.h>
#include <fstream>

class CowrieProcessor {

  std::vector<std::string> eventID;
  std::vector<std::string> srcIP;
  std::vector<int> srcPort;
  std::vector<int> destPort;
  std::vector<std::string> destIP;
  std::vector<std::string> message;
  std::vector<std::string> duration; //figure out how to turn into a float
  std::vector<std::string> macCS;
  std::vector<std::string> version;
  std::vector<std::string> kexAlgs;
  std::vector<std::string> compCS;
  std::vector<std::string> keyAlgs;
  std::vector<std::string> encCS;
  std::vector<std::string> username;
  std::vector<std::string> password;
  std::vector<std::string> input;
  std::vector<int> session;
  std::vector<std::string> sessionHex;
  std::vector<std::string> timestamp;
  std::vector<std::string> date;

public:
  CowrieProcessor();
  int hexToDec(std::string hexValue);

  void findEventID(std::string cowrieString);
  void findSourceIP(std::string cowrieString);
  void findSourcePort(std::string cowrieString);
  void findDestinationPort(std::string cowrieString);
  void findDestinationIP(std::string cowrieString);
  void findMessage(std::string cowrieString);
  void findDuration(std::string cowrieString);
  void findMacCS(std::string cowrieString);
  void findVersion(std::string cowrieString);
  void findKexAlgs(std::string cowrieString);
  void findCompCS(std::string cowrieString);
  void findKeyAlgs(std::string cowrieString);
  void findEncCS(std::string cowrieString);
  void findUsername(std::string cowrieString);
  void findPassword(std::string cowrieString);
  void findInput(std::string cowrieString);
  void findSession(std::string cowrieString);
  void findTimestamp(std::string cowrieString);
  void process(std::vector<std::string> cowrieData);
  void print();
  std::string findCSVFileNumber();
  bool outputCSV();
  void emptyData();
  void getNewCowrieData();

  std::vector<std::string> getUsernames();
  std::vector<std::string> getPasswords();
  std::vector<std::string> getInputs();
};

#endif

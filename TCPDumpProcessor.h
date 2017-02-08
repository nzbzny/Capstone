/*
 * DataPreprocessing.h
 * Created on November 3, 2016
 * Author: Noah Zbozny
 */

#ifndef TCPDUMPPROCESSOR_H
#define TCPDUMPPROCESSOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <math.h>
#include <fstream>

class TCPDumpProcessor {
  std::vector< std::vector<std::string> > ipFlags; //two dimensional array since one packet can have multiple flags
  std::vector< std::vector<std::string> > options;
  std::vector< std::vector<int> > tcpFlags;
  std::vector<std::string> srcIP; //where the packet is coming from
  std::vector<std::string> destIP; //where the packet is going
  std::vector<std::string> timestamp; //what time was the packet received
  std::vector<std::string> tosHex; //type of service (priority level) hex value
  std::vector<std::string> connectionType;
  std::vector<std::string> connectionProtocol;
  std::vector<std::string> protocol;
  std::vector<std::string> macAddress; //mac address
  std::vector<int> ack;
  std::vector<int> win;
  std::vector<int> trafficDirection; //0 = out and 1 = in
  std::vector<int> srcPort; //what port did the packet originate from on its computer
  std::vector<int> destPort; //what port is the packet going to
  std::vector<int> ipPacketLength; //length of the entire packet in bytes including headers
  std::vector<int> tcpPacketLength; //length of the TCP packet in bytes including headers
  std::vector<int> ipTOS; //type of service decimal value
  std::vector<int> ipTTL; //time to live - how many hops before the packet expires
  std::vector<int> ipID; //used for identifying parts of a fragmented datagram
  std::vector<int> ipFragmentOffset; //used with fragmented packets
  std::vector<int> srcTCPWin;


public:
  TCPDumpProcessor();
  std::vector<std::string> fixTCPDumpData(std::vector<std::string> startData);
  std::vector<std::string> splitUpTCPDumpString(std::string tcpdumpString);
  int hexToDec(std::string hexValue);
  int tcpFindTimestamp(std::string tcpdumpString);
  int tcpTrafficDirection(std::string tcpdumpString, int startIndex);
  int tcpFindMacAddress(std::string tcpdumpString, int startIndex);
  int tcpFindConnectionType(std::string tcpdumpString, int startIndex);
  int tcpFindConnectionProtocol(std::string tcpdumpString, int startIndex);
  void tcpFindIPPacketLength(std::string tcpdumpString);
  void tcpFindTOS(std::string tcpdumpString);
  void tcpFindTTL(std::string tcpdumpString);
  void tcpFindID(std::string tcpdumpString);
  void tcpFindFragmentOffset(std::string tcpdumpString);
  void tcpFindIPFlags(std::string tcpdumpString);
  void tcpFindSource(std::string tcpdumpString);
  void tcpFindDestination(std::string tcpdumpString);
  void tcpFindTCPFlags(std::string tcpdumpString);
  bool tcpFindChecksum(std::string tcpdumpString);
  void tcpFindAck(std::string tcpdumpString);
  void tcpFindWin(std::string tcpdumpString);
  void tcpFindOptions(std::string tcpdumpString);
  void tcpFindTCPPacketLength(std::string tcpdumpString);
  void printTCP();
  void processTCPDump(std::vector<std::string> tcpdumpData);
  std::string findCSVFileNumber();
  void outputCSV();
};

#endif

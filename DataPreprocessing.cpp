/*
 * DataPreprocessing.cpp
 * Created on November 3, 2016
 * Author: Noah Zbozny
 */

/*
 *
 * TCPDumpProcessor and LogFileProcessor are no longer implemented - CowrieProcessor is the only source of data being used at the moment.
 * Given the time for the project, there was not enough time to link them all together and use them all for data collection, so since Cowrie is the most valuable data source it is the only one implemented.
 *
 */

#include "DataPreprocessing.h"

DataPreprocessing::DataPreprocessing() {
  tcpdump;
  logs;
  cowrie;
}

void DataPreprocessing::runProcessTCPDump(std::vector<std::string> tcpdumpData) {
  tcpdump.processTCPDump(tcpdumpData); //run the process code
}

bool DataPreprocessing::processCowrie(std::vector<std::string> cowrieData) {
  cowrie.process(cowrieData); //run the processing code
  return cowrie.outputCSV(); //output to a csv file
}

void DataPreprocessing::processNmap(std::vector<std::string> nmapData) {

}

void DataPreprocessing::runProcessLogs(std::vector<std::string> logsData) {
  logs.processLogs(logsData); //run the process code
}

bool DataPreprocessing::torRouter(std::string ip) { //script to identify if an ip is from a tor router
  std::string line;
  system("touch torNode.txt"); //temp file to store grep in
  std::string systemCommand = "grep " + ip + " torNodeIPsSorted.txt > torNode.txt"; //torNodeIPsSorted.txt is the list of tor node ip's
  bool result = false;
  system(systemCommand.c_str()); //execute command
  std::ifstream fileStream; //input filestream
  fileStream.open("torNode.txt"); //open file
  while (getline(fileStream, line)) {
    result = true; //if there's anything in the file, return true
  }
  fileStream.close(); //close filestream
  system("rm -f torNode.txt"); //remove the temp file
  return result;
}

void DataPreprocessing::printTCP() {
  tcpdump.printTCP(); //run print code
}

void DataPreprocessing::printLog() {
  logs.print(); //run print code
}

void DataPreprocessing::checkTorRouter() {
  std::vector<std::string> srcIPVector = logs.getSrcIP(); //get list of source ip's
  int counter = 0;
  for (int i = 0; i < srcIPVector.size(); i++) {
    if (torRouter(srcIPVector[i])) { //check if the source ip is a tor router
      std::cout << srcIPVector[i] << "\n"; //output
      counter++; //count number or tor routers that hit the server
    }
  }
  std::cout << counter << "\n"; //output the counter
}

void DataPreprocessing::emptyData() {
  //tcpdump.emptyData();
  //logs.emptyData();
  cowrie.emptyData();
}

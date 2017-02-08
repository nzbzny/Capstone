/*
 * DataPreprocessing.cpp
 * Created on November 3, 2016
 * Author: Noah Zbozny
 */
#include "DataPreprocessing.h"

DataPreprocessing::DataPreprocessing() {
  tcpdump;
  logs;
}

void DataPreprocessing::runProcessTCPDump(std::vector<std::string> tcpdumpData) {
  tcpdump.processTCPDump(tcpdumpData); //run the process code
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

int main() {
  DataCollection collector;
  TCPDumpProcessor tcpdump;
  DataPreprocessing processor;
  LogFileProcessor logs;
  CowrieProcessor cowrie;

/*  collector.getLogsTesting(); //get temp log file
  std::vector<std::string> logVector = collector.getLogData(); //add temp log file to vector
  logs.processLogs(logVector); //process
  logs.outputCSV(); //output
*/
/*  std::vector<std::string> tcpdumpData = collector.getTCPDumpDataFile(); //get temp file
  std::cout << "collector done";
  tcpdump.processTCPDump(tcpdumpData); //process
  std::cout << "processed << \n";
  tcpdump.outputCSV(); //output
*/

  collector.getCowrieTesting(); //get temp file
  std::vector<std::string> cowrieData = collector.getCowrieData(); //add temp file to vector
  cowrie.process(cowrieData); //process
  cowrie.outputCSV(); //output

}

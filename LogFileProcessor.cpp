/*
 * LogFileProcessor.cpp
 * Created on December 12, 2016
 * Author: Noah Zbozny
 */

#include "LogFileProcessor.h"

LogFileProcessor::LogFileProcessor() {
  logPrefix = "ctrlCode: ";
}

std::vector<std::string> LogFileProcessor::breakUpLogFiles() {
    std::vector<std::string> logFile;
    std::string line; //required to get the file value line by line
    std::ifstream fileStream; //creates an input filestream to read from

    fileStream.open("syslog.txt"); //opens the filestream
    while (getline(fileStream, line)) { //while there are still lines in the filestream
      logFile.push_back(line);
    }
    fileStream.close(); //close the filestream
    return logFile;
}

int LogFileProcessor::hexToDec(std::string hexValue) {
  int result = 0; //final answer
  int decValue = 0; //temp variable for holding the conversion for that number
  int endIndex = hexValue.find("0x") + 2;
  for (int i = hexValue.length() - 1; i > endIndex; i--) { //going backwards through the loop (starting at 16^0)
    if (hexValue[i] > 47 && hexValue[i] < 58) { //if it is a decimal number
      decValue = hexValue[i] - 48; //convert to decimal value
    } else if (hexValue[i] > 64 && hexValue[i] < 71) { //if it is an uppercase letter
      decValue = hexValue[i] - 55; //convert to decimal value
    } else if (hexValue[i] > 96 && hexValue[i] < 103) { //if it is a lowercase letter
      decValue = hexValue[i] - 87; //convert to decimal value
    } else { //if it is none of the above (invalid input)
      return -1; //failed
    }
    result += (decValue * pow(16, hexValue.length() - 1 - i)); //math to convert to hex - power of 0 at the last number in the string power of hexValue.length() - 1 at the first number in the string
  }
  return result; //return
}


void LogFileProcessor::findTimestamp(std::string logString) {

}

int LogFileProcessor::findTrafficType(std::string logString) { //find the port the traffic came from (i.e., eth0)
  std::string result;
  if (logString[logString.find("OUT=", logString.find(logPrefix)) + 4] == ' ' && logString[logString.find("IN=", logString.find(logPrefix)) + 3] != ' ') { //if in traffic since that's all we're looking at
    for (int i = logString.find("IN=", logString.find(logPrefix)) + 3; i < logString.length(); i++) { //for startindex to end
      if (logString[i] == ' ') { //end of traffic type
        traffic.push_back(result);
        return 1; //success
      } else {
        result += logString[i]; //add char by char
      }
    }
  }
  return -1; //fail to find end
}
void LogFileProcessor::findMacAddress(std::string logString) { //find incoming mac address
  std::string result;
  int colonCounter = 0;
  int startIndex = logString.find("MAC=", logString.find(logPrefix)) + 4; //find start index - +4 is because "MAC=" is 4 chars
  if (logString[startIndex] != ' ' && startIndex != -1) { //if the start index was found and the mac address isn't empty
    for (int i = startIndex; i < logString.length(); i++) { //go to the end of the string if necessary
      if (logString[i] == ':' && colonCounter == 5) { //mac address has 4 colons - 4 octets
        macAddress.push_back(result); //add the result to the vector
        return; //exit
      } else { //if not reached the end of the mac address
        if (logString[i] == ':') { //new octet
          colonCounter++; //add to # octets
        }
        result += logString[i]; //add char by char
      }
    }
  }
  macAddress.push_back(""); //fail if the string was ended without the mac address being pushed back yet
}
void LogFileProcessor::findSourceIP(std::string logString) { //find source ip
  std::string result;
  int startIndex = logString.find("SRC=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') { //end of source ip
        srcIP.push_back(result);
        return;
      } else {
        result += logString[i];
      }
    }
  }
  srcIP.push_back(""); //fail
}
void LogFileProcessor::findDestinationIP(std::string logString) { //find destination io
  std::string result;
  int startIndex = logString.find("DST=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') { //end of destination ip
        destIP.push_back(result);
        return;
      } else {
        result += logString[i]; //add char by char
      }
    }
  }
  destIP.push_back(""); //fail
}
void LogFileProcessor::findLength(std::string logString) { //find length of the packet
  std::string result;
  int startIndex = logString.find("LEN=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') { //end of the length value
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        length.push_back(atoi(result.c_str())); //convert the string to an int
        return;
      } else {
        result += logString[i]; //add char by char
      }
    }
  }
  length.push_back(-1); //fail
}
void LogFileProcessor::findTOS(std::string logString) { //type of service
  std::string result;
  int startIndex = logString.find("TOS=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        tosHex.push_back(result); //value is in hex
        tosDec.push_back(hexToDec(result)); //convert hex to dec
        return;
      } else {
        result += logString[i];
      }
    }
  }
  tosHex.push_back(""); //fail
  tosDec.push_back(-1); //push back to both arrays
}
void LogFileProcessor::findPrecedence(std::string logString) { //precedence level of the packet
  std::string result;
  int startIndex = logString.find("PREC=", logString.find(logPrefix)) + 5;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        precHex.push_back(result); //log value is in hex
        precDec.push_back(hexToDec(result)); //convert to dec
        return;
      } else {
        result += logString[i];
      }
    }
  }
  precHex.push_back(""); //fail
  precDec.push_back(-1); //add to both vectors
}
void LogFileProcessor::findTTL(std::string logString) { //time to live
  std::string result;
  int startIndex = logString.find("TTL=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        ttl.push_back(atoi(result.c_str())); //turn to int
        return;
      } else {
        result += logString[i];
      }
    }
  }
  ttl.push_back(-1); //fail
}
void LogFileProcessor::findID(std::string logString) { //packet id
  std::string result;
  int startIndex = logString.find("ID=", logString.find(logPrefix)) + 3;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        id.push_back(atoi(result.c_str())); //convert string to int
        return;
      } else {
        result += logString[i];
      }
    }
  }
  id.push_back(-1); //fail
}
void LogFileProcessor::findFlags(std::string logString) {}
void LogFileProcessor::findProtocol(std::string logString) { //protocol
  std::string result;
  int startIndex = logString.find("PROTO=", logString.find(logPrefix)) + 6;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        protocol.push_back(result);
        return;
      } else {
        result += logString[i];
      }
    }
  }
  protocol.push_back(""); //fail
}
void LogFileProcessor::findSourcePort(std::string logString) { //originating port
  std::string result;
  int startIndex = logString.find("SPT=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        srcPort.push_back(atoi(result.c_str())); //convert string to int
        return;
      } else {
        result += logString[i];
      }
    }
  }
  srcPort.push_back(-1); //fail
}
void LogFileProcessor::findDestPort(std::string logString) { //destination port
  std::string result;
  int startIndex = logString.find("DPT=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        destPort.push_back(atoi(result.c_str())); //string to int
        return;
      } else {
        result += logString[i];
      }
    }
  }
  destPort.push_back(-1); //fail
}
void LogFileProcessor::findWindow(std::string logString) { //tcp window size
  std::string result;
  int startIndex = logString.find("WINDOW=", logString.find(logPrefix)) + 7;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        window.push_back(atoi(result.c_str())); //string to int
        return;
      } else {
        result += logString[i];
      }
    }
  }
  window.push_back(-1); //fail
}
void LogFileProcessor::findReset(std::string logString) { //reset value
  std::string result;
  int startIndex = logString.find("RES=", logString.find(logPrefix)) + 4;
  if (logString[startIndex] != ' ') {
    for (int i = startIndex; i < logString.length(); i++) {
      if (logString[i] == ' ') {
        resetHex.push_back(result); //value is in hex
        resetDec.push_back(hexToDec(result)); //convert to dec
        return;
      } else {
        result += logString[i];
      }
    }
  }
  resetHex.push_back(""); //fail
  resetDec.push_back(-1); //push to both vectors
}

void LogFileProcessor::processLogs(std::vector<std::string> logVector) {
  for (int i = 0; i < logVector.size(); i++) {
    if (findTrafficType(logVector.at(i)) != -1) { //if the traffic type succeeded and was not out traffic - process everything
      findMacAddress(logVector.at(i));
      findSourceIP(logVector.at(i));
      findDestinationIP(logVector.at(i));
      findLength(logVector.at(i));
      findTOS(logVector.at(i));
      findPrecedence(logVector.at(i));
      findTTL(logVector.at(i));
      findID(logVector.at(i));
      findProtocol(logVector.at(i));
      findSourcePort(logVector.at(i));
      findDestPort(logVector.at(i));
      findWindow(logVector.at(i));
      findReset(logVector.at(i));
    }
  }
}

void LogFileProcessor::print() { //print to terminal for testing
  std::cout << traffic.size() << "\n";
  for (int i = 0; i < traffic.size(); i++) {
    std::cout << "Traffic: " << traffic.at(i) << "\n";
    std::cout << "Mac Address: " << macAddress.at(i) << "\n";
    std::cout << "Source IP: " << srcIP.at(i) << "\n";
    std::cout << "Destination IP: " << destIP.at(i) << "\n";
    std::cout << "Length: " << length.at(i) << "\n";
    std::cout << "TOS (hex): " << tosHex.at(i) << "\n";
    std::cout << "TOS (dec): " << tosDec.at(i) << "\n";
    std::cout << "Precedence (hex): " << precHex.at(i) << "\n";
    std::cout << "Precedence (dec): " << precDec.at(i) << "\n";
    std::cout << "TTL: " << ttl.at(i) << "\n";
    std::cout << "ID: " << id.at(i) << "\n";
    std::cout << "Protocol: " << protocol.at(i) << "\n";
    std::cout << "Source Port: " << srcPort.at(i) << "\n";
    std::cout << "Destination Port: " << destPort.at(i) << "\n";
    std::cout << "Window: " << window.at(i) << "\n";
    std::cout << "Reset (hex): " << resetHex.at(i) << "\n";
    std::cout << "Reset (dec): " << resetDec.at(i) << "\n";
    std::cout << "\n\n";
  }
}

std::vector<std::string> LogFileProcessor::getSrcIP() { //for testing against tor routers
  return srcIP;
}

std::string LogFileProcessor::findCSVFileNumber() { //if logProcessed.csv exists && logProcessed1.csv exists && logProcessed2.csv exists, output logProcessed3.csv
  std::ifstream fileStream;
  std::string line;
  std::string fileValue;
  std::string filename = "logProcessed.csv";
  system("ls > fileList.txt");
  fileStream.open("fileList.txt"); //opens the filestream
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line + "\n"; //append filevalue
  }
  fileStream.close(); //close the filestream
  system("rm -f fileList.txt"); //remove the file
  if (fileValue.find(filename) == -1) {
    return filename;
  }
  for (int i = 1; i < 1000; i++) {
    filename = "logProcessed" + std::to_string(i) + ".csv";
    if (fileValue.find(filename) == -1) {
      return filename;
    }
  }
  return "";
}

void LogFileProcessor::outputCSV() { //write to a .csv file
  std::string line = "Traffic,MacAddress,SourceIP,DestinationIP,Length,TOS,Precedence,TTL,ID,Protocol,SourcePort,DestinationPort,Window,Reset\n"; //header line for which value is which
  for (int i = 0; i < traffic.size(); i++) {
    line += traffic.at(i); line += ","; //add the traffic then a comma (comma separated values file)
    line += macAddress.at(i); line += ","; //add mac address
    line += srcIP.at(i); line += ","; //add source ip
    line += destIP.at(i); line += ","; //add destination ip
    line += std::to_string(length.at(i)); line += ","; //add length
    line += std::to_string(tosDec.at(i)); line += ","; //add tos
    line += std::to_string(precDec.at(i)); line += ","; //add precedence
    line += std::to_string(ttl.at(i)); line += ","; //add time to live
    line += std::to_string(id.at(i)); line += ","; //add id then
    line += protocol.at(i); line += ","; //add protocol
    line += std::to_string(srcPort.at(i)); line += ","; //add source port
    line += std::to_string(destPort.at(i)); line += ","; //add destination port
    line += std::to_string(window.at(i)); line += ","; //add window
    line += std::to_string(resetDec.at(i)); //add reset value
    line += "\n"; //new line
  }
  std::ofstream filestream; //open filestream
  std::string filename = findCSVFileNumber(); //find file name
  std::string systemCommand = "touch " + filename; //create file
  system(systemCommand.c_str()); //execute command
  filestream.open(filename.c_str()); //open file
  filestream << line; //write to file
  filestream.close(); //close file
}

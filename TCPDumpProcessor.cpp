/*
 * TCPDumpProcessor.cpp
 * Created on December 12, 2016
 * Author: Noah Zbozny
 */

#include "TCPDumpProcessor.h"

TCPDumpProcessor::TCPDumpProcessor() {

}

int TCPDumpProcessor::hexToDec(std::string hexValue) {
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

int TCPDumpProcessor::tcpFindTimestamp(std::string tcpdumpString) { //returns the value of the start index for the next element
  std::string timestampString = "";
  int startIndex = (tcpdumpString[0] == '\n') ? 1 : 0; //if it's a new line there will be a space before the timestamp
  for (int i = startIndex; i < tcpdumpString.size(); i++) { //go through the whole string if necessary
    if (tcpdumpString[i] == ' ') { //timestamp starts off the string and goes until a space
      timestamp.push_back(timestampString); //add to the timestamp vector
      return i + 1; //return start index for the next element to find
    } else { //if the timestamp isn't finished yet
      timestampString += tcpdumpString[i]; //add the next value to the timestamp
    }
  }
  timestamp.push_back(""); //if the end of the file is reached without ending the timestamp
  return 0; //failed
}

int TCPDumpProcessor::tcpTrafficDirection(std::string tcpdumpString, int startIndex) { //in or out
  if (tcpdumpString.substr(startIndex, 3) == "Out") { //if out traffic
    trafficDirection.push_back(0); //0 = out
  } else if (tcpdumpString.substr(startIndex, 3) == " In") { //if in traffic
    trafficDirection.push_back(1); //1 = in
  } else { //if it can't find either
    trafficDirection.push_back(-1); //-1 = can't find
    return startIndex;
  }
  return startIndex + 4; //next start index
}

int TCPDumpProcessor::tcpFindMacAddress(std::string tcpdumpString, int startIndex) { //find mac address
  std::string macAddressString = ""; //temp
  if (tcpdumpString[startIndex + 2] != ':') { //if there isn't a mac address
  macAddress.push_back("");
    return startIndex; //dont change the start index
  }
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ' ') { //timestamp starts off the string and goes until a space
      macAddress.push_back(macAddressString); //add to the macAddress vector
      startIndex = i + 1; //new start index
      return startIndex; //return start index for the next element to find
    } else {
      macAddressString += tcpdumpString[i]; //add the next value to the timestamp
    }
  }
  macAddress.push_back("");
  return startIndex; //if it reaches the end without ending the mac address
}

int TCPDumpProcessor::tcpFindConnectionType(std::string tcpdumpString, int startIndex) { //connection type (ethertype, etc.)
  std::string connectionTypeString = "";
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ' ') { //ends the connection type string
      connectionType.push_back(connectionTypeString); //push back the result
      startIndex = i + 1; //next start index
      return startIndex; //return value of start index for the next function
    } else { //if not at the end
      connectionTypeString += tcpdumpString[i]; //add to the result
    }
  }
  connectionType.push_back(""); //if nothing found, add an empty string
  return startIndex; //start index for the next function
}

int TCPDumpProcessor::tcpFindConnectionProtocol(std::string tcpdumpString, int startIndex) { //ipv4 etc.
  std::string connectionProtocolString = "";
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ' ') { //ends connection protocol string
      connectionProtocol.push_back(connectionProtocolString); //add result to array
      startIndex = i + 11; //next start index
      return startIndex; //return
    } else {
      connectionProtocolString += tcpdumpString[i]; //add each char to the result
    }
  }
  connectionProtocol.push_back(""); //if nothing is found push back an empty string
  return startIndex;
}

void TCPDumpProcessor::tcpFindIPPacketLength(std::string tcpdumpString) { //packet length
  if (tcpdumpString.find("length") == -1) { //if not found
    ipPacketLength.push_back(-1); //not found
    return;
  }
  std::string lengthString = "";
  int startIndex = tcpdumpString.find("length") + 7; //6 char word + a space
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ':') { //ends the length
      ipPacketLength.push_back(atoi(lengthString.c_str())); //string to int
      return;
    } else {
      lengthString += tcpdumpString[i]; //add char by char to result
    }
  }
  ipPacketLength.push_back(-1); //if : never found
}

void TCPDumpProcessor::tcpFindTOS(std::string tcpdumpString) { //type of service
  if (tcpdumpString.find("tos") == -1) { //if not found
    tosHex.push_back("");
    ipTOS.push_back(-1);
    return;
  }
  std::string tosString = "";
  int startIndex = tcpdumpString.find("tos") + 4; //3 char word + a space
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ',') { // "," ends the string
      tosString = tosString.substr(2); //tos starts with 0x to indicate hex - skip those chars
      tosHex.push_back(tosString);
      ipTOS.push_back(hexToDec(tosString)); //hex to dec
      return;
    } else {
      tosString += tcpdumpString[i]; //add to result
    }
  }
  tosHex.push_back(""); //if "," never found
  ipTOS.push_back(-1);
}

void TCPDumpProcessor::tcpFindTTL(std::string tcpdumpString) { //time to live
  if (tcpdumpString.find("ttl") == -1) { //if not found
    ipTTL.push_back(-1);
    return;
  }
  std::string ttlString = "";
  int startIndex = tcpdumpString.find("ttl") + 4;
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ',') {
      ipTTL.push_back(atoi(ttlString.c_str()));
      return;
    } else {
      ttlString += tcpdumpString[i];
    }
  }
  ipTTL.push_back(-1);
}

void TCPDumpProcessor::tcpFindID(std::string tcpdumpString) { //packet id
  if (tcpdumpString.find("id") == -1) {
    ipID.push_back(-1);
    return;
  }
  std::string idString = "";
  int startIndex = tcpdumpString.find("id") + 3;
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ',') {
      ipID.push_back(atoi(idString.c_str()));
      return;
    } else {
      idString += tcpdumpString[i];
    }
  }
  ipID.push_back(-1);
}

void TCPDumpProcessor::tcpFindFragmentOffset(std::string tcpdumpString) { //packet fragment offset - used for when one packet is broken up into multiple
  if (tcpdumpString.find("offset") == -1) {
    ipFragmentOffset.push_back(-1);
    return;
  }
  std::string offsetString = "";
  int startIndex = tcpdumpString.find("offset") + 7;
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ',') {
      ipFragmentOffset.push_back(atoi(offsetString.c_str()));
      return;
    } else {
      offsetString += tcpdumpString[i];
    }
  }
  ipFragmentOffset.push_back(-1);
}

void TCPDumpProcessor::tcpFindIPFlags(std::string tcpdumpString) { //ip flags
  if (tcpdumpString.find("flags") == -1) {
    std::vector<std::string> lineFlags;
    lineFlags.push_back("");
    ipFlags.push_back(lineFlags);
    return;
  }
  std::vector<std::string> lineFlags;
  std::string flagString;
  int startIndex = tcpdumpString.find("flags") + 7;
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ']') {
      lineFlags.push_back(flagString);
      ipFlags.push_back(lineFlags);
      return;
    } else if (tcpdumpString[i] == ',') {
      lineFlags.push_back(flagString);
      flagString = "";
    } else {
      flagString += tcpdumpString[i];
    }
  }
  lineFlags.push_back("");
  ipFlags.push_back(lineFlags);
}

void TCPDumpProcessor::tcpFindSource(std::string tcpdumpString) { //find source ip and source port
  if (tcpdumpString.find(" > ") == -1) {
    srcIP.push_back("");
    srcPort.push_back(-1);
    return;
  }
  std::string srcIPString = "";
  std::string srcPortString = "";
  int startIndex = tcpdumpString.find(" > ") - 1;
  for (int i = startIndex; i > -1; i--) {
    if (tcpdumpString[i] == '.') {
      startIndex = i - 1;
      srcPort.push_back(atoi(srcPortString.c_str()));
      break;
    } else {
      srcPortString = tcpdumpString[i] + srcPortString;
    }
    if (i == 0) {
      srcPort.push_back(-1);
    }
  }
  for (int i = startIndex; i > -1; i--) {
    if (tcpdumpString[i] == ' ') {
      srcIP.push_back(srcIPString);
      return;
    } else {
      srcIPString = tcpdumpString[i] + srcIPString;
    }
  }
  srcIP.push_back("");
}

void TCPDumpProcessor::tcpFindDestination(std::string tcpdumpString) { //find destination ip and destination port
  if (tcpdumpString.find(" > ") == -1) {
    destIP.push_back("");
    destPort.push_back(-1);
    return;
  }
  std::string destIPString = "";
  std::string destPortString = "";
  int startIndex = tcpdumpString.find(" > ") + 3;
  int dotCounter = 0;
  for (int i = startIndex; i < tcpdumpString.length(); i++) {
    if (dotCounter == 4) {
      startIndex = i;
      destIP.push_back(destIPString);
      break;
    }
    if (tcpdumpString[i] == '.') {
      if (dotCounter < 3) {
        destIPString += tcpdumpString[i];
      }
      dotCounter++;
    } else {
      destIPString += tcpdumpString[i];
    }
    if (i == tcpdumpString.length() - 1) {
      destIP.push_back("");
    }
  }

  for (int i = startIndex; i < tcpdumpString.length(); i++) {
    if (tcpdumpString[i] == ':') {
      destPort.push_back(atoi(destPortString.c_str()));
      return;
    } else {
      destPortString += tcpdumpString[i];
    }
  }
  destPort.push_back(-1);
}

void TCPDumpProcessor::tcpFindTCPFlags(std::string tcpdumpString) { //tcp flags
  if (tcpdumpString.find("ack") == -1) {
    std::vector<int> tempFlag;
    tempFlag.push_back(-1);
    tcpFlags.push_back(tempFlag);
    return;
  }
  std::vector<int> tempFlag;
  int startIndex = tcpdumpString.find("Flags") + 7;
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
      if (tcpdumpString[i] == ']') {
        tcpFlags.push_back(tempFlag);
        return;
      } else {
        tempFlag.push_back(tcpdumpString[i]);
      }
  }
  tempFlag.push_back(-1);
  tcpFlags.push_back(tempFlag);
}

bool TCPDumpProcessor::tcpFindChecksum(std::string tcpdumpString) { //checksum for the packet - if the whole packet was received
  if (tcpdumpString.find("(correct),", tcpdumpString.find("cksum")) != -1) { //if the checksum is read as correct
    return true;
  } else {
    return false; //if the checksum is read as incorrect or if it can't find the checksum value at all
  }
}

void TCPDumpProcessor::tcpFindAck(std::string tcpdumpString) { //acknowledgement #
  if (tcpdumpString.find("ack") == -1) {
    ack.push_back(-1);
    return;
  }
  int startIndex = tcpdumpString.find("ack") + 4;
  std::string ackString = "";
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ',') {
      ack.push_back(atoi(ackString.c_str()));
      return;
    } else {
      ackString += tcpdumpString[i];
    }
  }
  ack.push_back(-1);
}

void TCPDumpProcessor::tcpFindWin(std::string tcpdumpString) { //tcp window size
  if (tcpdumpString.find("win") == -1) {
    win.push_back(-1);
    return;
  }
  int startIndex = tcpdumpString.find("win") + 4;
  std::string winString = "";
  for (int i = startIndex; i < tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ',') {
      win.push_back(atoi(winString.c_str()));
      return;
    } else {
      winString += tcpdumpString[i];
    }
  }
  win.push_back(-1);
}

void TCPDumpProcessor::tcpFindOptions(std::string tcpdumpString) { //tcp options
  if (tcpdumpString.find("options") == -1) {
    std::vector<std::string> lineOptions;
    lineOptions.push_back("");
    options.push_back(lineOptions);
    return;
  }
  int startIndex = tcpdumpString.find("options") + 9;
  std::string tempOption = "";
  std::vector<std::string> lineOptions;
  for (int i = startIndex; i <tcpdumpString.size(); i++) {
    if (tcpdumpString[i] == ']') {
      lineOptions.push_back(tempOption);
      options.push_back(lineOptions);
      return;
    } else if (tcpdumpString[i] == ',') {
      lineOptions.push_back(tempOption);
      tempOption = "";
    } else if ((tcpdumpString[i] == ' ' && tempOption.find("TS val ") != -1) ||
               (tcpdumpString[i] == ' ' && tempOption.find("ecr ") != -1)) {
                 lineOptions.push_back(tempOption);
                 tempOption = "";
    } else {
      tempOption += tcpdumpString[i];
    }
  }
}

void TCPDumpProcessor::tcpFindTCPPacketLength(std::string tcpdumpString) { //tcp packet length
  int startIndex = tcpdumpString.length() - 1;
  std::string tcpPacketLengthString = "";
  for (int i = startIndex; i > -1; i--) {
    if (tcpdumpString[i] == ' ') {
      tcpPacketLength.push_back(atoi(tcpPacketLengthString.c_str()));
      return;
    } else {
      tcpPacketLengthString = tcpdumpString[i] + tcpPacketLengthString;
    }
  }
  tcpPacketLength.push_back(-1);
}

void TCPDumpProcessor::printTCP() { //print to terminal for testing
  for (int i = 0; i < timestamp.size(); i++) {
    std::cout << "Timestamp: " << timestamp[i] << "\n";
    std::cout << "Traffic Direction: " << trafficDirection[i] << "\n";
    std::cout << "Mac Address: " << macAddress[i] << "\n";
    std::cout << "Connection Type: " << connectionType[i] << "\n";
    std::cout << "Connection Protocol: " << connectionProtocol[i] << "\n";
    std::cout << "IP Packet Length: " << ipPacketLength[i] << "\n";
    std::cout << "TOS (hex): " << tosHex[i] << "\n";
    std::cout << "TOS (dec): " << ipTOS[i] << "\n";
    std::cout << "TTL: " << ipTTL[i] << "\n";
    std::cout << "ID: " << ipID[i] << "\n";
    std::cout << "Fragment Offset: " << ipFragmentOffset[i] << "\n";
    for (int j = 0; j < ipFlags[i].size(); j++) {
      std::cout << "IP Flags: " << ipFlags[i][j] << "\t";
    }
    std::cout << "\n";
    std::cout << "Source IP: " << srcIP[i] << "\n";
    std::cout << "Source Port: " << srcPort[i] << "\n";
    std::cout << "Destination IP: " << destIP[i] << "\n";
    std::cout << "Destination Port: " << destPort[i] << "\n";
    std::cout << "TCPFlags: ";
    for (int j = 0; j < tcpFlags[i].size(); j++) {
      std::cout << (char)tcpFlags[i][j] << " ";
    }
    std::cout << "\n";
    std::cout << "ack: " << ack[i] << "\n";
    std::cout << "win: " << win[i] << "\n";
    std::cout << "\t";
    for (int j = 0; j < options[i].size(); j++) {
      std::cout << options[i][j] << "\n\t";
    }
    std::cout << "\b\b\b\b\b\b\b\b";
    std::cout << "TCP Packet Length: " << tcpPacketLength[i] << "\n";
    std::cout << "\n";
  }
}

std::vector<std::string> TCPDumpProcessor::fixTCPDumpData(std::vector<std::string> startData) { //TODO: confirm that this works with all kinds of TCPDump data through more testing
  //start data is the vector of tcpdumpdata with some lines taking up multiple elements of the array
  /*
    In the data collection subsystem, when the tcpdump data is collected, the way tcpdump writes
    the data, it sometimes puts a packet on two lines (with the second line started with several
    spaces) for readability. Obviously this isn't readable for a computer, so I have to process
    it properly
  */
  std::vector<std::string> resultantData;
  for (int i = 0; i < startData.size() - 1; i++) {
    if (startData.at(i + 1)[1] == ' ') {
      resultantData.push_back(startData.at(i) + startData.at(i + 1));
      i++;
    } else {
      resultantData.push_back(startData[i] + startData[i + 1]);
    }
  }
  if (startData.at(startData.size() - 1)[1] != ' ') {
    resultantData.push_back(startData.at(startData.size() - 1));
  }
  return resultantData;
}

void TCPDumpProcessor::processTCPDump(std::vector<std::string> tcpdumpData) { //process everything into the vectors
  std::vector<std::string> tcpdumpDataArray = fixTCPDumpData(tcpdumpData);
  int startIndex = 0;

  for (int i = 0; i < tcpdumpDataArray.size(); i++) {
    if (tcpdumpDataArray[i].find("Request who-has") == -1 || (tcpdumpDataArray[i].find("Reply") == -1 && tcpdumpDataArray[i].find("is-at") == -1)) {
      if (tcpFindChecksum(tcpdumpDataArray[i]) == true) {
        startIndex = tcpFindTimestamp(tcpdumpDataArray[i]);
        startIndex = tcpTrafficDirection(tcpdumpDataArray[i], startIndex);
        startIndex = tcpFindMacAddress(tcpdumpDataArray[i], startIndex);
        startIndex = tcpFindConnectionType(tcpdumpDataArray[i], startIndex);
        startIndex = tcpFindConnectionProtocol(tcpdumpDataArray[i], startIndex);
        tcpFindIPPacketLength(tcpdumpDataArray[i]);
        tcpFindTOS(tcpdumpDataArray[i]);
        tcpFindTTL(tcpdumpDataArray[i]);
        tcpFindID(tcpdumpDataArray[i]);
        tcpFindFragmentOffset(tcpdumpDataArray[i]);
        tcpFindIPFlags(tcpdumpDataArray[i]);
        tcpFindSource(tcpdumpDataArray[i]);
        tcpFindDestination(tcpdumpDataArray[i]);
        tcpFindTCPFlags(tcpdumpDataArray[i]);
        tcpFindAck(tcpdumpDataArray[i]);
        tcpFindWin(tcpdumpDataArray[i]);
        tcpFindOptions(tcpdumpDataArray[i]);
        tcpFindTCPPacketLength(tcpdumpDataArray[i]);
      }
    }
  }
  //TODO: make a linker variable called start index (since they all return start index) and if it ever equals -1 exit the function
}

std::string TCPDumpProcessor::findCSVFileNumber() { //if tcpdumpProcessed.csv and tcpdumpProcessed1.csv exist, output tcpdumpProcessed2.csv
  std::ifstream fileStream;
  std::string line;
  std::string fileValue;
  std::string filename = "tcpdumpProcessed.csv";
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
    filename = "tcpdumpProcessed" + std::to_string(i) + ".csv";
    if (fileValue.find(filename) == -1) {
      return filename;
    }
  }
  return "";
}

void TCPDumpProcessor::outputCSV() { //output to a .csv file
  std::string line = "Timestamp,TrafficDirection,MacAddress,ConnectionType,ConnectionProtocol,IPPacketLength,TOS,TTL,ID,FragmentOffset,IPFlags,SourceIP,SourcePort,DestinationIP,DestinationPort,TCPFlags,Ack,Win,Options,TCPPacketLength\n"; //header line for readability of the .csv file
  for (int i = 0; i < timestamp.size(); i++) {
    line += timestamp[i]; line += ","; //add timestamp, then a comma (comma separated values file)
    line += std::to_string(trafficDirection[i]); line += ","; //add traffic direction
    line += macAddress[i]; line += ","; //add mac address
    line += connectionType[i]; line += ","; //add connection type
    line += connectionProtocol[i]; line += ","; //add connection protocol
    line += std::to_string(ipPacketLength[i]); line += ","; //add ip packet length
    line += std::to_string(ipTOS[i]); line += ","; //add ip type of service
    line += std::to_string(ipTTL[i]); line += ","; //add ip time to live
    line += std::to_string(ipID[i]); line += ","; //add ip id
    line += std::to_string(ipFragmentOffset[i]); line += ","; //add ip fragment offset
    line += "["; //formatting flags
    for (int j = 0; j < ipFlags[i].size(); j++) {
      line += ipFlags[i][j]; //add flag
      line +=  "  ||  "; //for separating flags within cell
    }
    line += "],"; //end formatting flags
    line += srcIP[i]; line += ","; //add source ip
    line += std::to_string(srcPort[i]); line += ","; //add source port
    line += destIP[i]; line += ","; //add destination ip
    line += std::to_string(destPort[i]); line += ","; //add destination port
    line += "["; //add formatting for flags
    for (int j = 0; j < tcpFlags[i].size(); j++) { //output flags
      line += std::to_string(tcpFlags[i][j]); //output flags
      line += "  ||  "; //separating flags within cell
    }
    line += "],"; //end formatting flags
    line += std::to_string(ack[i]); line += ","; //add acknowledgements
    line += std::to_string(win[i]); line += ","; //windows
    line += "["; //start formatting for options
    for (int j = 0; j < options[i].size(); j++) { //add every option
      line += options[i][j]; //add options`
      line += " || "; //separating options within cell
    }
    line += "],"; //end formatting for options
    line += std::to_string(tcpPacketLength[i]); //add tcp packet length
    line += "\n"; //new line = new row in excel
  }
  std::ofstream filestream; //create filestream
  std::string filename = findCSVFileNumber(); //determine filename
  std::string systemCommand = "touch " + filename; //make file
  system(systemCommand.c_str()); //execute command
  filestream.open(filename.c_str()); //open filestream
  filestream << line; //write to filestream
  filestream.close(); //close filestream
}

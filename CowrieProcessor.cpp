/*
 * CowrieProcessor.cpp
 * Created on December 12, 2016
 * Author: Noah Zbozny
 */

#include "CowrieProcessor.h"

CowrieProcessor::CowrieProcessor() {}

int CowrieProcessor::hexToDec(std::string hexValue) {
  int result = 0; //final answer
  int decValue = 0; //temp variable for holding the conversion for that number
  int endIndex = hexValue.find("0x");
  if (endIndex != -1) {
    endIndex += 2;
  }
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

void CowrieProcessor::findEventID(std::string cowrieString) { //find the event - session opened, session closed, input command, etc.
  std::string result = "";
  int startIndex = cowrieString.find("eventid"); //eventid is the string that starts off the event id value
  if (startIndex != -1) { //if the start index is found
    startIndex += 11; //based on the cowrie.json log format, 11 chars after the 'e' in "eventid" is when the actual eventid starts
    for (int i = startIndex; i < cowrieString.length(); i++) { //go to the whole string if necessary
      if (cowrieString[i] == 34) { //quotation mark is what ends the event id string
        eventID.push_back(result); //add to the vector
        return; //exit
      } else { //if the result string hasnt been ended yet
        result += cowrieString[i]; //add char by char
      }
    }
  }
  eventID.push_back(" "); //fail
}

void CowrieProcessor::findSourceIP(std::string cowrieString) { //source ip
  std::string result = "";
  int startIndex = cowrieString.find("src_ip");
  if (startIndex != -1) {
    startIndex += 10;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        srcIP.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  srcIP.push_back(" "); //fail
}

void CowrieProcessor::findSourcePort(std::string cowrieString) { //source port
  std::string result = "";
  int startIndex = cowrieString.find("src_port");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ',') {
        srcPort.push_back(atoi(result.c_str()));
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
 srcPort.push_back(-1); //fail
}

void CowrieProcessor::findDestinationPort(std::string cowrieString) { //destination port
  std::string result = "";
  int startIndex = cowrieString.find("dst_port");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ',') {
        destPort.push_back(atoi(result.c_str()));
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  destPort.push_back(-1);
}

void CowrieProcessor::findDestinationIP(std::string cowrieString) { //destination ip - mine
  std::string result = "";
  int startIndex = cowrieString.find("dst_ip");
  if (startIndex != -1) {
    startIndex += 10;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        destIP.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  destIP.push_back(" ");
}

void CowrieProcessor::findMessage(std::string cowrieString) { //message stating the connection was lost or dropped or a command was entered, etc.
  std::string result = "";
  int startIndex = cowrieString.find("message");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        message.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  message.push_back(" ");
}

void CowrieProcessor::findDuration(std::string cowrieString) { //duration of the session - this only appears when the session is closed so the other rows are infilled in excel later
  std::string result = "";
  int startIndex = cowrieString.find("duration");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ',') {
        duration.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  duration.push_back(" ");
}

void CowrieProcessor::findMacCS(std::string cowrieString) { //mac cs
  std::string result = "";
  int startIndex = cowrieString.find("macCS");
  if (startIndex != -1) {
    startIndex += 10;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        macCS.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        result += cowrieString[i];
      }
    }
  }
  macCS.push_back(" ");
}

void CowrieProcessor::findVersion(std::string cowrieString) { //if it can determine their os version
  std::string result = "";
  int startIndex = cowrieString.find("version");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        version.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  version.push_back(" ");
}

void CowrieProcessor::findKexAlgs(std::string cowrieString) { //kex algorithms
  std::string result = "";
  int startIndex = cowrieString.find("kexAlgs");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        kexAlgs.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        result += cowrieString[i];
      }
    }
  }
  kexAlgs.push_back(" ");
}

void CowrieProcessor::findCompCS(std::string cowrieString) { //comp cs
  std::string result = "";
  int startIndex = cowrieString.find("compCS");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        compCS.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else if (cowrieString[i] != 34) {
        result += cowrieString[i];
      }
    }
  }
  compCS.push_back(" ");
}

void CowrieProcessor::findKeyAlgs(std::string cowrieString) { //key algorithms (encryption)
  std::string result = "";
  int startIndex = cowrieString.find("keyAlgs");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        keyAlgs.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        result += cowrieString[i];
      }
    }
  }
  keyAlgs.push_back(" ");
}

void CowrieProcessor::findEncCS(std::string cowrieString) { //encryption cs
  std::string result = "";
  int startIndex = cowrieString.find("encCS");
  if (startIndex != -1) {
    startIndex += 10;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        encCS.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        result += cowrieString[i];
      }
    }
  }
  encCS.push_back(" ");
}

void CowrieProcessor::findUsername(std::string cowrieString) { //username attempted
  std::string result = "";
  int startIndex = cowrieString.find("username");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        username.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  username.push_back(" ");
}

void CowrieProcessor::findPassword(std::string cowrieString) { //password attempted
  std::string result = "";
  int startIndex = cowrieString.find("password");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        password.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  password.push_back(" ");
}

void CowrieProcessor::findInput(std::string cowrieString) { //commands input
  std::string result = "";
  int startIndex = cowrieString.find("input");
  if (startIndex != -1) {
    startIndex += 8;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        input.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  input.push_back(" ");
}

void CowrieProcessor::findSession(std::string cowrieString) { //unique session id
  std::string result = "";
  int startIndex = cowrieString.find("\"session\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        session.push_back(hexToDec(result));
        sessionHex.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  session.push_back(-1);
  sessionHex.push_back(" ");
}

void CowrieProcessor::findTimestamp(std::string cowrieString) { //timestamp
  std::string result = "";
  int startIndex = cowrieString.find("\"timestamp\":");
  if (startIndex != -1) {
    startIndex += 14;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34 || cowrieString[i] == 'Z') {
        timestamp.push_back(result);
        return;
      } else {
        result += cowrieString[i];
      }
    }
  }
  timestamp.push_back(" ");
}

void CowrieProcessor::process(std::vector<std::string> cowrieData) {
  for (int i = 0; i < cowrieData.size(); i++) { //process everything
    findEventID(cowrieData[i]);
    findSourceIP(cowrieData[i]);
    findSourcePort(cowrieData[i]);
    findDestinationPort(cowrieData[i]);
    findDestinationIP(cowrieData[i]);
    findMessage(cowrieData[i]);
    findDuration(cowrieData[i]);
    findMacCS(cowrieData[i]);
    findVersion(cowrieData[i]);
    findKexAlgs(cowrieData[i]);
    findCompCS(cowrieData[i]);
    findKeyAlgs(cowrieData[i]);
    findEncCS(cowrieData[i]);
    findUsername(cowrieData[i]);
    findPassword(cowrieData[i]);
    findInput(cowrieData[i]);
    findSession(cowrieData[i]);
    findTimestamp(cowrieData[i]);
  }
}

void CowrieProcessor::print() { //print for testing
  for (int i = 0; i < eventID.size(); i++) {
    std::cout << "Event ID: " << eventID[i] << "\n";
    std::cout << "Source IP: " << srcIP[i] << "\n";
    std::cout << "Source Port: " << srcPort[i] << "\n";
    std::cout << "Destination IP: " << destIP[i] << "\n";
    std::cout << "Destination Port: " << destPort[i] << "\n";
    std::cout << "Message: " << message[i] << "\n";
    std::cout << "Duration: " << duration[i] << "\n";
    std::cout << "Mac CS: " << macCS[i] << "\n";
    std::cout << "Version: " << version[i] << "\n";
    std::cout << "Kex Algs: " << kexAlgs[i] << "\n";
    std::cout << "Comp CS: " << compCS[i] << "\n";
    std::cout << "Key Algs: " << keyAlgs[i] << "\n";
    std::cout << "Enc CS: " << encCS[i] << "\n";
    std::cout << "Username: " << username[i] << "\n";
    std::cout << "Password: " << password[i] << "\n";
    std::cout << "Input: " << input[i] << "\n";
    std::cout << "Session: " << session[i] << "\n";
    std::cout << "Session Hex: " << sessionHex[i] << "\n";
    std::cout << "HTD Test: " << hexToDec("3dc3174c") << "\n";
    std::cout << "Timestamp: " << timestamp[i] << "\n";
    std::cout << "Iteration: " << i << "\n\n";
  }
}

std::string CowrieProcessor::findCSVFileNumber() { //if cowrieProcessed.csv and cowrieProcessed1.csv already exist, output cowrieProcessed2.csv
  std::ifstream fileStream;
  std::string line;
  std::string fileValue;
  std::string filename = "cowrieProcessed.csv";
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
    filename = "cowrieProcessed" + std::to_string(i) + ".csv";
    if (fileValue.find(filename) == -1) {
      return filename;
    }
  }
  return "";
}

void CowrieProcessor::outputCSV() { //add to a .csv file
  std::string line = "EventID,SourceIP,SourcePort,DestinationIP,DestinationPort,Message,Duration,MacCS,Version,KexAlgs,CompCS,keyAlgs,EncCS,Username,Password,Input,Session,Timestamp\n"; //header line for when looking at the .csv file
  for (int i = 0; i < eventID.size(); i++) {
    if (eventID[i] != "cowrie.direct-tcpip.request" && eventID[i] != "cowrie.direct-tcpip.data") { //these come from other servers on the network so they're not used for this
      line += eventID[i]; line += ","; //add line then a comma (comma separated values file)
      line += srcIP[i]; line += ","; //add source ip
      line += std::to_string(srcPort[i]); line += ","; //add source port
      line += destIP[i]; line += ","; //add destination ip
      line += std::to_string(destPort[i]); line += ","; //add destinato port
      line += message[i]; line += ","; //add message
      line += duration[i]; line += ","; //add duration
      line += macCS[i]; line += ","; //add mac cs
      line += version[i]; line += ","; //add version
      line += kexAlgs[i]; line += ","; //add kex algorithms
      line += compCS[i]; line += ","; //add comp cs
      line += keyAlgs[i]; line += ","; //add key algorithms
      line += encCS[i]; line += ","; //add encryption cs
      line += username[i]; line += ","; //add username
      line += password[i]; line += ","; //add password
      line += input[i]; line += ","; //add input
      line += sessionHex[i]; line += ","; //was to_string(session[i])
      line += timestamp[i]; //add timestamp
      line += "\n"; //new line = new row in the excel file
    }
  }
  std::ofstream filestream; //create filestream
  std::string filename = findCSVFileNumber(); //find filename
  std::string systemCommand = "touch " + filename; //make file
  system(systemCommand.c_str()); //execute command
  filestream.open(filename.c_str()); //open filestream
  filestream << line; //write to file
  filestream.close(); //close filestream
}

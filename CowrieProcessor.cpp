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
  int startIndex = cowrieString.find("\"eventid\":"); //eventid is the string that starts off the event id value
  if (startIndex != -1) { //if the start index is found
    startIndex += 12; //based on the cowrie.json log format, 11 chars after the 'e' in "eventid" is when the actual eventid starts
    for (int i = startIndex; i < cowrieString.length(); i++) { //go to the whole string if necessary
      if (cowrieString[i] == 34) { //quotation mark is what ends the event id string
        eventID.push_back(result); //add to the vector
        return; //exit
      } else { //if the result string hasnt been ended yet
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  eventID.push_back("MISSING"); //fail
}

void CowrieProcessor::findSourceIP(std::string cowrieString) { //source ip
  std::string result = "";
  int startIndex = cowrieString.find("\"src_ip\":");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        srcIP.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  srcIP.push_back("MISSING"); //fail
}

void CowrieProcessor::findSourcePort(std::string cowrieString) { //source port
  std::string result = "";
  int startIndex = cowrieString.find("\"src_port\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ',') {
        srcPort.push_back(atoi(result.c_str()));
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
 srcPort.push_back(-1); //fail
}

void CowrieProcessor::findDestinationPort(std::string cowrieString) { //destination port
  std::string result = "";
  int startIndex = cowrieString.find("\"dst_port\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ',') {
        destPort.push_back(atoi(result.c_str()));
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        };
      }
    }
  }
  destPort.push_back(-1);
}

void CowrieProcessor::findDestinationIP(std::string cowrieString) { //destination ip - mine
  std::string result = "";
  int startIndex = cowrieString.find("\"dst_ip\":");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        destIP.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  destIP.push_back("MISSING");
}

void CowrieProcessor::findMessage(std::string cowrieString) { //message stating the connection was lost or dropped or a command was entered, etc.
  std::string result = "";
  int startIndex = cowrieString.find("\"message\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        message.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  message.push_back("MISSING");
}

void CowrieProcessor::findDuration(std::string cowrieString) { //duration of the session - this only appears when the session is closed so the other rows are infilled in excel later
  std::string result = "";
  int startIndex = cowrieString.find("\"duration\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ',') {
        duration.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  duration.push_back("-1");
}

void CowrieProcessor::findMacCS(std::string cowrieString) { //mac cs
  std::string result = "";
  int startIndex = cowrieString.find("\"macCS\":");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        macCS.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  macCS.push_back("MISSING");
}

void CowrieProcessor::findVersion(std::string cowrieString) { //if it can determine their os version
  std::string result = "";
  int startIndex = cowrieString.find("\"version\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        version.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  version.push_back("MISSING");
}

void CowrieProcessor::findKexAlgs(std::string cowrieString) { //kex algorithms
  std::string result = "";
  int startIndex = cowrieString.find("\"kexAlgs\":");
  if (startIndex != -1) {
    startIndex += 13;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        kexAlgs.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  kexAlgs.push_back("MISSING");
}

void CowrieProcessor::findCompCS(std::string cowrieString) { //comp cs
  std::string result = "";
  int startIndex = cowrieString.find("\"compCS\":");
  if (startIndex != -1) {
    startIndex += 12;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        compCS.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else if (cowrieString[i] != 34) {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  compCS.push_back("MISSING");
}

void CowrieProcessor::findKeyAlgs(std::string cowrieString) { //key algorithms (encryption)
  std::string result = "";
  int startIndex = cowrieString.find("\"keyAlgs\":");
  if (startIndex != -1) {
    startIndex += 13;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        keyAlgs.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  keyAlgs.push_back("MISSING");
}

void CowrieProcessor::findEncCS(std::string cowrieString) { //encryption cs
  std::string result = "";
  int startIndex = cowrieString.find("\"encCS\"");
  if (startIndex != -1) {
    startIndex += 11;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == ']') {
        encCS.push_back(result);
        return;
      } else if (cowrieString[i] == ',') {
        result += "  ||  ";
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  encCS.push_back("MISSING");
}

void CowrieProcessor::findUsername(std::string cowrieString) { //username attempted
  std::string result = "";
  int startIndex = cowrieString.find("\"username\":");
  if (startIndex != -1) {
    startIndex += 13;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        username.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  username.push_back("MISSING");
}

void CowrieProcessor::findPassword(std::string cowrieString) { //password attempted
  std::string result = "";
  int startIndex = cowrieString.find("\"password\":");
  if (startIndex != -1) {
    startIndex += 13;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        password.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  password.push_back("MISSING");
}

void CowrieProcessor::findInput(std::string cowrieString) { //commands input
  std::string result = "";
  int startIndex = cowrieString.find("\"input\":");
  if (startIndex != -1) {
    startIndex += 10;
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34) {
        input.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  input.push_back("MISSING");
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
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
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
    date.push_back(cowrieString.substr(startIndex, 10)); //format for the date is always 9 chars (yyy-mm-dd)
    startIndex += 11; //9 for the date and 1 for the 'T' that separates the date and time
    for (int i = startIndex; i < cowrieString.length(); i++) {
      if (cowrieString[i] == 34 || cowrieString[i] == 'Z') {
        timestamp.push_back(result);
        return;
      } else {
        if (cowrieString[i] == ',' || cowrieString[i] == ';') { //for when it prints to a csv - these are the separators
          result += "||"; //this separates them without putting them in different columns in the csv
        } else {
          result += cowrieString[i]; //else add char by char
        }
      }
    }
  }
  timestamp.push_back("MISSING");
}

void CowrieProcessor::process(std::vector<std::string> cowrieData) {
  for (int i = 0; i < cowrieData.size(); i++) { //process everything
    findEventID(cowrieData.at(i));
    findSourceIP(cowrieData.at(i));
    findSourcePort(cowrieData.at(i));
    findDestinationPort(cowrieData.at(i));
    findDestinationIP(cowrieData.at(i));
    findMessage(cowrieData.at(i));
    findDuration(cowrieData.at(i));
    findMacCS(cowrieData.at(i));
    findVersion(cowrieData.at(i));
    findKexAlgs(cowrieData.at(i));
    findCompCS(cowrieData.at(i));
    findKeyAlgs(cowrieData.at(i));
    findEncCS(cowrieData.at(i));
    findUsername(cowrieData.at(i));
    findPassword(cowrieData.at(i));
    findInput(cowrieData.at(i));
    findSession(cowrieData.at(i));
    findTimestamp(cowrieData.at(i));
  }
}

void CowrieProcessor::print() { //print for testing
  for (int i = 0; i < eventID.size(); i++) {
    std::cout << "Event ID: " << eventID.at(i) << "\n";
    std::cout << "Source IP: " << srcIP.at(i) << "\n";
    std::cout << "Source Port: " << srcPort.at(i) << "\n";
    std::cout << "Destination IP: " << destIP.at(i) << "\n";
    std::cout << "Destination Port: " << destPort.at(i) << "\n";
    std::cout << "Message: " << message.at(i) << "\n";
    std::cout << "Duration: " << duration.at(i) << "\n";
    std::cout << "Mac CS: " << macCS.at(i) << "\n";
    std::cout << "Version: " << version.at(i) << "\n";
    std::cout << "Kex Algs: " << kexAlgs.at(i) << "\n";
    std::cout << "Comp CS: " << compCS.at(i) << "\n";
    std::cout << "Key Algs: " << keyAlgs.at(i) << "\n";
    std::cout << "Enc CS: " << encCS.at(i) << "\n";
    std::cout << "Username: " << username.at(i) << "\n";
    std::cout << "Password: " << password.at(i) << "\n";
    std::cout << "Input: " << input.at(i) << "\n";
    std::cout << "Session: " << session.at(i) << "\n";
    std::cout << "Session Hex: " << sessionHex.at(i) << "\n";
    std::cout << "HTD Test: " << hexToDec("3dc3174c") << "\n";
    std::cout << "Timestamp: " << timestamp.at(i) << "\n";
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

bool CowrieProcessor::outputCSV() { //add to a .csv file
  std::string line = "EventID,SourceIP,SourcePort,DestinationIP,DestinationPort,Message,Duration,MacCS,Version,KexAlgs,CompCS,keyAlgs,EncCS,Username,Password,Input,Session,Date,Timestamp\n"; //header line for when looking at the .csv file
  for (int i = 0; i < eventID.size(); i++) {
    if (eventID.at(i) != "cowrie.direct-tcpip.request" && eventID.at(i) != "cowrie.direct-tcpip.data" && eventID.at(i) != "cowrie.client.size" && eventID.at(i) != "cowrie.client.version" && eventID.at(i).length() > 2) { //these come from other servers on the network so they're not used for this
      line += eventID.at(i); line += ","; //add line then a comma (comma separated values file)
      line += srcIP.at(i); line += ","; //add source ip
      line += std::to_string(srcPort.at(i)); line += ","; //add source port
      line += destIP.at(i); line += ","; //add destination ip
      line += std::to_string(destPort.at(i)); line += ","; //add destinato port
      line += message.at(i); line += ","; //add message
      line += duration.at(i); line += ","; //add duration
      line += macCS.at(i); line += ","; //add mac cs
      line += version.at(i); line += ","; //add version
      line += kexAlgs.at(i); line += ","; //add kex algorithms
      line += compCS.at(i); line += ","; //add comp cs
      line += keyAlgs.at(i); line += ","; //add key algorithms
      line += encCS.at(i); line += ","; //add encryption cs
      line += username.at(i); line += ","; //add username
      line += password.at(i); line += ","; //add password
      line += input.at(i); line += ","; //add input
      line += sessionHex.at(i); line += ","; //was to_string(session.at(i))
      line += date.at(i); line += ","; //add date
      line += timestamp.at(i); //add timestamp
      line += "\n"; //new line = new row in the excel file
    }
  }
  if (line == "EventID,SourceIP,SourcePort,DestinationIP,DestinationPort,Message,Duration,MacCS,Version,KexAlgs,CompCS,keyAlgs,EncCS,Username,Password,Input,Session,Date,Timestamp\n") { //if nothing has been added to the line and no proper datapoints were found (not tcpip requests etc.)
    return false; //exit the loop - don't write to a file
  }
  std::ofstream filestream; //create filestream
  std::string filename = findCSVFileNumber(); //find filename
  std::string systemCommand = "touch " + filename; //make file
  system(systemCommand.c_str()); //execute command
  filestream.open(filename.c_str()); //open filestream
  filestream << line; //write to file
  filestream.close(); //close filestream
  return true;
}

void CowrieProcessor::emptyData() { //clear the data in the preprocessing code
  std::vector<std::string> eventIDTemp;
  std::vector<std::string> srcIPTemp;
  std::vector<int> srcPortTemp;
  std::vector<int> destPortTemp;
  std::vector<std::string> destIPTemp;
  std::vector<std::string> messageTemp;
  std::vector<std::string> durationTemp;
  std::vector<std::string> macCSTemp;
  std::vector<std::string> versionTemp;
  std::vector<std::string> kexAlgsTemp;
  std::vector<std::string> compCSTemp;
  std::vector<std::string> keyAlgsTemp;
  std::vector<std::string> encCSTemp;
  std::vector<std::string> usernameTemp;
  std::vector<std::string> passwordTemp;
  std::vector<std::string> inputTemp;
  std::vector<int> sessionTemp;
  std::vector<std::string> sessionHexTemp;
  std::vector<std::string> timestampTemp;
  std::vector<std::string> dateTemp;

  eventIDTemp.swap(eventID);
  srcIPTemp.swap(srcIP);
  srcPortTemp.swap(srcPort);
  destPortTemp.swap(destPort);
  destIPTemp.swap(destIP);
  messageTemp.swap(message);
  durationTemp.swap(duration);
  macCSTemp.swap(macCS);
  versionTemp.swap(version);
  kexAlgsTemp.swap(kexAlgs);
  compCSTemp.swap(compCS);
  keyAlgsTemp.swap(keyAlgs);
  encCSTemp.swap(encCS);
  usernameTemp.swap(username);
  passwordTemp.swap(password);
  inputTemp.swap(input);
  sessionTemp.swap(session);
  sessionHexTemp.swap(sessionHex);
  timestampTemp.swap(timestamp);
  dateTemp.swap(date);
}

std::vector<std::string> CowrieProcessor::getUsernames() {
  return username;
}

std::vector<std::string> CowrieProcessor::getPasswords() {
  return password;
}

std::vector<std::string> CowrieProcessor::getInputs() {
  return input;
}

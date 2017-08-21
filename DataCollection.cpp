/*
 * DataCollection.cpp
 * Created on October 24, 2016
 * Author: Noah Zbozny
 */

//IMPORTANT NOTE: MUST RUN FILES WITH SUDO FOR SOME OF THE TERMINAL COMMANDS TO WORK PROPERLY

#include "DataCollection.h"

DataCollection::DataCollection() {
  nmapData; //initializes the nmapData vector with no elements to start with
  tcpdumpData; //initializes the tcpdumpData vector with no elements to start with
  logData; //initializes the logData vector with no elements to start with
  oldCowrieFileNames; //initializes vector with no elements to start with
  currentCowrieFileName = "cowrie.json"; //first logged file
  oldCowrieFileNames.push_back(currentCowrieFileName); //add to the list of old names so it doesn't see it and return that there's a new filename
  oldCowrieFileNames.push_back("cowrie.json~");
  lastCowrieDataSize = 0;
  //setup();
}

bool DataCollection::hasNmap() {
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string installValue; //the install version of the program
  std::ifstream policyReadFile; //creates an input filestream to read from
  int installValueStartIndex; //where the install version info starts in fileValue
  int installValueEndIndex; //where the install version info ends in fileValue
  int installValueLength; //how long the install version value is

  system("touch dataCollectionReadFile.txt"); //creates the file dataCollectionReadFile.txt to read from
  system("apt-cache policy nmap > dataCollectionReadFile.txt"); //puts the value from the apt-cache policy nmap into dataCollectionReadFile.txt
  policyReadFile.open("dataCollectionReadFile.txt"); //opens the filestream
  while (getline(policyReadFile, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line; //append filevalue
  }
  policyReadFile.close(); //close the filestream
  system("rm -f dataCollectionReadFile.txt"); //remove the file
  installValueStartIndex = fileValue.find("Installed") + 11; //index of Installed + the number of chars until the actual value starts
  installValueEndIndex = fileValue.find(" ", installValueStartIndex); //index of the end of the install version info
  installValueLength = installValueEndIndex - installValueStartIndex; //length of the install version value string
  installValue = fileValue.substr(installValueStartIndex, installValueLength); //install version value
  if (installValue.compare("(none)") == 0) { //if it says (none) it means that it isn't installed so I need to install it instead of updating it
    return false; //not installed
  } else {
    return true; //installed
  }
}

bool DataCollection::hasIPTables() {
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string installValue; //the install version of the program
  std::ifstream policyReadFile; //creates an input filestream to read from
  int installValueStartIndex; //where the install version info starts in fileValue
  int installValueEndIndex; //where the install version info ends in fileValue
  int installValueLength; //how long the install version value is

  system("touch dataCollectionReadFile.txt"); //creates the file dataCollectionReadFile.txt to read from
  system("apt-cache policy iptables > dataCollectionReadFile.txt"); //puts the value from the apt-cache policy nmap into dataCollectionReadFile.txt
  policyReadFile.open("dataCollectionReadFile.txt"); //opens the filestream
  while (getline(policyReadFile, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line; //append filevalue
  }
  policyReadFile.close(); //close the filestream
  system("rm -f dataCollectionReadFile.txt"); //remove the file
  installValueStartIndex = fileValue.find("Installed") + 11; //index of Installed + the number of chars until the actual value starts
  installValueEndIndex = fileValue.find(" ", installValueStartIndex); //index of the end of the install version info
  installValueLength = installValueEndIndex - installValueStartIndex; //length of the install version value string
  installValue = fileValue.substr(installValueStartIndex, installValueLength); //install version value
  if (installValue.compare("(none)") == 0) { //if it says (none) it means that it isn't installed so I need to install it instead of updating it
    return false; //not installed
  } else {
    return true; //installed
  }
}

bool DataCollection::hasTCPDump() {
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string installValue; //the install version of the program
  std::ifstream policyReadFile; //creates an input filestream to read from
  int installValueStartIndex; //where the install version info starts in fileValue
  int installValueEndIndex; //where the install version info ends in fileValue
  int installValueLength; //how long the install version value is

  system("touch dataCollectionReadFile.txt"); //creates the file dataCollectionReadFile.txt to read from
  system("apt-cache policy tcpdump > dataCollectionReadFile.txt"); //puts the value from the apt-cache policy nmap into dataCollectionReadFile.txt
  policyReadFile.open("dataCollectionReadFile.txt"); //opens the filestream
  while (getline(policyReadFile, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line; //append filevalue
  }
  policyReadFile.close(); //close the filestream
  system("rm -f dataCollectionReadFile.txt"); //remove the file
  installValueStartIndex = fileValue.find("Installed") + 11; //index of Installed + the number of chars until the actual value starts
  installValueEndIndex = fileValue.find(" ", installValueStartIndex); //index of the end of the install version info
  installValueLength = installValueEndIndex - installValueStartIndex; //length of the install version value string
  installValue = fileValue.substr(installValueStartIndex, installValueLength); //install version value
  if (installValue.compare("(none)") == 0) { //if it says (none) it means that it isn't installed so I need to install it instead of updating it
    return false; //not installed
  } else {
    return true; //installed
  }
}

void DataCollection::setup() {
  findWorkingDir(); //find the working directory
  if (hasNmap() == false) { //if the user doesn't have nmap
    downloadNmap(); //download nmap
  }
  if (hasIPTables() == false) { //if the user doesn't have iptables
    downloadIPTables(); //download iptables
  }
  if (hasTCPDump() == false) { //if the user doesn't have tcpdump
    downloadTCPDump(); //download tcpdump
  }
  updateApplications(); //update and upgrade everything on the computer
  setupIPTablesRules(); //add rules to iptables so that it logs everything and things can be found in the log files
}

void DataCollection::updateApplications() {
  system("sudo apt-get update -y"); //runs update command in the terminal assuming yes
  system("sudo apt-get upgrade -y"); //runs upgrade command in the terminal assuming yes
}

void DataCollection::findWorkingDir() { //pwd = path working directory
  std::string line; //required to get the file value line by line
  std::ifstream fileStream; //creates an input filestream to read from
  system("touch dataCollectionReadFile.txt"); //creates the file dataCollectionReadFile.txt to read from
  system("pwd > dataCollectionReadFile.txt"); //puts the value from the apt-cache policy nmap into dataCollectionReadFile.txt
  fileStream.open("dataCollectionReadFile.txt"); //opens the filestream
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    workingDir = workingDir + line; //append filevalue
  }
  fileStream.close(); //close the filestream

  system("rm -f dataCollectionReadFile.txt"); //remove the file
} //TODO: add a parse workingDir thing which adds "\\" before a space anytime it finds a space

void DataCollection::downloadNmap() {
   system("sudo apt-get install nmap -y"); //install nmap
}

void DataCollection::downloadIPTables() {
 system("sudo apt-get install iptables -y"); //install iptables
}

void DataCollection::downloadTCPDump() {
  system("sudo apt-get install tcpdump"); //install tcpdump
}

void DataCollection::setupIPTablesRules() { //TODO: turn into an array
  std::vector<std::string> importantPorts; //a vector of the ports iptables will log
  importantPorts.push_back("20"); //File Transfer Protocol (FTP)
  importantPorts.push_back("21"); //FTP
  importantPorts.push_back("22"); //Secure Shell (SSH)
  importantPorts.push_back("23"); //Telnet
  importantPorts.push_back("25"); //Simple Mail Transfer Protocol (SMTP)
  importantPorts.push_back("53"); //Domain Name System (DNS)
  importantPorts.push_back("69"); //Trivial File Transfer Protocol (TFTP)
  importantPorts.push_back("80"); //Hyptertext Transfer Protocol (HTTP)
  importantPorts.push_back("110"); //Post Office Protocol (POP) v3
  importantPorts.push_back("123"); //Network Time Protocol (NTP)
  importantPorts.push_back("143"); //Internet Message Access Protocol (IMAP)
  importantPorts.push_back("161"); //Simple Network Management Protocol (SNMP)
  importantPorts.push_back("162"); //SNMP
  importantPorts.push_back("443"); //HTTP over SSL/TLS
  importantPorts.push_back("989"); //FTP over SSL/TLS
  importantPorts.push_back("990"); //FTP over SSL/TLS
  std::string ipTablesCommandString = ""; //string to run the command

  for (int i = 0; i < importantPorts.size(); i++) {
    ipTablesCommandString = "sudo iptables -I INPUT -p tcp --dport " + importantPorts.at(i) + " -j LOG --log-prefix \"ctrlCode: \" -v"; //logs extensive data about what hits this port
    //TODO: make sure that the paramaters for this rule are what you need. Not 100% sure about that
    system(ipTablesCommandString.c_str()); //run the command
  }
}

void DataCollection::runNmap(std::string ip) {
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string nmapSubstr; //temp variable to hold the substring
  int nmapStartIndex; //start index of the new line
  int nmapEndIndex; //end index of the line
  int nmapLength; //length of the substring
  int lineCounter = 0; //for counting the number of lines to add to the nmapData vector

  system("touch nmapOutput_oN.txt"); //create the file
  system("chmod 777 nmapOutput_oN.txt"); //give all users read-write permissions (it'll be deleted immediately and holds no important info)
  std::string nmapCommandString = "sudo nmap -A -O -Pn -sV -v " + ip + " > nmapOutput_oN.txt"; //create the system command into a string
  const char *nmapCommand = nmapCommandString.c_str(); //convert the string into a char array (system parameters)
  system(nmapCommand); //execute the terminal command

  std::ifstream fileStream; //creates an input filestream to read from
  fileStream.open("nmapOutput_oN.txt"); //opens the filestream
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line + "\n"; //append filevalue
    lineCounter++; //do i really need to comment this?
  }
  fileStream.close(); //close the filestream
  system("rm -f nmapOutput_oN.txt"); //remove the file

  if (lineCounter != 0) { //if the file isn't empty
    nmapStartIndex = 0; //start of first line
    nmapEndIndex = fileValue.find("\n"); //differentiates between lines
    nmapLength = nmapEndIndex - nmapStartIndex; //length of the line
    nmapSubstr = fileValue.substr(nmapStartIndex, nmapLength); //create the substring for the line
    nmapData.push_back(nmapSubstr); //add the substring as the last element in the vector
  }

  for (int i = 1; i < lineCounter; i++) { //go through every line
    nmapStartIndex = fileValue.find("\n", nmapEndIndex); //new line start index
    nmapEndIndex = fileValue.find("\n", nmapStartIndex + 1); //new line end index
    nmapLength = nmapEndIndex - nmapStartIndex; //new line length
    nmapSubstr = fileValue.substr(nmapStartIndex, nmapLength); //create new line substring
    nmapData.push_back(nmapSubstr); //add new line substring to the vector
  }
}

void DataCollection::runTCPDump(int packetsToBeCaptured) {
  system("touch tcpdump.txt"); //create the file
  system("chmod 777 tcpdump.txt"); //modify the permissions to give all users read/write privileges (it will be deleted immediately so there's no security risk)
  std::string tcpDumpCommandString = "sudo tcpdump -i any -n -s0 -e -v -c" + std::to_string(packetsToBeCaptured) + " > tcpdump.txt"; //create the system command as a string
  const char *tcpDumpCommand = tcpDumpCommandString.c_str(); //convert the string to a char array
  system(tcpDumpCommand); //execute the command
}

void DataCollection::grabTCPDumpData() { //TODO: MAKE SURE THAT THIS IS RUN IMMEDIATELY AFTER RUNTCPDUMP AND TCPDUMP IS RESTARTED IMMEDIATELY AFTER THIS
  std::string dumpLine; //the install version of the program
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::ifstream fileStream; //creates an input filestream to read from
  int lineCounter = 0; //for counting how manty lines there are in the file
  int dumpLineStartIndex; //where the install version info starts in fileValue
  int dumpLineEndIndex; //where the install version info ends in fileValue
  int dumpLineLength; //how long the install version value is

  fileStream.open("tcpdump.txt"); //opens the filestream
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line + "\n"; //append filevalue
    lineCounter++; //do i really need to comment this?
  }
  fileStream.close(); //close the filestream
  system("rm -f tcpdump.txt"); //remove the file

  if (lineCounter != 0) { //if the file isn't empty
    dumpLineStartIndex = 0; //start of first line
    dumpLineEndIndex = fileValue.find("\n"); //differentiates between lines
    dumpLineLength = dumpLineEndIndex - dumpLineStartIndex; //length of the line
    dumpLine = fileValue.substr(dumpLineStartIndex, dumpLineLength); //create the substring for the line
    tcpdumpData.push_back(dumpLine); //add the substring as the last element in the vector
  }

  for (int i = 1; i < lineCounter; i++) { //go through every line
    dumpLineStartIndex = fileValue.find("\n", dumpLineEndIndex); //new line start index
    dumpLineEndIndex = fileValue.find("\n", dumpLineStartIndex + 1); //new line end index
    dumpLineLength = dumpLineEndIndex - dumpLineStartIndex; //new line length
    dumpLine = fileValue.substr(dumpLineStartIndex, dumpLineLength); //create new line substring
    tcpdumpData.push_back(dumpLine); //add new line substring to the vector
  }
}

void DataCollection::getLogs() { //logs are kept in /var/log/messages //TODO: make it read the authlogs too
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string logDir = "/var/log/"; //directory that the logs are in
  std::string message = ""; //messages file value
  std::ifstream fileStream; //creates an input filestream to read from
  std::string logSubstr; //temp variable to hold the substring
  int logStartIndex; //start index of the new line
  int logEndIndex; //end index of the line
  int logLength; //length of the substring
  int lineCounter = 0; //for counting the number of lines to add to the logData vector

  chdir(logDir.c_str()); //change the working directory of the program in all shells it creates
  /*
  Explanation:
    The system command creates a new shell everytime it is run, so you can't change the directory
    that way. chdir changes the directory of the entire program, so any shells or system commands
    opened will run in that directory. Which is why it's important that you change the directory
    back after getting the log files, otherwise you'll be running commands in that directory
  */

  fileStream.open("messages"); //opens the filestream //TODO: may need to be messages.txt, not sure about that. Will check when I get home and can check on the server
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    message = message + line + "\n"; //append filevalue
    lineCounter++;
  }
  fileStream.close(); //close the filestream
  chdir(workingDir.c_str()); //change the directory back

  if (lineCounter != 0) { //if the file isn't empty
    logStartIndex = 0; //start of first line
    logEndIndex = fileValue.find("\n"); //differentiates between lines
    logLength = logEndIndex - logStartIndex; //length of the line
    logSubstr = fileValue.substr(logStartIndex, logLength); //create the substring for the line
    logData.push_back(logSubstr); //add the substring as the last element in the vector
  }

  for (int i = 1; i < lineCounter; i++) { //go through every line
    logStartIndex = fileValue.find("\n", logEndIndex); //new line start index
    logEndIndex = fileValue.find("\n", logStartIndex + 1); //new line end index
    logLength = logEndIndex - logStartIndex; //new line length
    logSubstr = fileValue.substr(logStartIndex, logLength); //create new line substring
    logData.push_back(logSubstr); //add new line substring to the vector
  }
}

void DataCollection::getLogsTesting() { //logs are kept in /var/log/messages //TODO: make it read the authlogs too
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string message = ""; //messages file value
  std::ifstream fileStream; //creates an input filestream to read from
  std::string logSubstr; //temp variable to hold the substring
  int logStartIndex; //start index of the new line
  int logEndIndex; //end index of the line
  int logLength; //length of the substring
  int lineCounter = 0; //for counting the number of lines to add to the logData vector


  fileStream.open("syslog"); //opens the filestream //TODO: may need to be messages.txt, not sure about that. Will check when I get home and can check on the server
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    message = message + line + "\n"; //append filevalue
    lineCounter++;
  }
  fileStream.close(); //close the filestream
  if (lineCounter != 0) { //if the file isn't empty
    logStartIndex = 0; //start of first line
    logEndIndex = message.find("\n"); //differentiates between lines
    logLength = logEndIndex - logStartIndex; //length of the line
    logSubstr = message.substr(logStartIndex, logLength); //create the substring for the line
    logData.push_back(logSubstr); //add the substring as the last element in the vector
  }
  for (int i = 1; i < lineCounter; i++) { //go through every line
    logStartIndex = message.find("\n", logEndIndex); //new line start index
    logEndIndex = message.find("\n", logStartIndex + 1); //new line end index
    logLength = logEndIndex - logStartIndex; //new line length
    logSubstr = message.substr(logStartIndex, logLength); //create new line substring
    logData.push_back(logSubstr); //add new line substring to the vector
  }
}

std::vector<std::string> DataCollection::getNmapData() {
  return nmapData;
}

std::vector<std::string> DataCollection::getLogData() {
  return logData;
}

std::vector<std::string> DataCollection::getTCPDumpData() {
  return tcpdumpData;
}

std::vector<std::string> DataCollection::getCowrieData() {
  return cowrieData;
}

std::vector<std::string> DataCollection::getNewCowrieData() {
  // std::cout << "getNewCowrieData entered\n";
  std::vector<std::string> newDataVector; //only the new data
  // std::cout << "cowrieDataSize: " << cowrieData.size() << "\n";
  // std::cout << "lastCowrieDataSize: " << lastCowrieDataSize << "\n";
  for (int i = lastCowrieDataSize; i < cowrieData.size(); i++) { //add from the new data to the end
    newDataVector.push_back(cowrieData.at(i)); //add to the new vector
    // std::cout << "in for loop\n";
    // std::cout << cowrieData.at(i) << "\n";
    // std::cout << "newDataVectorSize: " << newDataVector.size();
  }
  // std::cout << "out of for loop\n";
  // std::cout << "newDataVectorSize: " << newDataVector.size();
  return newDataVector;
}

std::vector<std::string> DataCollection::getTCPDumpDataFile() {
  std::vector<std::string> tcpdumpDataFile;
  std::string dumpLine; //the install version of the program
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::ifstream fileStream; //creates an input filestream to read from
  int lineCounter = 0; //for counting how manty lines there are in the file
  int dumpLineStartIndex; //where the install version info starts in fileValue
  int dumpLineEndIndex; //where the install version info ends in fileValue
  int dumpLineLength; //how long the install version value is

  fileStream.open("tcpdump.txt"); //opens the filestream
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line + "\n"; //append filevalue
    lineCounter++; //do i really need to comment this?
  }
  fileStream.close(); //close the filestream

  if (lineCounter != 0) { //if the file isn't empty
    dumpLineStartIndex = 0; //start of first line
    dumpLineEndIndex = fileValue.find("\n"); //differentiates between lines
    dumpLineLength = dumpLineEndIndex - dumpLineStartIndex; //length of the line
    dumpLine = fileValue.substr(dumpLineStartIndex, dumpLineLength); //create the substring for the line
    tcpdumpDataFile.push_back(dumpLine); //add the substring as the last element in the vector
  }

  for (int i = 1; i < lineCounter; i++) { //go through every line
    dumpLineStartIndex = fileValue.find("\n", dumpLineEndIndex); //new line start index
    dumpLineEndIndex = fileValue.find("\n", dumpLineStartIndex + 1); //new line end index
    dumpLineLength = dumpLineEndIndex - dumpLineStartIndex; //new line length
    dumpLine = fileValue.substr(dumpLineStartIndex, dumpLineLength); //create new line substring
    tcpdumpDataFile.push_back(dumpLine); //add new line substring to the vector
  }
  return tcpdumpDataFile;
}

void DataCollection::getCowrie() {
  std::string line; //required to get the file value line by line
  std::string fileValue; //the string form of what is read in the file
  std::string message = ""; //messages file value
  std::ifstream fileStream; //creates an input filestream to read from
  std::string cowrieSubstr; //temp variable to hold the substring
  int cowrieStartIndex; //start index of the new line
  int cowrieEndIndex; //end index of the line
  int cowrieLength; //length of the substring
  int lineCounter = 0; //for counting the number of lines to add to the cowrieData vector


  fileStream.open(currentCowrieFileName); //opens the filestream //TODO: may need to be messages.txt, not sure about that. Will check when I get home and can check on the server
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    if (line != "") {
      cowrieData.push_back(line); //add to the vector
    }
  }
  fileStream.close(); //close the filestream
}

void DataCollection::emptyNmapData() {
  std::vector<std::string> tempVector; //temporary vector that only exists within the scope of this function
  nmapData.swap(tempVector); //swaps the full vector with the empty vector that is deleted on completion of the function
}

void DataCollection::emptyLogData() {
  std::vector<std::string> tempVector; //temporary vector that only exists within the scope of this function
  logData.swap(tempVector); //swaps the full vector with the empty vector that is deleted on completion of the function
}

void DataCollection::emptyTCPDumpData() {
  std::vector<std::string> tempVector; //temporary vector that only exists within the scope of this function
  tcpdumpData.swap(tempVector); //swaps the full vector with the empty vector that is deleted on completion of the function
}

void DataCollection::emptyCowrieData() {
  std::vector<std::string> tempVector; //temporary vector that only exists within the scope of this function
  cowrieData.swap(tempVector); //swaps the full vector with the empty vector that is deleted on completion of the function
}

bool DataCollection::newCowrieFileName() {
  system("ls > ls.txt"); //store contents of ls into ls.txt to check for a new file
  std::vector<std::string> list; //contents of ls.txt
  std::string line = ""; //temp variable
  std::ifstream filestream; //create filestream for reading the file
  bool oldFileName = false; //tracks if it's an old filename
  filestream.open("ls.txt"); //open the filestream
  while (getline(filestream, line)) { //while end of file not reached
    list.push_back(line); //add the line to the list vector
  }
  //system("rm -f ls.txt");
  for (int i = 0; i < list.size(); i++) { //scroll through the files in the directory
    oldFileName = false; //reset oldFilename at the beginning of each iteration
    //std::cout << list.at(i) << "\n";
    //std::cout << "list at " << i << ": " << list.at(i) << "\n";
    if (list.at(i).find("cowrie.json") != -1) { //if this line is one of the cowrie log files
      for (int j = 0; j < oldCowrieFileNames.size(); j++) { //scroll through old cowrie filenames
        if (list.at(i) == oldCowrieFileNames.at(j)) { //if it's an old cowrie file
          oldFileName = true; //it is an old filename
          break; //stop iterating through old filenames
        }
      }
    } else {
      oldFileName = true; //it's not an old filename but it's not a new good filename so it's as useful as an old filename
    }
    if (!oldFileName) {
      oldCowrieFileNames.push_back(currentCowrieFileName); //add the new old one to the list of old names";
      oldCowrieFileNames.push_back(currentCowrieFileName + "~"); //sometimes appears
      currentCowrieFileName = list.at(i); //new filename
      return true; //there is a new filename
    }
  }
  return false; //if there was never a new filename
}

bool DataCollection::newCowrieData() {
  std::string lastCowrieValue = "";
  if (newCowrieFileName()) { //if there is a new file there will be new data
    emptyCowrieData(); //empty the old data
    getCowrie(); //refill it with new data from the new file
    lastCowrieDataSize = 0;
    return true; //there is new data
  }
  if (cowrieData.size() == 0) { //if there is no current cowrie data
    // std::cout << "no cowrie data\n";
    lastCowrieDataSize = 0;
    getCowrie();
    return true; //all data is new data
  } else { //if there is current data
    lastCowrieValue = cowrieData.at(cowrieData.size() - 1); //find the last string
    lastCowrieDataSize = cowrieData.size(); //set the datasize variable so it knows where to go on from
  }
  emptyCowrieData(); //empty the current data
  getCowrie(); //refill it with new data from the current file
  if (cowrieData.size() != 0) { //if there were no errors collecting the data`
    if (cowrieData.at(cowrieData.size() - 1) == lastCowrieValue) { //if the new last line and the old last line were the same
      // std::cout << "\nno new data\n";
      return false; //there is no new data
    } else { //if they were different
      return true; //there is new data
    }
  }
}

void DataCollection::collectNewCowrieData() { //write only the most recent data to the cowrie file
  std::vector<std::string> tempCowrieVector; //temporary vector
  // std::cout << "\nlastCowrieDataSize: " << lastCowrieDataSize;
  // std::cout << "\ncowrieDataSize: " << cowrieData.size() << "\n";
  for (int i = lastCowrieDataSize; i < cowrieData.size(); i++) {
    tempCowrieVector.push_back(cowrieData.at(i)); //add the new data to a vector
  }
  cowrieData.swap(tempCowrieVector); //swap the new data vector with the full data vector
}













/*DataCollection::findworkingDir() { //ugly way of doing it
   int LINUX_MAX_PATH_LENGTH = 4096; //linux a path name can't be longer than 4096 characters (which is 4096 bytes)
   int closeStreamStatus;
   char *workingDir; //TODO: once you move beyond testing and start doing actual class functions, make workingDir a global variable
   FILE *stream;

   stream = popen("pwd", "r"); //open a filestream that reads the output from the terminal command pwd
   if (stream == NULL) { //if the command pwd didn't output something
     return 0; //error handling - TODO: implement more error handling later
   }

   fgets(workingDir, LINUX_MAX_PATH_LENGTH, stream); //reads the file stream and copies it to the char* workingDir - only copies up to LINUX_MAX_PATH_LENGTH (4096) characters
   printf("%s", workingDir); //outputs the current directory - used for testing purposes

   closeStreamStatus = pclose(stream); //close the filestream

   if (closeStreamStatus == -1) { //if there was an error in closing the filestream
     return 0; //error handling - TODO: implement more error handling later
   }

   char* output; //for some reason this variable is necessary for outputting to the terminal
   strncpy(output, "echo \"", 6); //output needs to have these lines to be able to output to the terminal... don't know why

}*/

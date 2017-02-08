#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <math.h>

std::string toString(int number) {
  std::string result = "";
  int tempNum = 0;
  int counter = 10;
  while (number > 0) {
    tempNum = number % counter;
    result = (char)(tempNum + 48) + result;
    number = number / counter;
  }
  return result;
}

int findFileNumber() {
  std::ifstream fileStream;
  std::string line;
  std::string fileValue;
  std::string filename = "tcpdump.txt";
  system("ls > fileList.txt");
  fileStream.open("fileList.txt"); //opens the filestream
  while (getline(fileStream, line)) { //while there are still lines in the filestream
    fileValue = fileValue + line + "\n"; //append filevalue
  }
  fileStream.close(); //close the filestream
  system("rm -f fileList.txt"); //remove the file
  if (fileValue.find(filename) == -1) {
    return 0;
  }
  for (int i = 1; i < 1000; i++) {
    filename = "tcpdump" + toString(i) + ".txt";
    if (fileValue.find(filename) == -1) {
      return i;
    }
  }
  return -1;
}

int main() {
  std::string line;
  std::string eventID;
  int counter = -1;
  //int startValue = findFileNumber() == 0 ? 0 : (findFileNumber() - 1) * 50000; //initial data file is tcpdump so tcpdump.1 is actually 0 - 50000
  //int endValue = startValue + 50000;
  int startValue = 0;
  int endValue = 30000;
  std::cout << "start: " << startValue << "\n";
  std::cout << "end: " << endValue << "\n";
  std::ifstream inFilestream;
  std::ofstream outFilestream;
  std::string outFile = "tcpdump1.txt";
  outFilestream.open(outFile.c_str());
  inFilestream.open("tcpdump.txt");
  while(getline(inFilestream, line)) {
    if (counter > startValue && counter < endValue) {
      outFilestream << line << "\n";
    }
    counter++;
    if (counter > endValue) {
      if (line[1] == ' ') {
        outFilestream << line << "\n";
      }
      outFilestream.close();
      outFile = "tcpdump" + toString(findFileNumber()) + ".txt";
      outFilestream.open(outFile.c_str());
      endValue += 30000;
    }
  }
  outFilestream.close();
  inFilestream.close();
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <math.h>

std::string toString(int number) { //convert an integer to a string because I can't currently update my compiler to get the built in method to work
  std::string result = "";
  int tempNum = 0;
  int counter = 10;
  while (number > 0) {
    tempNum = number % counter; //get the last digit of the number
    result = (char)(tempNum + 48) + result; //add to the string from end to beginning
    number = number / counter; //use integer math to get rid of the last digit (tempNum)
  }
  return result;
}

int findFileNumber() { //scroll through the list of current tcpdump files and find the first unused one (i.e., if tcpdump.txt and tcpdump1.txt exist already, output to tcpdump2.txt)
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
  for (int i = 2; i < 1000; i++) { //tcpdump is used already as the temp file and tcpdump1 already exists so it starts at 2
    filename = "tcpdump" + toString(i) + ".txt"; //filename
    if (fileValue.find(filename) == -1) { //if file not found
      return i;
    }
  }
  return -1; //if you've got tcpdump 0-999 your file is way too big
}

int main() {
  std::string filename = "tcpdump.txt";
  std::string command;
  std::cout << findFileNumber();
  int numToFinish = findFileNumber();
  for (int i = 2; i < numToFinish; i++) {
    system("./main"); //execute main file - processor
    filename = "tcpdump.txt"; //reset filename
    command = "rm -f " + filename; //delete temp file
    system(command.c_str()); //execute
    filename = "tcpdump" + toString(i) + ".txt"; //most recent temp filename
    command = "mv " + filename + " tcpdump.txt"; //change the new lowest tcpdump file to tcpdump.txt to run main
    system(command.c_str()); //execute
  }
}

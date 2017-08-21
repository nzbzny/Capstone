#include "DataPreprocessing.h"
#include "DataCollection.h"
#include <unistd.h>


int main() {
  // std::cout << "first line\n";
  DataCollection collector; //for collecting the data initially and determining if there is new data
  DataPreprocessing processor; //for processing the data into .csv files

  std::string predictionsText = "";
  std::ifstream inFilestream;
  std::ofstream outFilestream;
  std::string line = "";
  // std::cout << "starting getting cowrie\n";
  collector.getCowrie(); //get data the first runthrough
  // std::cout << "processing cowrie\n";
  processor.processCowrie(collector.getCowrieData()); //process data the first runthrough
  // std::cout << "done processing cowrie\n";
  system("python OpenMLModel.py"); //run the ML code
  // std::cout << "slept\n";
  inFilestream.open("NewMLOutput.csv"); //open the new machine learning output file
  while (getline(inFilestream, line)) {
    predictionsText = line + "\n" + predictionsText; //add the new line(s) to the predictions string
  }
  inFilestream.close(); //close the new machine learning output file
  std::cout << predictionsText; //output the new predictions
  system("touch predictions.csv");
  inFilestream.open("predictions.csv"); //open the file with all of the predictions
  while (getline(inFilestream, line)) {
    predictionsText += line; //add the previous predictions back to the predictions string
    predictionsText += "\n";
  }
  inFilestream.close(); //close the overall predictions file
  outFilestream.open("predictions.csv"); //open the overall predictions file to rewrite to it
  outFilestream << predictionsText; //rewrite to the old file
  outFilestream.close(); //close the overall predictions file
  predictionsText = "";
  line = "";
  system("rm -f cowrieProcessed.csv"); //remove cowrieProcessed.csv to avoid having a million 1-line files
  system ("rm -f NewMLOutput.csv"); //remove the new ML output data since it's all in predictions.csv

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

  /*collector.getCowrie(); //get file
  std::vector<std::string> cowrieData = collector.getCowrieData(); //add temp file to vector
  processor.processCowrie(cowrieData);*/
/*  std::string temp;
  std::cout << "\nstarted";
  std::cin >> temp;
  std::cout << "\nnewCowrieData: " << collector.newCowrieData();
  std::cin >> temp;
  std::cout << "\nmoving files";
  system("mv cowrie.json cowrie2.json");
  system("mv cowrieCopy.json cowrie.json");
  std::cin >> temp;
  std::cout << "\nemptying datapreprocessing data";
  processor.emptyData();
  std::cin >> temp;
  std::cout << "\nnewCowrieData: " << collector.newCowrieData();
  std::cin >> temp;
  std::cout << "\n\nnewCowrieData:\n\n\n" << collector.getNewCowrieData().size() << "\n\n\n";
  std:: cin >> temp;
  std::cout << "\nprocessCowrieData" << processor.processCowrie(collector.getNewCowrieData());
  std::cin >> temp;*/

  while (true) { //infinite loop - TODO: create way to break out of it
    // std::cout << "infinite loop\n";
    processor.emptyData(); //empty the processor's vectors so that it deletes the old data
    if (collector.newCowrieData()) { //checks for new data (also collects new data and empties the data file within the function, so that is not necessary to do explicitly in this loop)
      if (processor.processCowrie(collector.getNewCowrieData())) { //process the cowrie data then output to CSV - if there was no usable data to process then don't go on
        //TODO: transfer VBA code to C++ or python and run that, predict with machine learning code, then delete the .csv file, then report to the command line
        //TODO: run the ML code - figure out how to turn it into a .exe
        system("python OpenMLModel.py"); //run the ML code
        // sleep(500); //give it half a second to finish processing everything
        inFilestream.open("NewMLOutput.csv"); //open the new machine learning output file
        while (getline(inFilestream, line)) {
          predictionsText = line + "\n" + predictionsText; //add the new line(s) to the predictions string
        }
        inFilestream.close(); //close the new machine learning output file
        std::cout << predictionsText; //output the new predictions
        inFilestream.open("predictions.csv"); //open the file with all of the predictions
        while (getline(inFilestream, line)) {
          predictionsText += line; //add the previous predictions back to the predictions string
          predictionsText += "\n";
        }
        inFilestream.close(); //close the overall predictions file
        outFilestream.open("predictions.csv"); //open the overall predictions file to rewrite to it
        outFilestream << predictionsText; //rewrite to the old file
        outFilestream.close(); //close the overall predictions file
        predictionsText = "";
        line = "";
        system("rm -f cowrieProcessed.csv"); //remove cowrieProcessed.csv to avoid having a million 1-line files
        system ("rm -f NewMLOutput.csv"); //remove the new ML output data since it's all in predictions.csv
      }
    }
  }

  //system("mv cowrie.json cowrie2.json");
  //system("mv cowrie3.json cowrie.json");
  //std::cout << collector.newCowrieData() << "\n";
  //std::cout << collector.newCowrieFileName() << "\n";
}

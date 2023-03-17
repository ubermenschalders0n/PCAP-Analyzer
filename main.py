import spacy


#this class will be the schema of our main class. If we want to update something we can update this abstract class
#also if the project was to be expanded we can create multiple concrete classes without writing everything again.
#we can have another class that inherits from abstract class and defines the functions that will be used for future classes
#which will increase our code reuse and will decrease redundancy 
class pcapAnalyzerAbstract():
    def giveReport(self):
        pass
    def numOfFlows(self):
        pass
    def sizeOfBytes(self):
        pass
    def topHostname(self):
        pass
    
    
class concretePcapAnalyzer(pcapAnalyzerAbstract):
    #Give report will call the other functions and will double check if the variables are empty or not
    def giveReport(self):
        self.numOfFlows;self.sizeOfBytes;self.topHostname if not self.flowCount==-1 and not self.byteSize==-1 and not self.topHost=="Empty" else print("Flow count is empty , please start the analyzer first")
    def numOfFlows(self):
        print("Flow count for the pcap file is as follows :{} \n".format(self.flowCount)) if not self.flowCount==-1 else print("Flow count is empty , please start the analyzer first")
    def sizeOfBytes(self):
        print("Byte size for the pcap file is as follows :{} \n".format(self.byteSize)) if not self.byteSize==-1 else print("Byte size is empty , please start the analyzer first")   
    def topHostname(self):
        print("Byte size for the pcap file is as follows :{} \n".format(self.topHost)) if not self.topHost=="Empty" else print("Top hostname is empty , please start the analyzer first")
        pass
    def __init__():
        pass
    
    #default case for objects to have numOfFlows as -1 . The # of flows cannot be under 0, this will be used for testing whether the variable is started or not
    #and as python is different to java you cannot initialize variables without assigning them
    flowCount=-1
    #default case for error handling 
    byteSize=-1
    #default case for error handling
    topHost="Empty"
    
  
  
from scapy.all import *
from optparse import OptionParser


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
        self.printNumOfFlows();self.printSizeOfBytes();self.printTopHostname() if not self.flowCount==-1 and not self.byteSize==-1 and not self.topHost=="Empty" else print("Flow count is empty , please start the analyzer first")
    def printNumOfFlows(self):
        print("Flow count for the pcap file is as follows :{} \n".format(self.flowCount)) if not self.flowCount==-1 else print("Flow count is empty , please start the analyzer first")
    def printSizeOfBytes(self):
        print("Byte size for the pcap file is as follows :{} \n".format(self.byteSize)) if not self.byteSize==-1 else print("Byte size is empty , please start the analyzer first")   
    def printTopHostname(self):
        print("Byte size for the pcap file is as follows :{} \n".format(self.topHost)) if not self.topHost=="Empty" else print("Top hostname is empty , please start the analyzer first")
    def __init__():
        pass
    def packetReader(self):
        try:
            self.packets=rdpcap(self.pathToPcap) if not self.pathToPcap=="Empty" else print("Path to pcap file is empty check your path")
        except Exception as e:
            print("Error raised \n")
            print(str(e))
    def numOfFlows(self):
        print("The packets are empty please initialize it"); self.packetReader() if not self.packets else print("Analyzing the pcap file for # of HTTP flows")
        #initialize a hashmap to check uniqueness of HTTP flows
        httpFlows={}
        #firstly check if the communication is based on HTTP
        #if it is HTTP than extract the destination and source IP addresses 
        #check if the src and dst pair is unique in the hashmap , if it is initialize the count for that with 1
        #if it is not unique increment the existing count by one
        for packet in self.packets:
            if(packet.hasLayer("HTTP")):
                src=packet[IP].src
                dst=packet[IP].dst
            if (src, dst) in httpFlows:
                httpFlows[(src, dst)] += 1
            else:
                httpFlows[(src, dst)] = 1
        #here we are counting number of HTTP flow count. If we wanted to count only the unique http flows we can just take the length of httpFlows dictionary          
        #self.flowCount=len(httpFlows)
        #we will count all of the http flows for each unique src and dst IP address combination
        
        for val in httpFlows.values():
            numberOfFlows+=val
        self.flowCount=numberOfFlows
    def sizeOfBytes(self):
        print("The packets are empty please initialize it"); self.packetReader() if not self.packets else print("Analyzing the pcap file for total byte size")
        totalSize=0
        #for this I have been researching , it seems scapy can not handle length of IPv6 packets correctly therefore I am checking the layer of the packet
        #if it is in  ipv6 layer we will use plen variable from packet which gives back length of the packet correctly for IPv6 packets
        #if it is not IPv6 we can safely call len variable to get length of the packet
        # I have not truncated any packet size as assignment said total size of packets
        # I have found the solution for finding IPv6 packet length here ==> https://stackoverflow.com/questions/21752576/whole-packet-length-scapy
        for packet in self.packets:
          if packet.haslayer(IPv6):
              totalSize+=packet.plen
          else:
              totalSize+=packet.len               
    def topHostname(self):
        pass
    #default case for objects to have numOfFlows as -1 . The # of flows cannot be under 0, this will be used for testing whether the variable is started or not
    #and as python is different to java you cannot initialize variables without assigning them
    flowCount=-1
    #default case for error handling 
    byteSize=-1
    #default case for error handling
    topHost="Empty"
    packets=""
    pathToPcap="Empty"
    
#the main class we will be using
def main():
    #we will use the OptionParser library for parsing command line arguments , we will have only one argument which will direct us to the pcap files path
    cliParser=OptionParser()
    cliParser.add_option("-p","--path",dest="pcapPath",help="The path of the pcap file as absolute path in the operating system",type="string")#pcap file path
    (options,args) = cliParser.parse_args()
    pcapPath=options.pcapPath
  
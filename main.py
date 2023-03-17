from scapy.all import *
from optparse import OptionParser
import socket

#!!!!!!!!!!!!!!!!!!!!!!ASSUMPTIONS!!!!!!!!!!!!!!!!!!!!!!

#HTTP traffic can be generated with UDP . I will not check if the http request has layers for TCP only. As some of the http traffic can be on UDP protocol.

#3-Top hostname visited in HTTP traffic
#there are couple of ways to solve this
#3.1- Extract all IP addresses from the pcap file and do a reverse DNS lookup with sockets library
#This can be problematic as IP addresses provided can be private IP addresses and when resolved to a host it will give back the wrong hostname
#3.2- Look for DNS requests in the PCAP file and extract hostnames from DNS requests
#I think this is not the solution you want , as HTTP traffic is explicitly wanted in the assignment 
#3.3- Extract host header from packets
#This will be the solution I am implementing, I will parse each packet and extract the host header value from the packet
#The host value will be put inside hashmap(dictionary in python) and incremented each time the same host header value is found


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
    def printNumOfFlows(self):
        pass
    def printSizeOfBytes(self):
        pass
    def printTopHostname(self):
        pass
    
    
class concretePcapAnalyzer(pcapAnalyzerAbstract):
    #Give report will call the other functions and will double check if the variables are empty or not
    def giveReport(self):
        self.printNumOfFlows();self.printSizeOfBytes();self.printTopHostname() if not self.flowCount==-1 and not self.byteSize==-1 and not self.topHost=="Empty" else print("Error in variables check everything started correctly")
    def printNumOfFlows(self):
        print("Flow count for the pcap file is as follows :{} \n".format(self.flowCount)) if not self.flowCount==-1 else print("Flow count is empty , please start the analyzer first")
    def printSizeOfBytes(self):
        print("Byte size for the pcap file is as follows :{} \n".format(self.byteSize)) if not self.byteSize==-1 else print("Byte size is empty , please start the analyzer first")   
    def printTopHostname(self):
        print("Top host for the pcap file is as follows :{} \n".format(self.topHost)) if not self.topHost=="Empty" else print("Top hostname is empty , please start the analyzer first")
    def __init__(self,pathToPcap):
        self.pathToPcap=pathToPcap
        self.packetReader()
    def analyzeAndReport(self):
        self.numOfFlows()
        self.sizeOfBytes()
        #self.topHostname()
        self.giveReport()
    def packetReader(self):
        try:
            packets=rdpcap(self.pathToPcap) if not self.pathToPcap=="Empty" else print("Path to pcap file is empty check your path")
            filteredPacket=[]
            for packet in packets:
                try:
                    if TCP in packet and packet[TCP].dport==80 and packet.haslayer('Raw'):
                        if b'HTTP' in packet[Raw].load:
                            filteredPacket.append(packet)
                except Exception as e:
                    print("Error raised")  
            self.packets=filteredPacket   
        except Exception as e:
            print("Error raised \n")
            print(str(e))            
    def numOfFlows(self):
        if(self.packets=="Empty"):
            print("The packets are empty please initialize it numofflows")
            self.packetReader()
        else:
            print("Analyzing the pcap file for # of HTTP flows")
        #initialize a hashmap to check uniqueness of HTTP flows
        httpFlows={}        
        #firstly check if the communication is based on HTTP
        #if it is HTTP than extract the destination and source IP addresses 
        #check if the src and dst pair is unique in the hashmap , if it is initialize the count for that with 1
        #if it is not unique increment the existing count by one
        for packet in self.packets:
            # pkt.haslayer(TCP) and pkt.haslayer(Raw) and b"HTTP" in pkt[Raw].load
            if(b'HTTP' in packet[Raw].load):
                src=packet[IP].src
                dst=packet[IP].dst
                if (src, dst) in httpFlows:
                    httpFlows[(src, dst)] += 1
                else:
                    httpFlows[(src, dst)] = 1
            #we are only looking for http packets 405 10282
            else:
                pass
        #here we are counting number of HTTP flow count. If we wanted to count only the unique http flows we can just take the length of httpFlows dictionary          
        #self.flowCount=len(httpFlows)
        #we will count all of the http flows for each unique src and dst IP address combination    
        numberOfFlows=0    
        for val in httpFlows.values():
            numberOfFlows+=val
        self.flowCount=numberOfFlows
    #ipv6 implementation ==> 58403
    #without ipv6 ==> 59375
    def sizeOfBytes(self):
        print("The packets are empty please initialize it"); self.packetReader() if self.packets=="Empty" else print("Analyzing the pcap file for total byte size")
        totalSize=0
        #for this I have been researching , it seems scapy can not handle length of IPv6 packets correctly therefore I am checking the layer of the packet
        #if it is in  ipv6 layer we will use plen variable from packet which gives back length of the packet correctly for IPv6 packets
        #if it is not IPv6 we can safely call len variable to get length of the packet
        # I have not truncated any packet size as assignment said total size of packets
        # I have found the solution for finding IPv6 packet length here ==> https://stackoverflow.com/questions/21752576/whole-packet-length-scapy
        for packet in self.packets:
          if packet.haslayer(IPv6) and b'HTTP' in packet[Raw].load:
              totalSize+=packet.plen
          elif b'HTTP' in packet[Raw].load:
              totalSize+=packet.len
          else:
              #we are only counting http traffic so we will pass these packets
              pass         
    #host_header = http_layer.fields['Host']
        self.byteSize=totalSize    
    def topHostname(self):
        print("The packets are empty please initialize it"); self.packetReader() if self.packets=="Empty" else print("Analyzing the pcap file for finding top hostname")
        hostsDict={}
        print("Here in tophostname")
        for packet in self.packets:
            if(b'HTTP' in packet[Raw].load):
                host_header = packet.fields['Host']
                if(host_header in hostsDict):
                    hostsDict[host_header]+=1
                else:
                    hostsDict[host_header]=1
            #we are only counting the http traffic so pass other packets that does not have http layer
            else:
                pass
        #the host with the top value will assigned to our internal class variable
        self.topHost=max(hostsDict,key=hostsDict.get)
    #default case for objects to have numOfFlows as -1 . The # of flows cannot be under 0, this will be used for testing whether the variable is started or not
    #and as python is different to java you cannot initialize variables without assigning them
    flowCount=-1
    #default case for error handling 
    byteSize=-1
    #default case for error handling
    topHost="Empty"
    #default case for error handling 
    # , in python empty strings are falsy so I will use the inbuilt functionality of python
    packets="Empty"
    #default case for error handling
    pathToPcap="Empty"    
        

    
#the main class we will be using
def main():
    #we will use the OptionParser library for parsing command line arguments , we will have only one argument which will direct us to the pcap files path
    cliParser=OptionParser()
    cliParser.add_option("-p","--path",dest="pcapPath",help="The path of the pcap file as absolute path in the operating system",type="string")#pcap file path
    (options,args) = cliParser.parse_args()
    pcapPath=options.pcapPath
    pcapParser=concretePcapAnalyzer(pcapPath)
    pcapParser.analyzeAndReport()
  
  
if __name__ == '__main__':
    main()

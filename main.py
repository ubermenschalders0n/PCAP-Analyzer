import pyshark
#from optparse import OptionParser
import socket
import re
import sys



#!!!!!!!!!!!!!!!!!!!!!!ASSUMPTIONS!!!!!!!!!!!!!!!!!!!!!!

#HTTP traffic can be generated with UDP . I will check if the http request has layers for TCP only. As haslayer was problematic in the implementation and there
#was none of the http udp packets
#1-Number of flows in HTTP
#For each unique destination IP address and source IP address I will create an element inside the hashmap
#Each time this unique combination is found in the packets the value of the key value - pair will be incremented by one
#The number of HTTP flows will be calculated by getting the value of each key and getting the sum of all the values
#If we wanted to see only the count of unique src,dst combination we can just use the len() function and give it as result
#3-Top hostname visited in HTTP traffic
#there are couple of ways to solve this
#3.1- Extract all IP addresses from the pcap file and do a reverse DNS lookup with sockets library
#This can be problematic as IP addresses provided can be private IP addresses and when resolved to a host it will give back the wrong hostname
#3.2- Look for DNS requests in the PCAP file and extract hostnames from DNS requests
#I think this is not the solution you want , as HTTP traffic is explicitly wanted in the assignment 
#3.3- Extract host header from packets
#This will be the solution I am implementing, I will parse each packet and extract the host header value from the packet
#The host value will be put inside hashmap(dictionary in python) and incremented each time the same host header value is found



#!!!!!!!!!!!!!!!!!!!!!!Using pyshark rather than scapy !!!!!!!!!!!!!!!!!!!!!!
    #when I have debugged the program , and ran some calculation on the given pcap file with tshark I have found a major logic error caused by the scapy library
    #the packets were giving back unexpected errors and the script was not working correctly
    #when I have debugged it , I was able to find that haslayer(HTTP) was causing this error
    #Therefore I decided not to use the native functionalities of scapy to check whether or not the given packet uses http protocol
    #the bug arises from scapy not counting packets as having http layer , it will only check src.port and if it is 80 it will count the packet as HTTP
    #when the haslayer(http) is called for the given pcap in the assignment , it will think nearly half of the packets are using http protocol
    #but it is wrong , 405 packets are using http protocols
    #I have tried fixing it by handling everything in the very low level , reading packets raw and extracting http reqs and their continuation packet
    #I was finding http requests , finding the first transaction and getting all the dst and src ip with port
    #the four variables were creating a unique combination that we can use , finding packets that had the same (dst.ip,src.ip,dst.port,src.ip) combination 
    #will give us the full flow of that HTTP request with each packet. I was adding those to the packet list.
    #The code started to get really complicated for this task and code became redundant , multiple checks were needed in each function to negate errors
    #Therefore as I knew how to write with pyshark and I was using tshark for personal development I switched to pyshark
    #Which did not have the errors present in scapy , and the problem was solved by 10 lines of code
    
    #references about the problem 
    #https://github.com/invernizzi/scapy-http/issues/36#issuecomment-417051684
    #https://stackoverflow.com/questions/70408860/packets-dont-have-http-layer-available
    #https://stackoverflow.com/questions/57447123/cannot-get-scapy-2-4-3-http-layer-support-to-work/57450404#57450404
    
    #My old notes about implementing the functionality I have explained above
    #I will create the filter on the given packets by myself
    #it will check every packet for the following information
    #1-Packet uses TCP protocol , as HTTP uses TCP protocol in nearly most cases the remaining packets will be with HTTP protocol
    #2-The destination port of the TCP protocol is 80 , as port 80 is used for HTTP traffic universally this will give us no errors also
    #3-8080 port was not being used in the pcap file so we have skipped the other possible http port
    #4-The packet also may have layer of raw, but this can create problems, raw layer is given to the packet if no other layer can be assigned to it
    #5-Also http requests may send data as URL parameter , which results in some of the http requests not being counted in our current filter
    
    #Old notes about top host header 
        #for this I have been researching , it seems scapy can not handle length of IPv6 packets correctly therefore I am checking the layer of the packet
        #if it is in  ipv6 layer we will use plen variable from packet which gives back length of the packet correctly for IPv6 packets
        #if it is not IPv6 we can safely call len variable to get length of the packet
        # I have not truncated any packet size as assignment said total size of packets
        # I have found the solution for finding IPv6 packet length here ==> https://stackoverflow.com/questions/21752576/whole-packet-length-scapy


#this class will be the schema of our main class. If we want to update something we can update this abstract class. It will be used for handling redundancy
#also if the project was to be expanded we can create multiple concrete classes without writing everything again in each child instance
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
    #error handling firstly in each class , for the integrity of software 
    def giveReport(self):
        self.printNumOfFlows();self.printSizeOfBytes();self.printTopHostname() if not self.flowCount==-1 and not self.byteSize==-1 and not self.topHost=="Empty" else print("Error in variables check everything started correctly")
    #error handling firstly in each class , for the integrity of software 
    def printNumOfFlows(self):
        print("Flow count for the pcap file is as follows :{} \n".format(self.flowCount)) if not self.flowCount==-1 else print("Flow count is empty , please start the analyzer first")
    #error handling firstly in each class , for the integrity of software 
    def printSizeOfBytes(self):
        print("Byte size for the pcap file is as follows :{} \n".format(self.byteSize)) if not self.byteSize==-1 else print("Byte size is empty , please start the analyzer first")   
    #error handling firstly in each class , for the integrity of software 
    def printTopHostname(self):
        print("Top host for the pcap file is as follows :{} \n".format(self.topHost)) if not self.topHost=="Empty" else print("Top hostname is empty , please start the analyzer first")
    #when the class object is created the instance firstly should assign the absolute path of pcap file
    #therefore the constructor is getting the path to pcap as a parameter
    #after that the constructor will call the packetreader class , which will read the pcap file in the given path
    #and populate the instance variable packets which will be used in nearly every function in the class
    def __init__(self,pathToPcap):
        self.pathToPcap=pathToPcap
        self.packetReader()
    #this function internally calls each corresponding function and lastly gives back report on each one of them
    def analyzeAndReport(self):
        self.numOfFlows()
        self.sizeOfBytes()
        self.printSizeOfBytes()
        self.topHostname()
        self.giveReport()
    #this is a regex implementation to check whether or not the given address is an ip address
    #if it is an ip address we will do a reverse_dns_lookup on the ip address to get the hostname
    #I have implemented this because some of the hostnames are given in IP address in the pcap file
    #if multiple ip addresses resolved to the same hostname it would have given us f/p , this will negate that
    def isIPV4Address(self,address):
        ipv4_regex = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'
        match = re.match(ipv4_regex, address)
        return bool(match)
    #do a reverse_dns_lookup on the given ip address, if it is an private ip address it will not resolve to anything
    #this is implemented to negate some niche possible f/p reports
    def reverse_dns_lookup(self,ip_address):
        #Code will be inside try catch statement because the functions can raise a lot of network errors, this will handle the error and keep the program
        #from crashing
        try:
            hostname = socket.getnameinfo((ip_address,0),0)[0]
            return hostname
        except socket.herror:
            return None
    #this class will take adventage of inbuilt functionalities that work and should have been working in scapy
    #It will filter all the packets using HTTP protocol and do a double check on the packets before populating the packets using http protocol to the
    #filteredPackets list 
    def packetReader(self):
        try:
            filteredPackets=[]
            packets = pyshark.FileCapture(self.pathToPcap, display_filter='http')
            for packet in packets:
                #double check just to be sure , some multithreaded sheningangs can cause a lot of headache
                if 'TCP' in packet and 'HTTP' in packet:
                    filteredPackets.append(packet)    
            self.packets=filteredPackets
        except Exception as e:
            print("Error raised \n")
            print(str(e))            
    def numOfFlows(self):
        #error handling firstly in each class , for the integrity of software 
        if(self.packets=="Empty"):
            print("The packets are empty please initialize it")
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
            flow=(packet['ip'].src,packet['ip'].dst,packet['tcp'].srcport,packet['tcp'].dstport)
            # I have implemented 2 solutions to find number of http flows
            # First one only looks for src and dst IP addresses and if the combination is unique the packet is stored and number of packets having the same value 
            # will result incremented values for the unique combination in the key-value pair with each iteration.
            # number of flows can be counted as the sum of all the values in the dictionary
            # Second one also uses the same combination to find unique packets but it will only count the number of unique pairs in the dictionary
            # as the result , which will give back unique number of http flows in the pcap file , therefore I am using the second solution
            if flow not in httpFlows:
                httpFlows[flow]=1
            else:
                httpFlows[flow]+=1

        #here we are counting number of HTTP flow count. If we wanted to count only the unique http flows we can just take the length of httpFlows dictionary          
        #self.flowCount=len(httpFlows)
        #we will count all of the http flows for each unique src and dst IP address combination    
        self.flowCount=len(httpFlows)
    def sizeOfBytes(self):
        #error handling firstly in each class , for the integrity of software 
        print("The packets are empty please initialize it"); self.packetReader() if self.packets=="Empty" else print("Analyzing the pcap file for total byte size")
        totalSize=0
        #as packets are sorted correctly in the reading step , we do not need to double check in every function
        #this code will just print sum of all the packet lengths by using .length variable without specifying any layer to get total size
        for packet in self.packets:
            totalSize+=int(packet.length)
        #assign found sum to to the internal class variable
        self.byteSize=totalSize
    #host_header = http_layer.fields['Host']
    def topHostname(self):
        #error handling firstly in each class , for the integrity of software 
        print("The packets are empty please initialize it"); self.packetReader() if self.packets=="Empty" else print("Analyzing the pcap file for finding top hostname")
        hostsDict={}
        for packet in self.packets:
            try:
                #extract the host field from http requests
                hostName=packet['http'].host
                #check if the host name is in ipv4 format , if it is make a reverse dns lookup to get human
                if(self.isIPV4Address(hostName)):
                    #this line can cause a lot of errors , if the IP address found is an private address for example it will not resolve to any hostname
                    #as it will have no dns records, therefore the whole snippet is wrapped around try catch . It will pass the expected errors and 
                    #will continue the execution of the program
                    try:
                        hostName=self.reverse_dns_lookup(hostName)
                    except Exception as e:
                        print("Reverse lookup is giving back errors , passing to the next value \n {}".format(str(e)))
                if(hostName not in hostsDict):
                    hostsDict[hostName]=1
                else:
                    hostsDict[hostName]+=1
            except Exception as e:
                print("Error raised , host field may not be present in the packet or the packet may be malformed")
                print(str(e))
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
    packets="Empty"
    #default case for error handling
    pathToPcap="Empty"    
        

    
#the main class we will be using
def main():
    #I have firstly implemented command line argument parsing with OptionParser
    #but as you do not want to use any flags in the cli I have deleted it and changed it with getting the second value in the argv array (indexed 1)
    #we will use the OptionParser library for parsing command line arguments , we will have only one argument which will direct us to the pcap files path
    #cliParser=OptionParser()
    #cliParser.add_option("-p","--path",dest="pcapPath",help="The path of the pcap file as absolute path in the operating system",type="string")#pcap file path
    #(options,args) = cliParser.parse_args()
    #pcapPath=options.pcapPath
    #this will get the first argument without any flags
    pcapPath=sys.argv[1]
    #this will check if the argument is of type str or not , if it is not str it will exit the program
    if(not isinstance(pcapPath,str)):
        print("The given command line argument is not of type string , illegal input exiting")
        quit()
    pcapParser=concretePcapAnalyzer(pcapPath)
    pcapParser.analyzeAndReport()
  
  
if __name__ == '__main__':
    main()

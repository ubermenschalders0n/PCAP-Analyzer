*************************
*****farukburakgurel***** 
****ubermenschalders0n***               
*************************

Hello and welcome to my packet analyzing application.

The application is fully containerized and can be run with docker commands after image is built.

The application will analyze the HTTP traffic of given pcap file and provide the statistics
1-Number of HTTP flows 
2-Total size of the packets using HTTP protocol
3-The most common host name in the packets using HTTP protocol

Installing 

After cloning the repository run the following commands in the cloned directory , make sure you have root permissions to run the docker commands

docker build -t <enter-image-name> .

After building the image you can run the script with the following command

As the program is reading pcap files in the host system we have to make the files viable to docker container to see

This can be done by giving the path to the file in the host system and giving the imaginary mounting point for docker container
The file will be present in the mounted point inside docker container

sudo docker run -v <localLocationOfFile>:<MountedPointInContainer> --rm 84936700d93a <locationOfFileYouWantToReadInContainer>



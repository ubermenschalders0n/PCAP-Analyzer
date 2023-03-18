FROM cincan/tshark
#Firstly the comment is below the above code because if we have any text before FROM is initialized in a docker file we may get an error
#I have built my docker image from an already existing image, because tshark is needed for program to work stable,
#I had to do some kind of tinkering to create a stable environment for my script

#needed for fixing a bug
#in alpine linux docker while you are trying to build from a docker file if you are not a root user you will get the following error
#ERROR: Failed to open apk database: Permission denied
#this bug can be solved by making the user root 
#I have found the solution from ==> https://stackoverflow.com/questions/50727783/alpine-docker-error-unable-to-lock-database-permission-denied-error-failed-to
USER root

#our working directory
WORKDIR /app

#copy our script to the /app folder in the container
COPY main.py /app

# Install python/pip found it from ==> https://stackoverflow.com/questions/62554991/how-do-i-install-python-on-alpine-linux
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools pyshark
RUN apk update 

#This is used for reading command line arguments while running the docker image
#basically in the following command 
#sudo docker run -v /home/reaper/Documents/tempSandvine/capture.pcap:/pcapfiles/capture.pcap --rm 84936700d93a "!!!!/pcapfiles/capture.pcap!!!!""
#the argument that I have wrapped with "!!!! will be handled like a command line argument thanks to entrypoint
ENTRYPOINT ["python3","/app/main.py"]

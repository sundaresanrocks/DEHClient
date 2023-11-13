![](https://portal.ogc.org/files/?artifact_id=92076)
# DEHClient
As a core component of DEH, DEHClient functionality is to interoperate with BSE & DEH to gather resource consumption metrics and reports back the data to DEH EnablerHub.


## Table of contents
* [**Architecture**](#architecture)
* [**Technologies**](#technologies)
* [**Features**](#features)
* [**Requirements**](#requirements)
* [**PreRequisites**](#prerequisites)
* [**Setup local instance**](#setup-local-instance)
* [**Run application using docker-compose**](#run-application-using-docker-compose)
* [**How to use**](#how-to-use)
* [**Debugging**](#Debugging)
* [**Endpoints**](#endpoints)
* [**Workaround**](#workaround)
* [**Support team**](#support-team)
* [**Status**](#status)
* [**Release**](#release)
* [**Roadmap**](#roadmap)
* [**Licence**](#licence)
* [**Other Information**](#other-information)


## Architecture
To make the solution more flexible and easier to maintain, all components inside the DEH are developed as separate services and deployed as standalone Docker containers.


## Technologies

| Description                                     | Language | Version          |
| :---------------------------------------------- | :------: | :--------------: |
| [Flask web framework][1]                        | Python   | 1.1.2            |
| [Docker][3]                                     |          | 19.03.13         |

[1]: https://pypi.org/project/Flask/
[2]: https://www.mongodb.com/try/download/community
[3]: https://docs.docker.com/get-docker/


## Features

* Resource Discovery.
* Interoperability with DEH RRM & BSE.
* Generate resource consumption metrics of DEH Resource Containers and POST data periodically to RRM. 
* This metrics data is then visualized with DEH Dashboard.


## Requirements

* Installed Docker (version >= 19). 
* Installed Docker Compose.


## References

***  Brief description of Terms used across this document ***

* Docker Host: This is where you will be running DEH Service Containers. Once set up DEH Client will monitor these Containers, report back metrics periodically to DEH and the same will be visualized in DEH Dashboard.

* DEH Client: Communicates with Docker Host, generates Metrics for running DEH Service Containers, and reports back Metrics to DEH RRM.

* Secured Communication: Please refer to the attached document, <<HowToCreateSecureChannels_v2.pdf>> for more information on how to set up Docker Host and DEH Client over a secured channel.

* DEH Dashboard:
	Gitlab Documentation: https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/dehdashboard

* DEH Client.
	Gitlab Documentation: https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/dehclient

* DEH RRM.
	Gitlab Documentation: https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/resourceregistrymanagement

	API Documentation: https://deh-demeter.eng.it/swagger-ui/index.html?configUrl=/api-docs/swagger-config#/

* BSE.
	Gitlab Documentation: https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/bse/bse/-/blob/master/README.md

	API Documentation Test Instance : https://vm1.test.h2020-demeter-cloud.eu/api/swagger/

    API Documentation Production Instance : https://bse.h2020-demeter-cloud.eu/api/swagger/

## Prerequisites: 

Do these steps before starting DEHClient as a container.

* Step 1: Download the DEHClient project from GitLab:

    git clone https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/dehclient.git

* Step 2: Configure and set up Docker Host to communicate with DEH Client.

    Note: Users can choose how they intend to establish communication between Docker Host & DEH Client.
    
    This can be done by setting the below-mentioned attribute in the .env file before starting DEH Client Container.
    
    For open communication 
    
    > update attriute 'secure_connection = False' in .env file.  
    
    or 
    
    For secured connection 
    
    > update attriute 'secure_connection = True' in .env file. 

    Based on the choice made perform the below steps.

			$ cd dehclient

			$ vi ./.env
            
  
  	- For Open communication, Set in .env
    
    > update attriute 'secure_connection = False' in .env file.

    - Perform these steps on the Docker Host:
        
            $ sudo vi /lib/systemd/system/docker.service
        
		- Update: Configure to expose docker daemon service as API (Docker Engine API) over a specific port.

		  DEH Client will use this exposed Docker Engine API to  communicate and track resource consumption data of Docker Containers running on this Docker Host. Note : replace in the below line Docker_Host_IPV4 with IPV4 address. 
        
            ExecStart=/usr/bin/dockerd -H fd:// -H tcp://Docker_Host_IPV4:2375
        
        - Restart Service: 
        
            $ sudo systemctl daemon-reload
            
            $ sudo service docker restart
            
            $ sudo systemctl restart docker.service

        - Test if Docker Engine API is accessible over the exposed port, From a remote Docker host or on the same machine

          GET request, get Docker Engine Version number of remote Docker Host.
        
			Request: 

				$ curl "http://<<DockerHostIP/ Docker Engine Host IP>>:2375/version"
        
        	Or
        
            	$ wget -q -O - http://<<DockerHostIP/ Docker Engine Host IP>>:2375/version 

        	Response:

				{ "Platform": { "Name": "" }, "Components": [
				{ "Name": "Engine",
				"Version": "20.10.7",
				"Details": { "ApiVersion": "1.41", "Arch": "amd64",
				"BuildTime": "2021-08-04T19:07:47.000000000+00:00",
				"Experimental": "false", "GitCommit": "20.10.7-0ubuntu1~20.04.1",
				"GoVersion": "go1.13.8", "KernelVersion": "5.4.0-80-generic",
				"MinAPIVersion": "1.12", "Os": "linux" } ], ... }

    	Note here, that we have successfully enabled remote access to docker services of Docker Host. 

  - For Encrypted/ Secured communication,

    - Follow the instructions from the document -- HowToCreateSecureChannels_v2.pdf under section -- How to enable Docker Engine API on Docker Host: Secured.

	- Update the docker-compose.yml file with the local path of the CA cert files and the path where you intend to copy the same in the DEH Client container. 

			volumes:
				- ${PWD}/logs:/logs
				- /app/DEHClientEnabler/resource_monitor/ca.pem:/app/DEHClientEnabler/resource_monitor/ca.pem
				- /app/DEHClientEnabler/resource_monitor/key.pem:/app/DEHClientEnabler/resource_monitor/key.pem
				- /app/DEHClientEnabler/resource_monitor/cert.pem:/app/DEHClientEnabler/resource_monitor/cert.pem

* Step 3: Once Docker Host is setup, edit .env file and set below mentioned attributes,

  - Update Docker Host info. Set Docker Host Name & Docker Host IPV4 and Doker Engine exposed port number.
  
    docker_hostname=[[DockerHost Name]]

    docker_host=https://[[Docker Host IPV4]]:[[Port Number]]/

    e.g.

    docker_hostname=demeter-dev-1
    
    docker_host=https://10.0.10.132:2375/

  - Set/ configure the mode of communication between Docker Host & DEH Client.
    
      Option 1 : Set secure_connection=True if you intend to establish secured communication between Docker Host & DEH Client via TLS server/client certificates.

      Option 2: Set secure_connection=False if you intend to keep communication between Docker Host & DEH Client open.

      Note : By default, this is set to False ie secure_connection=False

  - Set option for Auto Registration with BSE.
    
      Option 1: auto_register_bse=True if you need to register any container/s automatically to BSE before generating metrics.

      Option 2: auto_register_bse=False if you do not want DEH Client to automatically register container/s to BSE.

      Note : By default, this is set to False ie auto_register_bse=False

  - Update DEH Account Details: Will be used to communicating with BSE & RRM - user with a Provider access privilege.

	  DEH_ACCOUNT_MAIL=[[User Name]]

	  DEH_ACCOUNT_PASS=[[Password]]

  - Set instance of ACS, DEH RRM & BSE.
      
      Note: ACS, RRM & BSE instances configured in .env will be used by DEHClient to generate authentication & authorization tokens, register Containers & look up for Container's registration data. The below parameters in the .env file need to be set before starting DEH Client as a container.

    - DEH RRM environment variables: 

    DEHEnablerHub_Host  --> DEH RRM instance.

    DEH_ACCOUNT_MAIL    --> This DEH account(with provider access)will be used to generate access tokens, To interface with DEH RRM & BSE endpoints. 

    DEH_ACCOUNT_PASS    --> DEH account password.

    ACS_Token_Request_Url --> ACS instance.

    Capability_Token_Url    --> Capability Token request Url.

    DEH_RRM_Proxy_URL       --> DEH RRM Proxy URL.

    - BSE environment variables:

    DEH_BSE_Host                    --> BSE instance.

    DEH_BSE_ACS_Token_Request_Url   --> ACS instance.

    DEH_BSE_Capability_Token_Url    --> Capability Token request Url.
    
    DEH_BSE_Proxy_URL               --> BSE Proxy URL.

* Step 4: To start tracking resource consumption metrics.

	Docker pull any DEH Resource (Docker Image) from the registry, which you intend to deploy as DEH service containers on Docker Host.
	DEH Client once deployed & set up, will monitor these container/s and report the metrics data to DEH RRM periodically. 

  - Manually pull by issuing Docker Pull command

        $ docker pull demeterengteam/estimate-animal-welfare-condition:candidate

    or

  - Use DEH Client exposed API to pull the Docker Image on to Docker Host. 
  	
	Note: Try Post deployment of DEH Client. DEH Client will pull the Docker Image locally onto the Docker Host, not on the remote DEH Client.

    Request : 
        
        curl -i -H "Content-Type: application/json" -X POST -d '{"image":"demeterengteam/estimate-animal-welfare-condition:candidate",  "tag":"candidate"}' http://<<DEH Client IP>>:<<DEH Client Port>>/api/v1/DEHClientEnabler/ResourceManagement/image/pull

    Response : 

        agement/image/pull
        HTTP/1.0 200 OK
        Content-Type: application/json
        Content-Length: 74
        Server: Werkzeug/1.0.1 Python/3.8.10
        Date: Thu, 02 Sep 2021 00:15:27 GMT

        "sha256:061f1ee69095e5e50b52db9c834ec99e9a73e569c5bfdbfbc4c540c3174fe349"

    ie sha256 hash of Docker Image if pull success.

* Step 5: Associate UID ie RRM registration ID to locally downloaded/ pulled DEH Resource Docker Image.

  - Note: This is an important step, Each DEH Resource/Enabler across Demeter is identified by a unique ID called UID /RRM ID ie unique registration ID generated when registering with RRM. 
    
    Some Useful RRM Endpoints to do this "Search for a DEH Resource by Filters", "List all DEH Resources"  and "Find DEH Resource by uid". Please refer deh-resource-api section under DEH RRM swagger documentation, link below
    
        https://deh-demeter.eng.it/swagger-ui/index.html?configUrl=/api-docs/swagger-config

        echo "FROM [[DEH Resource:tag]]" | sudo docker build --label uid="[[UID]]" -t "[[DEH Resource:tag]]" -

        e.g

        echo "FROM demeterengteam/estimate-animal-welfare-condition:candidate" | docker build --label uid="601ad929cc5e1504df125b04" -t "demeterengteam/estimate-animal-welfare-condition:candidate" -


  - Note : UID - 601ad929cc5e1504df125b04 registration ID of a test DEH Resource in production environment.

* Step 6: Deploy/run DEH Enabler: estimate-animal-welfare-condition:candidate, as a container on Docker Host.
    
        $ docker run -d --name <<"Container Name">> "demeterengteam/estimate-animal-welfare-condition:candidate"

* Step 6: Validate if UID is associated with local DEH Resource Docker Image & DEH Resource Container.

        $ docker inspect <<"DEH Resource Docker Image Name">>
        
    and

        $ docker inspect <<"DEH Resource Docker Container Name">>   

    Response: Validate if the UID is added as a label attribute.

        "Image": "sha256:a91c7ea76a8644bc7936f23cbb99dc87046b577b305938417678c8a4283b733a",
        "Volumes": null,
        "WorkingDir": "/usr/local/tomcat",
        "Entrypoint": null,
        "OnBuild": null,
        "Labels": {
            "com.docker.compose.config-hash": "691f76150dddc59f81a69ee1b85a6212cc020592cee8fc69e10402932e934353",
            "com.docker.compose.container-number": "1",
            "com.docker.compose.oneoff": "False",
            "com.docker.compose.project": "estimateanimalwelfareconditionmodule",
            "com.docker.compose.project.config_files": "docker-compose.yml",
            "com.docker.compose.project.working_dir": "C:\\Users\\luidicorra\\Desktop\\EstimateAnimalWelfareConditionModule",
            "com.docker.compose.service": "animalwelfare",
            "com.docker.compose.version": "1.29.0",
            "uid": "601ad929cc5e1504df125b04"
        }

## Setup local instance

* Step 1: Download the  DEH Client project from GitLab.

        git clone https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/dehclient.git
        
* Step 2: Ensure you have a DEH account with provider access and configured appropriately in .env before starting the DEH Client solution as Docker Container.

* Step 3: Update DEH Client related attributes in the .env file (Refer to PreRequisites section - Step 2 of the Readme file).

        Docker Host.
        DEH Client API exposed port.
        secure_connection.
        DEH Account.
        RRM instance. 
        BSE instance.

* Step 4: DEH Client once deployed locally, automatically discovers Docker Containers deployed on the configured Docker Host, generates metrics and POSTs periodically to DEH.

### Run application using docker-compose

* Based on the choice made for open or secured communication between Docker Host and DEH Client.

Option 1: Open Communication: 

    * Download the  DEH Client project from GitLab.
        
            $ git clone https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/dehclient.git

    * Update all environment variables related to DEH Client can be updated in `.env` file.
        
        For open communication between Docker Host & DEH Client, set 
        
        secure_connection=False

    * Set up Docker Host to communicate with DEH Client, please refer Pre-Requisites section above, Step 2.

    * Run `docker-compose up` to run Docker Compose with server image and MongoDB.

    * If you want to run DEH Client as a container in the background, run the next command `docker-compose up -d`

            $ cd ./dehclient/

            $ docker-compose up -d | docker-compose logs -f


Option 2: Secured Communication:

    * Download the  DEH Client project from GitLab.
        
            $ git clone https://gitlab.h2020-demeter-cloud.eu/demeterproject/wp3/demeterenablerhub/dehclient.git

    * Update all environment variables related to DEH Client can be updated in `.env` file.

      For open communication between Docker Host & DEH Client, set

        secure_connection=True

    * Create CA certificates and configure Docker Host to accept only secured connections. Follow the instructions from the document attached (HowToCreateSecureChannels_v2.pdf).    


    * Update `docker-compose.yml` to copy client certificates to DEH Client container before starting the same. Please ignore this step if you want to opt for open communication between Docker Host & DEH Client.

        Note: For example, you have the required certificate files under dir: `/etc/ssl/certs/`

        $ vi docker-compose.yml

            volumes:
            - ${PWD}/logs:/logs
            - /etc/ssl/certs/ca.pem:/app/DEHClientEnabler/resource_monitor/ca.pem
            - /etc/ssl/certs/key.pem:/app/DEHClientEnabler/resource_monitor/key.pem
            - /etc/ssl/certs/cert.pem:/app/DEHClientEnabler/resource_monitor/cert.pem


    * Run `docker-compose up` to run Docker Compose with server image and MongoDB.

    * If you want to run DEH Client as a container in the background, run the next command `docker-compose up -d`

            $ cd ./dehclient/

            $ docker-compose up -d | docker-compose logs -f

## How to use

* Once deployed, DEH Client will periodically (every 20 seconds) will discover and generate metrics of all DEH Resource containers running on the Docker Host which are associated with UID.

* Thus generated metrics data will be written/updated to the MongoDB instance running along.(DB: DEHClient & metrics).

* DEH Client will POST the metrics periodically to RRM via RRM metrics API. Records for those containers which are successfully POSTed are deleted from MongoDB (Memory Management).

    Note 1: DEH Client will attempt to POST metrics to RRM once in every 8 hours. Till then DEH Client will write/update metrics data for all containers in MongoDB.

    Note 2: Records for those containers which were failed to POST to RRM, due to reasons like Temporary issues connecting to RRM, etc, will not be deleted from MongoDB and will be reattempted to POST to the next try.

    Note 3: Records older than 1 day and failed to be posted to RRM will be deleted from MongoDB.  

* You can also use DEHClient exposed APIs to track/generate Resource Consumption Metrics of any Containers which are hosted on the given Docker Host.

## Debugging:

###   Pre-Deployment Issues: Common issues which could occur during DEH Client deployment:

 - Common issues and possible resolution: 

   - Issue 1: Unable to pull DEH Client image from GitLabs registry because of permission issues or unable to download the image.

     Possible Resolution: The issue may be that you have logged into a different registry. Do the following steps

     - First, log out from the any registry

            $ docker logout
            $ docker login registry.gitlab.com

     - This will prompt for login. With valid credentials, the login is successful.
     - Then attempt to run docker-compose to start DEH Client Container.


   - Issue 2: Set up Docker Host, Failed to restart DockerD service after updating /lib/systemd/system/docker.service

     Possible Resolution: 
     
     - Ensure the Docker service file is updated as below:

            $ sudo vi /lib/systemd/system/docker.service

     - Update dockerd as below:

            ExecStart=dockerd -H fd:// -H tcp://<<Docker Host IPV4>>:2375

     - Restart Service:
    
            $ sudo systemctl daemon-reload

            $ sudo service docker restart

            $ sudo systemctl restart docker.service

     - Post restart, test if Docker Engine API is accessible over the exposed port, From a remote host, or on the same machine

     - GET request, get Docker Engine Version number of remote Docker Host.
    
     - Request:

            $ curl "http://<<DockerHostIP/ Docker Engine Host IP>>:2375/version"

     - Ensure the port number in this case 2375 is open and not used by another service. 


###   Post Deployment Issues: Once deployed, You can use DEH Client's exposed APIs to:

  - Get the list of all Running containers on configured Docker Host.

    e.g.

        curl -X GET "http://[[DEH Client Container IPV4]]:[[DEH Client Port]]/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter?status=running"
        
    
  - Monitor DEH Client container logs manually or use DEH Client log parser exposed API to look for logs

    e.g.

        curl -X GET "http://[[DEH Client Container IPV4]]:[[DEH Client Port]]/api/v1/DEHClientEnabler/ResourceConsumption/get_container_logs?container=[[DEH Client Container ID]]&pattern=ERROR"

    or

        curl -X GET "http://[[DEH Client Container IPV4]]:[[DEH Client Port]]/api/v1/DEHClientEnabler/ResourceConsumption/get_container_logs?container=[[DEH Client Container ID]]&pattern=POST&tail=100"

    or

        curl -X GET "http://[[DEH Client Container IPV4]]:[[DEH Client Port]]/api/v1/DEHClientEnabler/ResourceConsumption/get_container_logs?container=[[DEH Client Container ID]]&pattern=POST&tail=100"


Note: You can use log parsing API to explore logs of other Docker Containers running on Docker Host. Just replace [[DEH Client Container ID]] in the GET request with the Docker ID/ Name of the respective Docker Container.


## Endpoints

* Use with request like:

  	Syntax : 
	  
	curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/<<"endpoint">>"


**List of endpoints**


| URL                                   | Type         | Used for                                         | Input                                | Output                                                  |
| :-----------------------------        | :----------: | :----------------------------------------------- | :----------------------------------- | :------------------------------------------------------ |
| **/ResourceConsumption/individual/metrics?name=** | **GET** | Generate resource consumption stats.       |Parameter: name (Resource Name)       | Resource consumption stats of a given resource. |
| **/ResourceConsumption/individual/metrics?uid=**  | **GET** | Generate resource consumption stats.       |Parameter: uid (deh_id RRM id)        | Resource consumption stats of a given resource. |
| **/ResourceConsumption/get_resources_filter?name=** | **GET** | Get list of Containers matching filter. |Parameter: name (search pattern ie part of Container name) | List of all Containers matching name pattern |
| **/ResourceConsumption/get_resources_filter?status=** | **GET** | Get list of Containers matching filter.|Parameter: status (running, exited, restarting, paused) |  List of all Containers with given status |
| **/ResourceConsumption/get_resources_filter?ancestor=** | **GET** | Get list of Containers matching filter.|Parameter: ancestor (image name or id) | Get List of Containers which are instances of the given image.  |


## Other Information 

* In case if you need more information/ details on your DEH account, please follow steps below,

	- First generate x-subject-token:

	   	Request: 

			$ curl -s -D - -o /dev/null -X POST   https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens -H 'content-type: application/json' -d '{"name": "<<'Registered Email'>>", "password": "<<'PASSWORD'>>"}'
	   
    	Response: 
	
			HTTP/1.1 201 Created
			Cache-Control: no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0
			**X-Subject-Token: 91cb1202-59ac-4e9c-871a-b8e4febc13ee**
			Content-Type: application/json; charset=utf-8
			Content-Length: 141
			ETag: W/"8d-yJcfLWskMp/ynaoLm+Jn35UunCI"
			Set-Cookie: session=eyJyZWRpciI6Ii8ifQ==; path=/; expires=Mon, 29 Mar 2021 16:47:00 GMT; secure; httponly
			Set-Cookie: session.sig=TqcHvLKCvDVxuMk5xVfrKEP-GSQ; path=/; expires=Mon, 29 Mar 2021 16:47:00 GMT; secure; httponly
			Date: Mon, 29 Mar 2021 15:47:00 GMT
			Connection: keep-alive


	- GET Token info:
		
		Request:
	   	
			$ curl -X GET   https://acs.bse.h2020-demeter-cloud.eu:5443/v1/auth/tokens -H 'x-auth-token: <<"Generated x-subject-token">>' -H 'x-subject-token: <<"Generated x-subject-token">>'
	
		Response : 

			{"access_token": "43c50983-d671-463c-ba10-7d024f2029fe",
			"expires": "2021-03-29T13:37:07.000Z",
			"valid": true,
			"User": {
			"scope": [],
			**"id": "32194dbf-03de-4ac5-a91b-c959ceb97358"**,
			"username": "<<'Registered UserName'>>"
			"email": "<<'Registered Email'>>",
			"date_password": "2021-01-27T12:23:26.000Z",
			"enabled": true,
			"admin": false}}

## Workaround 

To establish secure communication between DEH Client & DockerHost(Resource Host), need to create server & client certificates manually.
Please follow the document "Securing Docker Engine API.pdf".


$`\textcolor{red}{ \text{(Attention: In future releases these certificates genration will be automated)}\ } `$

## Support team
* [Steven Davy (Development and Delivery)](sdavy@wit.ie) 
* [Sundaresan Venkatesan (Development and Delivery)](sundaresan.venkatesan@wit.ie) 


## Release

V1

 | :dart: [Roadmap](roadmap.md) |
| ------------------------------------------ |


## Status
Project is: _in progress_ 


## License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

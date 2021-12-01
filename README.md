![](https://portal.ogc.org/files/?artifact_id=92076)
# DEHClient
As a core component of DEH, DEHClient functionality is to interfaces with BSE & DEH EnablerHub.
Enables to gather resource consumption metrics and reports back the data to DEH EnablerHub.


## Table of contents
* [**Architecture**](#architecture)
* [**Technologies**](#technologies)
* [**Features**](#features)
* [**Requirements**](#requirements)
* [**PreRequisites**](#prerequisites)
* [**Setup local instance**](#setup-local-instance)
* [**Run application using docker-compose**](#run-application-using-docker-compose)
* [**How to use**](#how-to-use)
* [**Endpoints**](#endpoints)
* [**Usage**](#usage)
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

* DEH Client being a core component of DEH, the main functionality is to generate Resource Consumption Metrics of Enablers deployed as Docker Container on a given Docker Host and report back to DEH.

* DEH Client generated Resource Consumption Metrics will be reported back to DEH periodically.​

* For security, DEH Client establishes a secured channel of communication with Docker Host.​

* Configurable option to enable user to choose between 

  - Option 1: Secure connection Docker Host & DEH Client. or,

  - Option 2: Open connection between Docker Host & DEH Client.

* Container attributes tracked as part of metrics includes.​

	Volume = Memory Usage & CPU Usage.​

	Time Usage = Duration of running containers.

* Generate Resource Consumption Metrics for a requeted Container/s of DEH Resources deployed on Docker Host.

* Periodically Report the generated metrics data back to Resource Registry Management and the metrics thus reported are visualized in DEH Dashboard.

* Get Containers deployed on Docker Host matching one of the filters below:
    
  - name=<<"part of container name as string">>​.
      
  - Status=<<"based on one of the container status restarting, running, paused, exited">>​.
    
  - ancestor=<<"Instances of an image e.g, demeterengteam/estimate-animal-welfare-condition:candidate">>.

* Get a given Container's log lines:
  
  - pattern=<<"part of container log">>​.
  
  - tail=<<"last few lines">>​.

  - pattern & tail parameters can also be used in combination.

 Note :
  * Docker Host: Where DEH Enablers/ Containers will be deployed.​

	Enabler e.g., estimate-animal-welfare-condition:candidate​

	& Container Name: estimate-animal-welfare-pilot1​

  * Docker Host is the Host running Docker daemon service & the same is exposed as Docker Engine API. Where DEH Resources will be deployed as service containers.

  * DEH Enablers - DEH Solution Developed as Docker Images and uploaded to Registry.

  * All DEH Resources (Docker Image) has to be associated with an UID - Unique 


## Requirements

* Installed Docker (version >= 19). 
* Installed Docker Compose.


## References

* DEH Dashboard:
	Gitlab Documentation: https://gitlab.com/demeterproject/wp3/demeterenablerhub/dehdashboard

* DEH Client.
	Gitlab Documentation: https://gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient

* DEH RRM.
	Gitlab Documentation: https://gitlab.com/demeterproject/wp3/demeterenablerhub/resourceregistrymanagement

	API Documentation: https://deh-demeter.eng.it/swagger-ui/index.html?configUrl=/api-docs/swagger-config#/

* BSE.
	Gitlab Documentation: https://gitlab.com/demeterproject/wp3/bse/bse/-/blob/master/README.md

	API Documentation: https://vm1.test.h2020-demeter-cloud.eu/api/swagger/


## Pre-Requisites: 

Do these steps before starting DEHClient as a container.

* Step 1: Download DEHClient project from gitlabs:

		git clone https://gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient.git

 	Pull DEH Client Docker Image locally from the registry : 
	 
		docker pull registry.gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient:latest

* Step 2: Edit .env file and set below mentioned attributes like, 

  - Set medium/ mode of communication between Docker Host & DEH Client.
  	
	  Option 1 : set secure_connection=True if you intend to establish secured communication between Docker Host & DEH Client via TLS server / client certificates.

      Reference Document : dehclient/Securing_Docker_Engine_API.pdf

	  Please refer to the section of the document - How to enable Docker Engine API on Docker Host: Secured. 

      Option 2: set secure_connection=False if you intend to keep communication between Docker Host & DEH Client open.

      Please refer to the section of the document - How to enable Docker Engine API on Docker Host: Open Connection - Unsecured/ Open

  - Set option for Auto Registration with BSE.
    
      Option 1: auto_register_bse=True if you need to register any container/s automatically to BSE before generating metrics.

      Option 2: auto_register_bse=False if you do not want DEH Client to automatically register container/s to BSE.

  - Set instance of ACS, DEH RRM & BSE.
      
      Note: ACS, RRM & BSE instances configured in .env will be used by DEHClient to generate authentication & authorization token, register Containers & look up for Container's registration data. The below parameters in the .env file need to be set before starting DEH Client as a container.

	- DEH RRM environment variables: 

	  DEHEnablerHub_Host	--> DEH RRM instance.

	  DEH_ACCOUNT_MAIL   	--> This DEH account(with provider access)will be used to generate access tokens, To interface with DEH RRM & BSE endpoints. 

	  DEH_ACCOUNT_PASS   	--> DEH account password.

	  ACS_Token_Request_Url --> ACS instance.

	  Capability_Token_Url 	--> Capability Token request Url.

	  DEH_RRM_Proxy_URL    	--> DEH RRM Proxy URL.

	- BSE environment variables:

	  DEH_BSE_Host					--> BSE instance.

	  DEH_BSE_ACS_Token_Request_Url	--> ACS instance.

	  DEH_BSE_Capability_Token_Url	--> Capability Token request Url.
	  
	  DEH_BSE_Proxy_URL				--> BSE Proxy URL.

* Step 3: Setup Docker Host to communicate with DEH Client, Based on the attribute 'secure_connection' value set in .env (Refer : Step 2)
  
  Reference Document : dehclient/Securing_Docker_Engine_API.pdf

  - Open communication, 
    - Warning: It's strongly recommended to set the communication secured. With an open connection, there is a high risk as we expose Docker Admin level access / Docker Engine API over TCP.

    - Follow the instructions from the document -- Securing Docker Engine API.pdf under section - How to enable Docker Engine API on Docker Host: Open Connection - Unsecured/ Open.

  - Encrypted/ Secured communication,
    - Follow the instructions from the document -- Securing Docker Engine API.pdf under section - How to enable Docker Engine API on Docker Host: Secured.


* Step 4: Docker pull any DEH Resource (Docker Image) from the registry, which you intend to deploy as DEH service containers on Docker Host.
DEH Client once deployed & set up, will monitor these container/s and report the metrics data to DEH RRM periodically. 

  - Manually pull by issuing Docker Pull command

    sudo docker pull demeterengteam/estimate-animal-welfare-condition:candidate

  - Use DEH Client exposed API to pull the Docker Image on to Docker Host. (Note: Post deployment of DEH Client)
    
	Note: DEH Client will pull the Docker Image locally onto the Docker Host, not on the remote DEH Client.
	Request : curl -i -H "Content-Type: application/json" -X POST -d '{"image":"demeterengteam/estimate-animal-welfare-condition:candidate","tag":"candidate"}' http://<<DEH Client IP>>:<<DEH Client Port>>/api/v1/DEHClientEnabler/ResourceManagement/image/pull

	Response : 
		agement/image/pull
		HTTP/1.0 200 OK
		Content-Type: application/json
		Content-Length: 74
		Server: Werkzeug/1.0.1 Python/3.8.10
		Date: Thu, 02 Sep 2021 00:15:27 GMT

		"sha256:061f1ee69095e5e50b52db9c834ec99e9a73e569c5bfdbfbc4c540c3174fe349"

	ie sha256 hash of Docker Image if pull success.

* Step 5: Associate UID ie RRM registration ID to locally downloaded/ pulled Docker Image.

  - Note: This is an important step, Each DEH Resource/Enabler across Demeter is identified by a unique ID called UID /RRM ID ie unique registration ID generated when registering with RRM. 

  - Challenge:

    - There is no streamlined process on how a user can register the DEH Resource with RRM and validate if the resource is already registered.
  
    - If persisted incorrectly, this might lead to a mismatch of DEH Resource/s being tracked. 

  - Interim solution:

    - As a workaround until the process of registration is streamlined, is to have the pilot of DEH Client manually associate UID to the DEH Resource (downloaded in Step 3:) manually before starting DEH Resource as container/s. 

    - Add UID as docker label to already pulled image, so any container/s created from this image will have UID associated and don't have to do for all the container instances. This can be done using the Docker command or using DEH Client API.
    
    - Before associated UID as a label, validate using DEH RRM API if the UID to be associated is valid i.e. registered to appropriate DEH Resource. 
	Some Useful RRM Endpoints to do this "Search for a DEH Resource by Filters", "List all DEH Resources"  and "Find DEH Resource by uid". Please refer deh-resource-api section under DEH RRM swagger documentation, link below
    
    	https://deh-demeter.eng.it/swagger-ui/index.html?configUrl=/api-docs/swagger-config

		echo "FROM [[DEH Resource:tag]]" | sudo docker build --label uid="[[UID]]" -t "[[DEH Resource:tag]]" -

      	e.g

    	echo "FROM demeterengteam/estimate-animal-welfare-condition:candidate" | sudo docker build --label uid="610411e8c56e160279440661" -t "demeterengteam/estimate-animal-welfare-condition:candidate" -


  	Note : UID - 610411e8c56e160279440661 registration ID of a test DEH Resource in production environment.

* Deploy/run DEH Enabler: estimate-animal-welfare-condition:candidate, as a container on Docker Host.
	
	$ sudo docker run -d --name <<"Container Name">> "demeterengteam/estimate-animal-welfare-condition:candidate"


## Setup local instance

1. Login into the registry 

	$ sudo docker login registry.gitlab.com

  Provide your credentials

  Successful Login Respons: Login Succeeded

2. Pull DEH Client Docker Image from the registry :

	$ docker image pull registry.gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient:latest

3. Download the  DEH Client project from GitLab.

	git@gitlab.com:demeterproject/wp3/demeterenablerhub/dehclient.git

4. Get a DEH account with provider access and have them updated in the .env file.

5. Update .env file with relevant attributes like (Refer PreRequisites section - Step 2 of the readme file).
    Docker Host.
	DEH Client API exposed port.
	DEH Account.
    RRM instance. 
    BSE instance.

6. Update docker-compose.yml with the locally downloaded DEH Client Image Name like:
  	dehclient:
    	image: registry.gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient:latest


### Run application using docker-compose

* Based on the choice made for open or secured communication between Docker Host and DEH Client

Option 1: Open Communication: 

	* All environment variables related to DEH Client can be updated in `.env` file.
	* Run `docker-compose up` to run Docker Compose with server image and MongoDB.
	* If you want to run containers in background run next command `docker-compose up -d`


Option 2: Secured Communication:

	* Step 1: Login into the registry 

		$ sudo docker login registry.gitlab.com

		Provide your credentials

		Successful Login Respons: Login Succeeded

	* Step 2: Pull DEH Client Docker Image from the registry :

		$ docker image pull registry.gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient:latest

	* Step 3: Pull mongo:4.2.8 Image and start a mongo instance as a Docker Container:

		$ docker image pull mongo:4.2.8
		$ docker run -d --name dehclient-db "mongo:4.2.8"

	* Step 4: Update mongo DB details in the .env vaiable : MongoDB variables section.
		e.g,.
		MONGO_DB_PORT=27017
		MONGO_DB_EXPOSED_PORT=27017
		MONGODB_DATABASE=DEHClient
		MONGODB_HOST=dehclient_db


	* Step 5: Create DEH Client container, supplying env variables as a file: 
	
		docker create --name <<"ContainerName">> --env-file <<"env file name">> registry.gitlab.com/demeterproject/wp3/demeterenablerhub/dehclient:v1

	* Step 6: Copy relevant Client certificates to the container before starting the container. 
	
		Note: Please refer to the document "Securing Docker Engine API.pdf" to establish a secure connection between Docker Client & Docker Host.

		$ docker cp <<"CertPath">>/ca.pem <<"ContainerName">>:/app/DEHClientEnabler/resource_monitor

		$ docker cp <<"CertPath">>/key.pem <<"ContainerName">>:/app/DEHClientEnabler/resource_monitor

		$ docker cp <<"CertPath">>/cert.pem <<"ContainerName">>:/app/DEHClientEnabler/resource_monitor

	* Step 7: Start DEH Client as a container (-i in case of interactive mode)
	
		$ sudo docker start -i <<"ContainerName">>


## How to use

* Once your local instance of DEH Client is up, you can use DEHClient exposed APIs to track/generate Resource Consumption Metrics of any Containers which are hosted on the given Docker Host.


## Endpoints

* Use with request like:

  Syntax : curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/<<"endpoint">>"


**List of endpoints**


| URL                                   | Type         | Used for                                         | Input                                | Output                                                  |
| :-----------------------------        | :----------: | :----------------------------------------------- | :----------------------------------- | :------------------------------------------------------ |
| **/ResourceConsumption/individual/metrics?name=** | **GET** | Generate resource consumption stats.       |Parameter: name (Resource Name)       | Resource consumption stats of a given resource. |
| **/ResourceConsumption/individual/metrics?uid=**  | **GET** | Generate resource consumption stats.       |Parameter: uid (deh_id RRM id)        | Resource consumption stats of a given resource. |
| **/ResourceConsumption/get_resources_filter?name=** | **GET** | Get list of Containers matching filter. |Parameter: name (search pattern ie part of Container name) | List of all Containers matching name pattern |
| **/ResourceConsumption/get_resources_filter?status=** | **GET** | Get list of Containers matching filter.|Parameter: status (running, exited, restarting, paused) |  List of all Containers with given status |
| **/ResourceConsumption/get_resources_filter?ancestor=** | **GET** | Get list of Containers matching filter.|Parameter: ancestor (image name or id) | Get List of Containers which are instances of the given image.  |


## Usage

* If in .env file auto_register=yes,

	Case 1: If GET metrics request by UID, 
	
	Request: curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics?uid=605f580337801e241cf995ec" | json	
	
	- Stages	
		
	 	- Get Container Name associated with UID from RRM, Get RRM info.

  		- Identify if corresponding Container is hosted on the given Docker Host.

  		- Check if the Container is registered with BSE.

  		- if not registered, auto register with BSE & Get BSE info.

  		- Produce requested Container's Resource Consumption Metrics.
		
		
	Case 2: If GET metrics request by Container Name,
	
	Request: curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics?name=estimate-animal-welfare-condition12" | json

	- Stages	
		
  		- Identify if corresponding Container is hosted on the given Docker Host.

  		- Check if the Container is registered with DEH RRM & BSE.

  		- if not registered, auto register with DEH RRM & BSE, Get RRM & BSE info.

  		- Produce requested Container's Resource Consumption Metrics.

		
* If in .env file auto_register=no,

	Case 1: If GET metrics request by UID, 
	
	Request: curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics?uid=605f580337801e241cf995ec" | json	
	
	- Stages	
		
	 	- Get Container Name associated with UID from RRM, Get RRM info.

  		- Identify if corresponding Container is hosted on the given Docker Host.

  		- Check if the Container is registered with BSE, Get BSE info.

  		- Produce requested Container's Resource Consumption Metrics.
		
		
	Case 2: If GET metrics request by Container Name,
	
	Request: curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/individual/metrics?name=estimate-animal-welfare-condition12" | json

	- Stages	
		
  		- Identify if corresponding Container is hosted on the given Docker Host.

  		- Check if the Container is registered with DEH RRM & BSE, Get RRM & BSE info.

  		- Produce requested Container's Resource Consumption Metrics.
	

* Get list of Containers matching filter,

  - Filter by name:

	Request : curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter?name=animal-welfare"
	
	Response : 
			["estimate-animal-welfare-condition13", 
			"estimate-animal-welfare-condition12", 
			"estimate-animal-welfare-condition11", 
			"estimate-animal-welfare-condition-v1", 
			"estimate-animal-welfare-condition10", 
			"estimate-animal-welfare-condition9"]


  - Filter by status of the container : Valid Container Status (running, exited, restarting, paused)
	
	Request : curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter?status=running"

  - Filter by ancestor (List all instances/ Containers of the image given)
	
	Request: curl -X GET "http://<<"container_ip">>:<<"port">>/api/v1/DEHClientEnabler/ResourceConsumption/get_resources_filter?ancestor=demeterengteam/estimate-animal-welfare-condition:candidate"

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

* Establish secured communication between Docker Host & DEHClient. Please refer to the document "Securing Docker Engine API.pdf" to establish a secure connection between Docker Client & Docker Host.

  - On Docker Host, Make the Docker daemon only accept connections from clients providing a certificate trusted by your CA and port.

	$ sudo vi /lib/systemd/system/docker.service 

	Update the docker.service file as below: 

	ExecStart=dockerd --tlsverify --tlscacert=<<"CertPath">>/ca.pem --tlscert=<<"CertPath">>/server-cert.pem --tlskey=<<"CertPath">>/server-key.pem -H=0.0.0.0:2376 

  - Restart service: 

	$ sudo systemctl daemon-reload 

	$ sudo service docker restart 

	$ sudo systemctl restart docker.service

  - To test if the connection is successful: From a remote docker CLI or Client
	
	$ docker --tlsverify --tlscacert=<<"CertPath">>/ca.pem --tlscert=<<"CertPath">>/cert.pem --tlskey=<<"CertPath">>/key.pem -H=$DOCKER_DAEMON_HOST:2376 version
	
	Note : To test from a remote docker CLI or Client, copy these cert files ie ca.pem, cert.pem & key.pem to the Client and try connecting to Docker Host CLI.

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

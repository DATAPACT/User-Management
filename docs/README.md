# Contract Tool

Powered by

[![UoSLOGO](./images/UniSouthampton.png)](https://dips.soton.ac.uk/#home)


## **General Description**

Repository for the FastAPI implementation of a User Management Service that enables 1) the creation of contracts, 2) the storage and management of contracts and 3) functions to operate for specific contracts.

## **Commercial Information**


| Organisation (s) | License Nature | License |
| ---------------  | -------------- | ------- |
| University of Southampton  | Open Source | MIT Licence |



## **How To Install**


### Requirements

Docker

### Software

FastAPI, Python

### Summary of installation steps

#### Docker Setup Instructions

* Configure the files as mentioned above
* Build and run the docker container as usual
  * run MongoDB in Docker with your app
    * build docker-compose.yml file
    * docker compose up --build 
    * or  docker compose up -d --build (running on background)
    * docker compose down

  
* The API documentation will then be available under the `/docs` sub path, such as `http://127.0.0.1:8800/docs`

#### Manual Installation Instructions
If you are not using docker, you can run the project as follows:
* Configure the files as mentioned above
* Install MongoDB database
* Install required libraries using `pip install -r requirements.txt`
* Run FastAPI  `python user_management_api.py` from the project directory
* See the API here `http://127.0.0.1:8800/docs`


 

# Running the IDS with Docker

Our IDS works with PCAP files, so before testing it, you need to add your desired PCAP file into the `dataset` folder. These files can be found in the source files section on this webpage: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset). You will need to open the SharePoint link provided by UNSW and pcpas are availabe there.

If you just want to run our approach, we have included a small PCAP file to demonstrate the workflow.

To make the setup more efficient and ensure all necessary components are packaged together, we created a `Dockerfile` and a script (`run.sh`) that automates the process of building and running the Docker container.

---

## **1. Running the System**

### **Container Setup and Processing Instructions**  
Follow these steps to log into the Docker container, process the PCAP file, and generate alerts.

#### **Step 1: Run the Docker Container**  
Execute the following script to start the container: 

```sh
./run.sh
```

---

## **2. Log into the Container**  

To log into the container interactively, use the following command:

```sh
docker run -it --rm feature-extraction bash
```

---

## **3. Verifying the Working Directory**  

Once inside the container, ensure the following files and directories are present in the working directory:

- `CaseManagement`  
- `dataset`  
- `generate_alerts.py`  
- `model`  
- `pcaps_parsing_script.py`
- `requirements.txt`  

---

## **4. Converting the PCAP File to CSV**  

The first step is to convert the PCAP file into CSV format using the `pcaps_parsing_script.py` script.  

Run the following command:

```sh
python3 pcaps_parsing_script.py
```

This script generates a folder named `final_csvs`, containing files named using the schema `(name_of_the_pcap)_unsw_nb15_final.csv` inside the container's filesystem. Additionally, logs created by Zeek, Argus, and other related tools will be saved.

---

## **5. Generating Alerts from the CSV File**  

With the CSV file available, the next step is to analyze the network traffic for potential threats.  

Run the following command:

```sh
python3 generate_alerts.py
```

Executing `generate_alerts.py` will process the data and detect possible port scans. After execution, a new folder named `alerts` will be created. Inside it, there will be folders for each parsed file, containing JSON files with information about flows detected as port scans and marked as alerts.

---

## **6. Copying Alerts for Case Management**  

After completing the previous steps, the generated alerts are stored into the `CaseManagement/alerts` folder. Please proceed to the next `README.md` in the `CaseManagement` folder.


If you want to train the model yourself (using all the data from UNSW), you need to download the other three source UNSW files named `UNSW-NB15_x.csv` (where `x` is 1-4). These files can be found in the source files section on this webpage: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset). You will need to open the SharePoint link provided by UNSW. The three additional files are located in the "CSV Files" folder within the SharePoint directory.

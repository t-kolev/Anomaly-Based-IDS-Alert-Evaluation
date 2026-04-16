
# IDS DFIR-IRIS Integration Readme

Please first install IRIS on your system using the guide below. If you have already installed it, you can skip to the "Execution Guide"
## **Installation Guide**

### **1. Set Up DFIR-IRIS**
Follow these steps to deploy DFIR-IRIS using Docker:

1. **Clone the `iris-web` Repository**:
   ```bash
   git clone https://github.com/dfir-iris/iris-web.git
   cd iris-web
   ```

2. **Check Out the Latest Tagged Version**:
   ```bash
   git checkout v2.4.16
   ```

3. **Set Up the Environment File**:
   Copy the example `.env` file and configure it as needed:
   ```bash
   cp .env.model .env
   ```

4. **Pull the Docker Images**:
   Pull the latest Docker images for DFIR-IRIS:
   ```bash
   docker compose pull
   ```

5. **Start the DFIR-IRIS Containers**:
   Run the following command to bring up the DFIR-IRIS services:
   ```bash
   docker compose up
   ```

   DFIR-IRIS will now be accessible at `https://127.0.0.1` / `(https://hostip)`

 
---

### **IMPORTANT!**  
Upon first start, an administrator account will be created. The password is printed in the console output and can be found by searching for:  

**`WARNING :: post_init :: create_safe_admin`**  

Alternatively, you can define an admin password at the first start using the **IRIS_ADM_PASSWORD** environment variable in the `.env` file. This setting has no effect once the administrator account is created.  

**If you don't find the password in the logs,** try running:  
`docker compose logs app | grep "WARNING :: post_init :: create_safe_admin"`  

If the logs indicate that **user administrator is already created**, it means the instance has already started once and the password has been set. Check the recovery options here https://docs.dfir-iris.org/latest/operations/access_control/authentication/

IRIS should now be available on the host interface, port **443**, using HTTPS by default. You can access it at `https://127.0.0.1` or `(https://hostip)`

### **IMPORTANT!**  
Ensure all steps outlined in the IDS folder’s README have been completed.

Critical: The alerts.json has been copied inot files into the designated alerts folder before proceeding. There are some alerts already there if you only want to test our approach.

## Execution Guide 
### **1. Run the `setup.py` Script located in the `CaseManagement` directory**
Once DFIR-IRIS is running, make sure you replaced the **API_KEY** (Your key can be found under "My Settings") in `setup.py` and execute script to initialize Case Template. 

```bash
python setup.py
```

This script need to be used only the first time you use IRIS, as it only loads the created from us templates.

---

### **2. Import Custom Attributes for Cases**
To enable custom attributes for case management:

1. Log in to the DFIR-IRIS web interface.
2. Navigate to **Advanced > Custom Attributes > Cases**.
3. Import the provided custom attributes configuration file or manually define the required attributes.

Ensure all attributes required by the `create_case.py` script are configured correctly.

This needs to be used only the first time you use IRIS, as it only loads the custom attributes we crated.

---

## Creating Cases in DFIR-IRIS
### **Run the `create_case.py` Script located in the `CaseManagement` directory**
Replace **API_KEY** (Your key can be found under "My Settings") in `create_case.py` and use it to automate the creation of cases and handling of associated evidence.

```bash
python create_case.py
```

This script:
- Reads alerts from an EVE JSON file.
- Automatically creates cases in DFIR-IRIS with custom attributes.
- Adds evidence metadata and links it to the appropriate case.

---

## **Features**
- **Automated Case Creation**: Streamlines the creation of cases in DFIR-IRIS from external data sources.
- **Custom Attributes Integration**: Enhances case management with user-defined attributes.
- **Evidence Handling**: Adds metadata for evidence files and links them to cases.

---
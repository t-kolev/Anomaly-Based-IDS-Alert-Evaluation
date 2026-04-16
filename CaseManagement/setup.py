import requests
import json
import logging

LOG_FORMAT = '%(asctime)s %(levelname)s %(funcName)s: %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO, datefmt='%Y-%m-%d %I:%M:%S')
log = logging.getLogger(__name__)

# API details
BASE_URL = "https://host.docker.internal"  # Replace with your DFIR-IRIS base URL
API_KEY = "X1Fl6YVZdeP2uChFAg29MAMU-671vuAq0VxhQzSMxsT9mscrjubiGd3LWmepi6SPtfdcIoI5fxc4RYbM_qMY-A"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}


def setup(template_file):
    """
    Sends a POST request to create a case template in DFIR-IRIS, with content loaded from a file.
    """
    url = f"{BASE_URL}/manage/case-templates/add"

    try:
        # Load template content from the file
        with open(template_file, "r") as file:
            template_content = json.load(file)

        # Prepare payload
        payload = {
            "case_template_json": json.dumps(template_content, indent=4)  # Convert template to a JSON string
        }

        log.info("Sending POST request to create the case template.")
        response = requests.post(url, headers=HEADERS, json=payload, verify=False)  # Set verify=True for valid SSL
        response.raise_for_status()  # Raise an error for bad status codes
        log.info("Case template created successfully.")
        log.info(f"Response: {response.json()}")
    except FileNotFoundError:
        log.error(f"Template file '{template_file}' not found.")
    except json.JSONDecodeError as e:
        log.error(f"Error decoding JSON from file '{template_file}': {e}")
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to create case template: {e}")
        if response is not None:
            log.error(f"Response: {response.text}")


def main():
    template_file = "templates/low-case-template.json"
    setup(template_file)
    template_file = "templates/mid-case-template.json"
    setup(template_file)
    template_file = "templates/full-case-template.json"
    setup(template_file)


if __name__ == "__main__":
    main()

import os
import json
import logging
import requests
import xmltodict
import tarfile
import xml.etree.ElementTree as ET
from urllib.parse import urlencode


SPLUNK_BASE_FETCH_APP_BY_ENTRY_ID = "https://apps.splunk.com/api/apps/entriesbyid/{app_name}"


def get_splunk_base_session_token():
    """
    This method will generate Splunk base session token, where we fetch our required TA
    :return: None
    """
    # self.log.info("\nGenerating Authentication Token from SplunkBase\n")

    # Data payload for fetch splunk base session token
    payload = urlencode(
        {
            "username": '',
            "password": '',
        }
    )

    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "cache-control": "no-cache",
    }

    response = requests.request(
        "POST",
        "https://splunkbase.splunk.com/api/account:login/",
        data=payload,
        headers=headers,
    )

    token_value = ""

    if not response or response.status_code != 200:
        error_message = (
            f"Error occurred while executing the rest call for splunk base authentication api ,"
            f"{response.content}"
            f"Username : {os.environ.get('SPLUNK_BASE_USERNAME')} Password: {os.environ.get('SPLUNK_BASE_PASSWORD')}"
        )
        # self.log.error(error_message)
        raise Exception(error_message)
    else:
        root = ET.fromstring(response.content)
        token_value = root.find("{http://www.w3.org/2005/Atom}id").text.strip()
        # self.log.info("Successfully fetch splunkBase authentication token")
    return token_value


def fetch_cim_field_report(file_name='.ta_cim_mapping/cim_field_report.json'):
    try:
        with open(file_name) as file_content:
            cim_field_report = json.load(file_content)
            return cim_field_report
    except Exception as error:
        error_message = f"Unexpected error occurred while reading file - {error}"
        logging.error(error_message)


def fetch_latest_version_of_app(app_name):
    response = requests.request("GET", SPLUNK_BASE_FETCH_APP_BY_ENTRY_ID.format(app_name=app_name))
    dict_data = xmltodict.parse(response.content)

    if type(dict_data.get("feed").get("entry")) == list:
        for obj in dict_data.get("feed").get("entry"):
            for skey in obj.get("content").get("s:dict").get("s:key"):
                if skey.get("@name") == "islatest" and skey.get("#text") == "True":
                    return os.path.basename(obj.get("link").get("@href"))

    else:
        for skey in (dict_data.get("feed").get("entry").get("content").get("s:dict").get("s:key")):
            if skey.get("@name") == "islatest" and skey.get("#text") == "True":
                return os.path.basename(dict_data.get("feed").get("entry").get("link").get("@href"))


def download_app_from_splunkbase(app_name, app_id):
    app_version = fetch_latest_version_of_app(app_name)
    auth_token = get_splunk_base_session_token()

    print("\nDownloading package from splunkbase\n")
    url = 'https://splunkbase.splunk.com/app/' + str(app_id) + '/release/' + app_version + "/download/"
    headers = {
        'Cookie': 'sessionid=' + auth_token
    }
    response = requests.get(url, headers=headers, allow_redirects=True)
    filename = app_name + '.tgz'
    print("Downloading file from url = " + url + " and storing in file = " + filename)
    if response.status_code == 200:
        # write-binary usage intentional here
        with open(filename, 'wb') as fh:  # noqa: X714
            fh.write(response.content)

    # extract file
    file = tarfile.open(filename)
    file.extractall('./')
    file.close()


def get_dataset_fields(obj):
    fields = []

    # Append all fields
    for field_obj in obj.get('fields'):
        fields.append(field_obj.get('fieldName'))

    # Append all calculated fields
    for calculated_obj in obj.get('calculations'):
        for output_field in calculated_obj.get('outputFields'):
            fields.append(output_field.get('fieldName'))

    return list(set(fields))


def fetch_datamodel_and_dataset():
    pass


def main():
    # download_app_from_splunkbase('Splunk_SA_CIM', '1621')

    for filename in os.listdir('cim_field_reports'):
        cim_field_report = {}
        cim_ta_mapping = {}
        if filename.endswith(".json"):
            cim_field_report = fetch_cim_field_report('./cim_field_reports/' + filename)

            cim_summary = {}
            for eventtype_name, eventtype_info in cim_field_report.get('fieldsreport').items():

                #print(eventtype_name)
                tags = eventtype_info.get('tags')   
                datamodel_fields = []
                if (eventtype_info.get('tags') is not None):
                    for datamodel_file in os.listdir('Splunk_SA_CIM/default/data/models'):
                        dm = None
                        try:
                            with open('Splunk_SA_CIM/default/data/models/' + datamodel_file) as file_content:
                                dm = json.load(file_content)
                        except Exception as error:
                            error_message = f"Unexpected error occurred while reading file {datamodel_file} - {error}"
                            logging.error(error_message)

                        for obj in dm.get('objects'):
                            if(obj.get('comment') is not None and obj.get('comment').get('tags') is not None):
                                
                                if set(obj.get('comment').get('tags')).issubset(set(tags)):
                                    datamodel_fields.extend(get_dataset_fields(obj))
                                    cim_summary[f"{dm['modelName']}:{obj['objectName']}"] = {}
                                    cim_summary[f"{dm['modelName']}:{obj['objectName']}"][eventtype_name] = [{}]
                                    for i in range (0,len(eventtype_info.get('summary'))):
                                        cim_summary[f"{dm['modelName']}:{obj['objectName']}"][eventtype_name][0]["fields"] = sorted(list(set(datamodel_fields) & set(eventtype_info.get('summary')[i].get('fields'))))

                                


                
            cim_ta_mapping["ta_name"] = cim_field_report.get('ta_name')
            cim_ta_mapping["sourcetypes"] = cim_field_report.get("sourcetypes")
            cim_ta_mapping["cimsummary"] = cim_summary
            cim_ta_mapping["fieldsummary"] = cim_field_report.get("fieldsummary")
            with open(f'ta_cim_mapping_{cim_ta_mapping["ta_name"].get("name")}.json', 'w') as outfile:
                json.dump(cim_ta_mapping, outfile, indent=4)
                


if __name__ == "__main__":
    main()

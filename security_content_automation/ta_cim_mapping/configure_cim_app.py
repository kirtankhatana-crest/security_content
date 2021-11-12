import os
import tarfile
from urllib.parse import urlencode

import requests
import xmltodict
import xml.etree.ElementTree as ET

SPLUNK_BASE_FETCH_APP_BY_ENTRY_ID = (
    "https://apps.splunk.com/api/apps/entriesbyid/{app_name}"
)


class CIMApp:
    def __init__(self) -> None:
        self.SPLUNKBASE_USERNAME = os.environ.get("SPLUNKBASE_USERNAME")
        self.SPLUNKBASE_PASSWORD = os.environ.get("SPLUNKBASE_PASSWORD")

    def get_splunk_base_session_token(self):
        """
        This method will generate Splunk base session token, where we fetch our required TA
        :return: None
        """
        # self.log.info("\nGenerating Authentication Token from SplunkBase\n")

        # Data payload for fetch splunk base session token
        payload = urlencode(
            {
                "username": f"{self.SPLUNKBASE_USERNAME}",
                "password": f"{self.SPLUNKBASE_PASSWORD}",
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

        if not response or response.status_code != 200:
            error_message = (
                f"Error occurred while executing the rest call for splunk base authentication api ,"
                f"{response.content}"
            )
            raise Exception(error_message)
        else:
            root = ET.fromstring(response.content)
            token_value = root.find("{http://www.w3.org/2005/Atom}id").text.strip()

        return token_value

    def fetch_latest_version_of_app(self, app_name):
        response = requests.request(
            "GET", SPLUNK_BASE_FETCH_APP_BY_ENTRY_ID.format(app_name=app_name)
        )
        dict_data = xmltodict.parse(response.content)

        if type(dict_data.get("feed").get("entry")) == list:
            for obj in dict_data.get("feed").get("entry"):
                for skey in obj.get("content").get("s:dict").get("s:key"):
                    if skey.get("@name") == "islatest" and skey.get("#text") == "True":
                        return os.path.basename(obj.get("link").get("@href"))

        else:
            for skey in (
                dict_data.get("feed")
                .get("entry")
                .get("content")
                .get("s:dict")
                .get("s:key")
            ):
                if skey.get("@name") == "islatest" and skey.get("#text") == "True":
                    return os.path.basename(
                        dict_data.get("feed").get("entry").get("link").get("@href")
                    )

    def download_app_from_splunkbase(self, app_name, app_id):
        auth_token = self.get_splunk_base_session_token()
        app_version = self.fetch_latest_version_of_app(app_name)

        print("\nDownloading package from splunkbase\n")
        url = (
            "https://splunkbase.splunk.com/app/"
            + str(app_id)
            + "/release/"
            + app_version
            + "/download/"
        )

        headers = {"Cookie": "sessionid=" + auth_token}
        response = requests.get(url, headers=headers, allow_redirects=True)
        filename = app_name + ".tgz"

        print(
            f"Splunkbase URL = {url}"
            f"Splunk_CIM Name = {filename}"
            f"Downloading file..."
        )

        if response.status_code == 200:
            # write-binary usage intentional here
            with open(filename, "wb") as fh:  # noqa: X714
                fh.write(response.content)

        # extract file
        file = tarfile.open(filename)
        file.extractall("./")
        file.close()

        # Remove tar file after extraction
        os.remove(filename)

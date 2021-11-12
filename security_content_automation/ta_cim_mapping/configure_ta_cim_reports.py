import json
import logging
import os
import shutil

import git


class TACIMReports:
    def __init__(self) -> None:
        self.github_token = "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"
        self.repo_org = "splunk"
        self.repo_name = "ta-cim-field-reports"


    def clone_ta_cim_field_reports_repo(self):
        url = (
            "https://"
            + self.github_token
            + ":x-oauth-basic@github.com/"
            + self.repo_org
            + "/"
            + self.repo_name
        )
        if os.path.exists(self.repo_name):
            shutil.rmtree(self.repo_name)

        git.Repo.clone_from(url, to_path=self.repo_name, branch="main")


    def fetch_cim_field_report(self, file_name):
        try:
            with open(file_name) as file_content:
                cim_field_report = json.load(file_content)
                return cim_field_report
        except Exception as error:
            error_message = f"Unexpected error occurred while reading file - {error}"
            logging.error(error_message)

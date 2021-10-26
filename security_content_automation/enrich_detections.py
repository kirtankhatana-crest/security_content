# 1. Take github token, branch_name from user to raise a PR for enriched detection of security_content repo
# 2. Iterate through each detection file
# 3. For each detection iterate through ta_cim_mapping report
# 4. map detection file and ta_cim_mapping reports and finalise the TA required for particular detection
# 5. Add the list of TA's in detection file
# 6. Create a new branch and raise an MR for it

import os
import git
import yaml
import json
import time
import argparse
import logging


def fetch_ta_cim_mapping_report(file_name):
    try:
        with open(file_name) as file_content:
            cim_field_report = json.load(file_content)
            return cim_field_report
    except Exception as error:
        error_message = f"Unexpected error occurred while reading file. Error: {error}"
        logging.error(error_message)


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def map_required_fields(cim_summary, required_fields):
    for dataset in cim_summary.values():
        for eventtype in dataset.values():
            for item in eventtype:
                cim_fields = item.get('fields', [])
                if set(required_fields).issubset(set(cim_fields)):
                    return True

    return False


def enrich_detection_file(file, ta_list, security_content_repo_obj):
    # file_path = 'security_content/detections/' + test['detection_result']['detection_file']
    detection_obj = load_file(file)
    detection_obj['tags']['supported_tas'] = ta_list

    with open(file, 'w') as f:
        yaml.dump(detection_obj, f, sort_keys=False, allow_unicode=True)


def main():

    parser = argparse.ArgumentParser(description="Enrich detections with relevant TA names")
    parser.add_argument("-scr", "--security_content_repo", required=False, default="kirtankhatana-crest/security_content",
                        help="specify the url of the security content repository")
    parser.add_argument("-scb", "--security_content_branch", required=False, default="develop",
                        help="specify the security content branch")
    parser.add_argument("-gt", "--github_token", required=False, default='a2lydGFua2hhdGFuYS1jcmVzdDpLa3JUZWNoQDMyMQ==',
                        help="specify the github token for the PR")

    args = parser.parse_args()
    security_content_repo = args.security_content_repo
    security_content_branch = args.security_content_branch
    github_token = args.github_token

    # clone security content repository
    security_content_repo_obj = git.Repo.clone_from(
        'https://' + github_token + ':x-oauth-basic@github.com/' + security_content_repo, "security_content",
        branch=security_content_branch)

    # iterate through every detection files
    for subdir, dirs, files in os.walk('security_content/detections/cloud'):
        for file in files:
            filepath = subdir + os.sep + file
            ta_list = []

            if filepath.endswith("abnormally_high_number_of_cloud_infrastructure_api_calls.yml"):

                detection_obj = load_file(filepath)
                required_fields = detection_obj.get('tags', {}).get('required_fields')

                for ta_cim_mapping_file in os.listdir('ta_cim_mapping_reports'):
                    ta_cim_map = fetch_ta_cim_mapping_report('./ta_cim_mapping_reports/' + ta_cim_mapping_file)
                    result = map_required_fields(ta_cim_map['cimsummary'], required_fields)

                    if result:
                        ta_list.append(ta_cim_map.get('ta_name').get('name'))

            if ta_list:
                enrich_detection_file(filepath, ta_list, security_content_repo_obj)

            security_content_repo_obj.index.add([changed_file_path])

    security_content_repo_obj.index.commit('Updated detection files with supported TA list.')

    # security_content_repo_obj.config_writer().set_value("user", "name", "Detection Testing Service").release()
    # security_content_repo_obj.config_writer().set_value("user", "email", "research@splunk.com").release()

    epoch_time = str(int(time.time()))
    branch_name = "security_content_automation_" + epoch_time
    repo.git.checkout("-b", branch_name)

    security_content_repo_obj.git.push('--set-upstream', 'origin', branch_name)
    pr = repo.create_pull(title="Enrich Detection PR " + branch_name, body='This is a dummy PR', head=branch_name, base="develop")


if __name__ == "__main__":
    main()

import json
import logging
import os


from configure_cim_app import CIMApp
from configure_ta_cim_reports import TACIMReports


class CIMFieldReport:
    def __init__(self) -> None:
        self.splunk_cim_app = "Splunk_SA_CIM"
        self.splunk_cim_app_id = "1621"
        self.ta_cim_field_repo = "ta-cim-field-reports"
        self.CIM_DM_PATH = "Splunk_SA_CIM/default/data/models"
        self.CIM_FIELD_REPORT_PATH = "ta-cim-field-reports/latest"

    def get_dataset_fields(self, obj):
        fields = []

        try:
            # Append all fields
            for field_obj in obj.get("fields"):
                fields.append(field_obj.get("fieldName"))

            # Append all calculated fields
            for calculated_obj in obj.get("calculations"):
                for output_field in calculated_obj.get("outputFields"):
                    fields.append(output_field.get("fieldName"))

        except:
            pass

        return list(set(fields))

    def get_datamodel_fields(dm_data):
        datamodel_feilds = set()
        dm_tag_fields_dict = dict()
        dm_objectName = set()
        dm_parentName = None
        dm_name = dm_data.get("modelName")

        try:
            for dm_object in dm_data.get("objects"):
                tags = dm_object.get("comment").get("tags")

                while dm_parentName not in ["BaseEvent", "BaseSearch"]:
                    dm_parentName = dm_object.get("parentName")
                    dm_objectName.add(dm_object.get("objectName"))

                    for fields_info in dm_object.get("fields"):
                        datamodel_feilds.add(fields_info.get("fieldName"))

                    for calculation_obj in dm_object.get("calculations"):
                        for outputFields_obj in calculation_obj.get("outputFields"):
                            datamodel_feilds.add(outputFields_obj.get("fieldName"))

                    for tag in tags:
                        dm_tag_fields_dict[tag] = dict()
                        dm_tag_fields_dict[tag]["fields"] = list(datamodel_feilds)
                        dm_tag_fields_dict[tag]["datatype"] = dm_name
                        dm_tag_fields_dict[tag]["datatype"] = dm_name

                    if dm_parentName in dm_objectName:
                        for dm_obj in dm_data.get("objects"):
                            if dm_parentName == dm_obj.get("objectName"):
                                dm_object = dm_obj
                                continue

                dm_parentName = None

        except:
            return None

        return dm_tag_fields_dict


    def get_SA_cim_field_data(self):
        datamodel_dir = "downloads/Splunk_SA_CIM/default/data/models"
        sa_cim_field_dict = dict()
        skipped_files = list()
        for datamodel_file in os.listdir(datamodel_dir):
            dm_file_path = os.path.join(datamodel_dir, datamodel_file)
            with open(dm_file_path) as datamodel_file_obj:
                dm_data = json.load(datamodel_file_obj)
                if self.get_datamodel_fields(dm_data):
                    sa_cim_field_dict.update(self.get_datamodel_fields(dm_data))

        with open("artifacts/sa_cim_fields.json", "w") as cim_field_file_obj:
            json.dump(sa_cim_field_dict, cim_field_file_obj, indent=2)

        print(skipped_files)

        return sa_cim_field_dict

    
    def get_ta_datamodel_fields(ta_report_data):
        ta_tag_field_mapping = dict()
        ta_tag_field_mapping["cimsummary"] = dict()
        ta_fieldsreport = ta_report_data.get("fieldsreport")
        for eventtype_name, event_type_data in ta_fieldsreport.items():
            ta_tag_field_mapping["cimsummary"][eventtype_name] = dict()
            tags = event_type_data.get("tags")
            fields_summary = event_type_data.get("summary")

            if tags is not None:
                for tag in tags:
                    ta_tag_field_mapping["cimsummary"][eventtype_name][tag] = fields_summary

        return ta_tag_field_mapping


    def get_ta_metadata(ta_report_data):
        ta_metadata_dict = dict()
        ta_metadata_dict["ta_name"] = ta_report_data.get("ta_name")
        ta_metadata_dict["sourcetypes"] = ta_report_data.get("sourcetypes")
        ta_metadata_dict["fieldsummary"] = ta_report_data.get("fieldsummary")

        return ta_metadata_dict

    def get_prerequisites(self):

        # Download Splunk_SA_CIM from splunkbase
        if not os.path.exists(self.splunk_cim_app):
            get_cim_app_obj = CIMApp()
            get_cim_app_obj.download_app_from_splunkbase(
                self.splunk_cim_app, self.splunk_cim_app_id
            )

        # Download ta-cim-field-reports repo
        if not os.path.exists(self.ta_cim_field_repo):
            ta_cim_field_report_obj = TACIMReports()
            ta_cim_field_report_obj.clone_ta_cim_field_reports_repo()

    def get_TA_cim_field_data():
        ta_cim_field_dict = dict()
        TA_cim_field_report_dir = "ta-cim-field-reports/latest"
        for filename in os.listdir(TA_cim_field_report_dir):
            if filename.endswith(".json"):
                ta_cim_field_dict[filename] = dict()
                TA_cim_field_filepath = os.path.join(TA_cim_field_report_dir, filename)
                with open(TA_cim_field_filepath) as ta_cim_field_report_obj:
                    ta_report_data = json.load(ta_cim_field_report_obj)
                    ta_metadata = get_ta_metadata(ta_report_data)
                    ta_dm_fields = get_ta_datamodel_fields(ta_report_data)
                    ta_cim_field_dict[filename].update(ta_metadata)
                    ta_cim_field_dict[filename].update(ta_dm_fields)

        return ta_cim_field_dict

    def map_cim_fields(sa_cim_mapping_fields, ta_cim_field_data):
        cim_field_data = copy.deepcopy(ta_cim_field_data)
        for eventtype_name, eventtype_data in ta_cim_field_data.get("cimsummary").items():
            for tag, tag_data in eventtype_data.items():
                for tag_object in tag_data:
                    ta_cim_fields = tag_object.get("fields")
                    try:
                        mapped_fields = list(
                            set(sa_cim_mapping_fields.get(tag).get("fields"))
                            & set(ta_cim_fields)
                        )
                        cim_field_data["cimsummary"][eventtype_name][tag][0][
                            "fields"
                        ] = mapped_fields
                        dm_name = "{}:{}".format(
                            sa_cim_mapping_fields.get(tag).get("datatype"), tag
                        )
                        cim_field_data["cimsummary"][eventtype_name][
                            dm_name
                        ] = cim_field_data["cimsummary"][eventtype_name].pop(tag)
                    except:
                        pass

        return cim_field_data

    def get_cim_field_report():
        fetch_ta_cim_field_report_repo()
        sa_cim_mapping_fields = get_SA_cim_field_data()
        ta_cim_mapping_fields = get_TA_cim_field_data()

        for filename, filedata in ta_cim_mapping_fields.items():

            mapped_data = map_cim_fields(sa_cim_mapping_fields, filedata)

            with open(f"artifacts/{filename}", "w") as cim_field_report_obj:
                json.dump(mapped_data, cim_field_report_obj, indent=4)


    def generate_ta_cim_field_reports(self):
        self.get_prerequisites()

        for filename in os.listdir("ta-cim-field-reports/latest"):
            cim_field_report = {}
            cim_ta_mapping = {}
            if filename.endswith(".json"):
                CIM_FIELD_REPORT_FILE = os.path.join(self.CIM_FIELD_REPORT_PATH, filename)
                cim_field_report = self.fetch_cim_field_report(CIM_FIELD_REPORT_FILE)

                cim_summary = {}
                for eventtype_name, eventtype_info in cim_field_report.get(
                    "fieldsreport"
                ).items():

                    # print(eventtype_name)
                    tags = eventtype_info.get("tags")
                    datamodel_fields = []
                    if eventtype_info.get("tags") is not None:
                        for datamodel_file in os.listdir(self.CIM_DM_PATH):
                            dm = None
                            try:
                                DM_FILE_PATH = os.path.join(self.CIM_DM_PATH, datamodel_file)
                                with open(DM_FILE_PATH) as file_content:
                                    dm = json.load(file_content)
                            except Exception as error:
                                error_message = f"Unexpected error occurred while reading file {datamodel_file} - {error}"
                                logging.error(error_message)

                            for obj in dm.get("objects"):
                                if (
                                    obj.get("comment") is not None
                                    and obj.get("comment").get("tags") is not None
                                ):

                                    for tag in obj.get("comment").get("tags"):
                                        if tag in set(tags):
                                            datamodel_fields.extend(
                                                self.get_dataset_fields(obj)
                                            )
                                            cim_summary[
                                                f"{dm['modelName']}:{obj['objectName']}"
                                            ] = {}
                                            cim_summary[
                                                f"{dm['modelName']}:{obj['objectName']}"
                                            ][eventtype_name] = [{}]
                                            for i in range(
                                                0, len(eventtype_info.get("summary"))
                                            ):
                                                cim_summary[
                                                    f"{dm['modelName']}:{obj['objectName']}"
                                                ][eventtype_name][0]["fields"] = sorted(
                                                    list(
                                                        set(datamodel_fields)
                                                        & set(
                                                            eventtype_info.get(
                                                                "summary"
                                                            )[i].get("fields")
                                                        )
                                                    )
                                                )

                cim_ta_mapping["ta_name"] = cim_field_report.get("ta_name")
                cim_ta_mapping["sourcetypes"] = cim_field_report.get("sourcetypes")
                cim_ta_mapping["cimsummary"] = cim_summary
                cim_ta_mapping["fieldsummary"] = cim_field_report.get("fieldsummary")
                with open(
                    f'cim_field_reports/ta_cim_mapping_{cim_ta_mapping["ta_name"].get("name")}.json',
                    "w",
                ) as outfile:
                    json.dump(cim_ta_mapping, outfile, indent=4)


if __name__ == "__main__":
    cim_field_report_obj = CIMFieldReport()
    cim_field_report_obj.generate_ta_cim_field_reports()

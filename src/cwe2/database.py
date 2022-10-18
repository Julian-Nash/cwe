import csv
import os
from typing import List, Union

from cwe2.categories import CWECategory
from cwe2.mappings import cwe_src_mapping, external_mapping
from cwe2.weakness import Weakness


class Database:
    base_path = os.path.abspath(os.path.dirname(__file__))
    software_development_db = open(
        os.path.join(base_path, cwe_src_mapping["software_development"]["csv_file"])
    )
    hardware_design_db = open(
        os.path.join(base_path, cwe_src_mapping["hardware_design"]["csv_file"])
    )
    research_concepts_db = open(
        os.path.join(base_path, cwe_src_mapping["research_concepts"]["csv_file"])
    )
    cwe_top_25_2022_db = open(
        os.path.join(base_path, external_mapping["CWE_top_25_2022"]["csv_file"])
    )
    owasp_top_ten_2021_db = open(
        os.path.join(base_path, external_mapping["OWASP_top_ten_2021"]["csv_file"])
    )

    def get(self, cwe_id: Union[int, str], category: str = None) -> Weakness:
        """Returns a CWE Weakness object"""
        cwe_obj = None
        cwe_category_mapper = {
            CWECategory.SOFTWARE_DEVELOPMENT: self.software_development_db,
            CWECategory.HARDWARE_DESIGN: self.hardware_design_db,
            CWECategory.RESEARCH_CONCEPTS: self.research_concepts_db,
        }

        for cwe_category in (
            {cwe_category_mapper[category]} if category else cwe_category_mapper.values()
        ):
            cwe_category.seek(0)
            reader = csv.DictReader(cwe_category)
            for row in reader:
                if row.get("CWE-ID") == str(cwe_id):
                    cwe_obj = list(row.values())[0:-1]
                    break

        if not cwe_obj:
            raise Exception(f"Invalid CWE ID {cwe_id} - {category or ''}")

        return Weakness(*cwe_obj)

    def get_top_25_cwe(self) -> List[Weakness]:
        """Returns a list of all CWE Top 25 (2022) Weakness objects"""
        self.cwe_top_25_2022_db.seek(0)
        weakness_list = []
        reader = csv.DictReader(self.cwe_top_25_2022_db)
        for row in reader:
            weakness_list.append(Weakness(*list(row.values())[0:-1]))
        return weakness_list

    def get_owasp_top_ten_2021(self) -> List[Weakness]:
        """Returns a list of all OWASP Top Ten (2021) Weakness objects"""
        self.owasp_top_ten_2021_db.seek(0)
        weakness_list = []
        reader = csv.DictReader(self.owasp_top_ten_2021_db)
        for row in reader:
            weakness_list.append(Weakness(*list(row.values())[0:-1]))
        return weakness_list

    def is_cwe_top_25(self, cwe_id: Union[int, str]) -> bool:
        """Returns True if Weakness object in a Top 25 CWE else False"""
        self.cwe_top_25_2022_db.seek(0)
        reader = csv.DictReader(self.cwe_top_25_2022_db)
        for row in reader:
            if row.get("CWE-ID") == str(cwe_id):
                return True
        return False

    def is_owasp_top_ten_2021(self, cwe_id: Union[int, str]) -> bool:
        """Returns True if Weakness object in a Top OWASP Ten (2021) else False"""
        self.owasp_top_ten_2021_db.seek(0)
        reader = csv.DictReader(self.owasp_top_ten_2021_db)
        for row in reader:
            if row.get("CWE-ID") == str(cwe_id):
                return True
        return False


database = Database()

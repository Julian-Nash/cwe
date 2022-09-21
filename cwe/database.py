from typing import List, Union

from cwe.categories import CWECategory
from cwe.mappings import cwe_src_mapping, external_mappings
import os
import pandas as pd

from cwe.weakness import Weakness


class Database:
    _instance = None

    base_path = os.path.abspath(os.path.dirname(__file__))
    software_development_db = pd.read_csv(
        os.path.join(base_path, cwe_src_mapping["software_development"]["csv_file"]), index_col=False)
    hardware_design_db = pd.read_csv(
        os.path.join(base_path, cwe_src_mapping["hardware_design"]["csv_file"]), index_col=False)
    research_concepts_db = pd.read_csv(
        os.path.join(base_path, cwe_src_mapping["research_concepts"]["csv_file"]), index_col=False)
    cwe_top_25_2022_db = pd.read_csv(
        os.path.join(base_path, external_mappings["CWE_top_25_2022"]["csv_file"]), index_col=False)
    owasp_top_ten_2021_db = pd.read_csv(
        os.path.join(base_path, external_mappings["OWASP_top_ten_2021"]["csv_file"]), index_col=False)

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
        return cls._instance

    def get(self, cwe_id: Union[int, str], category: str = None) -> Weakness:
        """ Returns a CWE Weakness object """
        cwe_category = {
            CWECategory.SOFTWARE_DEVELOPMENT: self.software_development_db,
            CWECategory.HARDWARE_DESIGN: self.hardware_design_db,
            CWECategory.RESEARCH_CONCEPTS: self.research_concepts_db
        }

        if not category:
            software_development_obj = self.software_development_db[self.software_development_db['CWE-ID'].values
                                                                    == int(cwe_id)]
            hardware_design_obj = self.hardware_design_db[self.hardware_design_db['CWE-ID'].values
                                                          == int(cwe_id)]
            research_concepts_obj = self.research_concepts_db[self.research_concepts_db['CWE-ID'].values
                                                              == int(cwe_id)]
            if not software_development_obj.empty:
                cwe_obj = software_development_obj
            elif not hardware_design_obj.empty:
                cwe_obj = hardware_design_obj
            elif not research_concepts_obj.empty:
                cwe_obj = research_concepts_obj
            else:
                raise Exception(f"Invalid cwe id {cwe_id}")
        else:
            cwe_obj = cwe_category[category][cwe_category[category]['CWE-ID'].values == int(cwe_id)]
            if cwe_obj.empty:
                raise Exception(f"Invalid cwe id {cwe_id} - for {category}")

        return Weakness(*cwe_obj.values[0])

    def get_top_25_cwe(self) -> List[Weakness]:
        """ Returns a list of all CWE Top 25 (2022) Weakness objects """
        weakness_list = []
        for cwe_id in self.cwe_top_25_2022_db['CWE-ID'].values:
            cwe_obj = self.cwe_top_25_2022_db[self.cwe_top_25_2022_db['CWE-ID'].values == int(cwe_id)]
            weakness_list.append(Weakness(*cwe_obj.values[0]))
        return weakness_list

    def get_owasp_top_ten_2021(self) -> List[Weakness]:
        """ Returns a list of all OWASP Top Ten (2021) Weakness objects """
        weakness_list = []
        for cwe_id in self.owasp_top_ten_2021_db['CWE-ID'].values:
            cwe_obj = self.owasp_top_ten_2021_db[self.owasp_top_ten_2021_db['CWE-ID'].values == int(cwe_id)]
            weakness_list.append(Weakness(*cwe_obj.values[0]))
        return weakness_list

    def is_cwe_top_25(self, cwe_id: Union[int, str]) -> bool:
        """ Returns True if Weakness object in a Top 25 CWE else False """
        return int(cwe_id) in self.cwe_top_25_2022_db['CWE-ID'].values

    def is_owasp_top_ten_2021(self, cwe_id: Union[int, str]) -> bool:
        """ Returns True if Weakness object in a Top OWASP Ten (2021) else False """
        return int(cwe_id) in self.owasp_top_ten_2021_db['CWE-ID'].values


if __name__ == "__main__":
    obj1 = Database()
    obj2 = Database()
    print('Are they the same object?', obj1.owasp_top_ten_2021_db is obj2.owasp_top_ten_2021_db)

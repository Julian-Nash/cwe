from cwe.weakness import Weakness

from typing import Union, Any, Optional
import json
import os


class Database(object):

    def __init__(self):
        self._file: str = os.path.dirname(os.path.realpath(__file__))
        self._resources: str = os.path.join(self._file, "resources")

    def _load_db(self, file: Optional[str] = None) -> dict:

        file = file or "cwe.json"

        with open(os.path.join(self._resources, file), "rb") as fp:
            data = json.load(fp)

        return data

    def get(self,
            cwe_id: Union[int, str],
            default: Optional[Any] = None) -> Union[Weakness, Any]:
        """ Get a common weakness object

        Args:
            cwe_id: The CWE ID
            default: A default value to return if the ID is not found
        Returns:
            Weakness
        """

        data: dict = self._load_db()

        if not data.get(str(cwe_id)):
            return default

        return Weakness(**data[str(cwe_id)])

    def get_category(self, category: str) -> dict:
        """ Returns a dictionary of weaknesses from a category """

        category_map: dict = {
            "hardware_design": "hardware_design.json",
            "research_concepts": "research_concepts.json",
            "software_development": "software_development.json"
        }

        if category not in category_map:
            return {}

        return self._load_db(file=category_map[category])

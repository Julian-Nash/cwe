from cwe.weakness import Weakness

import json
from typing import Union, Any, Optional
import os

_file: str = os.path.dirname(os.path.realpath(__file__))
_resources: str = os.path.join(_file, "resources")


class Database(object):

    def _load_db(self, file: Optional[str] = None) -> dict:

        file = file or "cwe.json"

        with open(os.path.join(_resources, file), "rb") as fp:
            return json.load(fp)

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

from cwe.weakness import Weakness

from typing import Union, Any, Optional
import json
import os

TOP_25: tuple = (
    "119", "79", "20", "200", "125", "89", "416", "190", "352", "22", "78",
    "787", "287", "476", "732", "434", "611", "94", "798", "400", "772", "426",
    "502", "269", "295"
)


class Database(object):

    def __init__(self):
        self._file: str = os.path.dirname(os.path.realpath(__file__))
        self._resources: str = os.path.join(self._file, "resources")
        self._count: int = 0

    def count(self) -> int:
        """ Returns the number of weaknesses in the DB """

        if self._count:
            return self._count
        else:
            self._load_db()
            return self._count

    def _load_db(self, file: Optional[str] = None) -> dict:
        """ Loads the database temporarily

        Args:
            file: The file to load (cwe.json)
        """

        file = file or "cwe.json"

        with open(os.path.join(self._resources, file), "rb") as fp:
            data = json.load(fp)
            self._count = len(data)

        return data

    def get_top_25(self):

        data = self._load_db()

        # r = {}
        #
        # for k, v in data.items():
        #     if str(k) in TOP_25:
        #         r[k] = v

        return {k: v for k, v in data.items() if str(k) in TOP_25}

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
        """ Returns a dictionary of weaknesses from a category

        Args:
            category: The category
        Returns
            dict: A dict of weaknesses from the category
        """

        category_map: dict = {
            "hardware_design": "hardware_design.json",
            "research_concepts": "research_concepts.json",
            "software_development": "software_development.json"
        }

        if category not in category_map:
            return {}

        return self._load_db(file=category_map[category])

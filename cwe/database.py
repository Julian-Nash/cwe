import gzip
import pickle

from cwe.weakness import Weakness
from cwe.mappings import top_25, cwe_src_mapping

import requests
from requests import Response

from typing import Union, Any, Optional, List
import tempfile
import logging
import zipfile
import json
import csv
import os
import io

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
base_path: str = os.path.abspath(os.path.dirname(__file__))


class Database(object):
    def __init__(self):
        self._count: int = 0

    @property
    def count(self) -> int:
        if not self._count:
            self._load_database()
        return self._count

    def _load_database(self) -> dict:
        """ Loads the gzipped pickle file """
        with gzip.open(os.path.join(base_path, "db.pickle.gz"), "rb") as f:
            data: dict = pickle.loads(f.read())
            # Update the self._count attr
            self._count = len(data)
            return data

    def _make_get_request(self, url: str) -> Response:
        logging.debug(f"Requesting data from url {url}")
        return requests.get(url)

    def _write_gzip(self, data: Union[str, bytes], filename: str) -> str:
        """ Writes data to a gzip file """

        if not filename.endswith(".gz"):
            filename = filename + ".gz"

        if not isinstance(data, bytes):
            data: bytes = data.encode("utf-8")

        logger.debug(f"Writing gzip {filename}")

        with gzip.open(filename, "wb") as f:
            f.write(data)

        return filename

    def _load_category_index(self) -> dict:
        """ Loads the category index """
        with open(os.path.join(base_path, "category_index.json"), "r") as fp:
            return json.load(fp)

    def _build_database(self):
        """ Builds the local database """

        db_dict: dict = {}
        category_index = self._load_category_index()

        for category, v in cwe_src_mapping.items():

            # Download the csv.zip
            data: Response = self._make_get_request(v["csv_uri"])

            # Unzip the csv into memory
            z = zipfile.ZipFile(io.BytesIO(data.content))

            # Get the filename
            filename = v["csv_uri"].split("/")[-1].split(".zip")[0]

            #  Save the csv to a tempfile
            with tempfile.TemporaryDirectory() as tmp:
                logger.debug(f"Extracting csv to {os.path.join(tmp, filename)}")
                z.extractall(path=tmp)

                # Open and read the csv
                with open(os.path.join(tmp, filename)) as csv_file:
                    logger.debug(f"Reading csv {filename}")
                    reader = csv.DictReader(csv_file)
                    for row in reader:
                        cwe_id: str = row["CWE-ID"]
                        # Update the category index
                        if cwe_id not in category_index[category]:
                            category_index[category].append()
                        #  Insert the cwe into it's respective category
                        db_dict[cwe_id] = row

        pickle_data: bytes = pickle.dumps(db_dict)

        with open("category_index.json", "w") as fp:
            logger.debug("Writing data to category_index.json")
            json.dump(category_index, fp)

        self._write_gzip(
            pickle_data, os.path.join(base_path, "db.pickle"),
        )

    def get_top_25(self) -> dict:
        """ Get a dict of the top 25 weaknesses

        Returns:
            dict
        """

        data = self._load_database()
        return {k: v for k, v in data.items() if str(k) in top_25}

    def get(
        self, cwe_id: Union[int, str], default: Optional[Any] = None
    ) -> Union[Weakness, Any]:
        """ Get a common weakness object

        Args:
            cwe_id: The CWE ID
            default: A default value to return if the ID is not found
        Returns:
            Weakness
        """

        db: dict = self._load_database()

        if not db.get(str(cwe_id)):
            return default

        return Weakness(**self._prepare_weakness(db[str(cwe_id)]))

    def _prepare_weakness(self, weakness: dict) -> dict:
        """ Prepares the raw weakness object for creating a new Weakness instance """
        return {
            k.replace(" ", "_").replace("-", "_").lower(): v
            for k, v in weakness.items()
            if k
        }

    def get_category(self, category: str) -> List[Weakness]:
        """ Returns a dictionary of weaknesses from a category

        Args:
            category: The category
        Returns
            dict: A dict of weaknesses from the category
        """

        category_map: dict = self._load_category_index()

        if category not in category_map:
            raise KeyError(f"Unknown category {category}")

        db: dict = self._load_database()

        resp: list = []

        for i in category_map[category]:
            resp.append(Weakness(**self._prepare_weakness(db[i])))

        return resp

    def get_all(self) -> List[Weakness]:
        """ Returns a list of all cwe Weakness objects """

        db: dict = self._load_database()

        resp: List[Weakness] = []
        for k, v in db.items():
            resp.append(Weakness(**self._prepare_weakness(v)))

        return resp


if __name__ == "__main__":

    db = Database()
    cwe = db.get(15)
    print(cwe)

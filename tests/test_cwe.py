from cwe import Database, CWECategory

import unittest


class TestReader(unittest.TestCase):

    def setUp(self):
        self.db = Database()

    def tearDown(self):
        ...

    def test_cwe_get_id(self):

        cwe = self.db.get(15)
        self.assertEqual(
            cwe.name, "External Control of System or Configuration Setting"
        )

    def test_weakness_to_dict_returns_dict_type(self):

        cwe = self.db.get(15)
        self.assertIs(type(cwe.to_dict()), dict)

    def test_weakness_to_dict_returns_dict_key(self):

        cwe = self.db.get(15)
        self.assertEqual(
            cwe.to_dict()["name"],
            "External Control of System or Configuration Setting"
        )

    def test_cwe_get_category(self):

        cwe = self.db.get_category(CWECategory.SOFTWARE_DEVELOPMENT.value)
        print(cwe)

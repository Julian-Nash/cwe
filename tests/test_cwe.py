from cwe import Database, CWECategory

import unittest


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.db = Database()

    def tearDown(self):
        ...

    def test_cwe_get_id(self):

        cwe = self.db.get(15)
        self.assertEqual(
            cwe.name, "External Control of System or Configuration Setting"
        )

    def test_database_count(self):

        count = self.db.count()
        self.assertEqual(count, 839)

    def test_get_top_25(self):

        top_25 = self.db.get_top_25()
        self.assertEqual(len(top_25), 25)

    def test_weakness_prop_name(self):

        cwe = self.db.get(15)
        self.assertEqual(
            cwe.name, "External Control of System or Configuration Setting"
        )

    def test_weakness_repr(self):

        cwe = self.db.get(15)
        self.assertEqual(str(cwe), "Weakness(cwe_id=15, name=External Control of System or Configuration Setting)")

    def test_weakness_get_prop(self):

        cwe = self.db.get(15)
        self.assertEqual(cwe.get("name"), "External Control of System or Configuration Setting")

    def test_weakness_get_prop_that_doesnt_exist(self):

        cwe = self.db.get(15)

        self.assertEqual(cwe.get("Foo"), None)

    def test_weakness_get_prop_that_doesnt_exist_with_default_supplied(self):

        cwe = self.db.get(15)

        self.assertEqual(cwe.get("Foo", False), False)

    def test_weakness_to_dict_returns_dict_type(self):

        cwe = self.db.get(15)
        self.assertIs(type(cwe.to_dict()), dict)

    def test_weakness_to_dict_returns_dict_key(self):

        cwe = self.db.get(15)
        self.assertEqual(
            cwe.to_dict()["name"],
            "External Control of System or Configuration Setting"
        )

    def test_cwe_get_category_with_bad_category(self):
        """ Should return an empty dict """

        cwe = self.db.get_category("foo")
        self.assertEqual(cwe, {})

    def test_cwe_get_software_development_category(self):

        cwe = self.db.get_category(CWECategory.SOFTWARE_DEVELOPMENT.value)
        self.assertEqual(type(cwe), dict)

    def test_cwe_get_hardware_design_category(self):

        cwe = self.db.get_category(CWECategory.HARDWARE_DESIGN.value)
        self.assertEqual(type(cwe), dict)

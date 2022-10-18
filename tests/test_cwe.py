from unittest import TestCase

from cwe2.categories import CWECategory
from cwe2.database import Database
from cwe2.weakness import Weakness


class TestDatabase(TestCase):
    def setUp(self):
        self.db = Database()

    def test_get_cwe_by_category(self):
        cwe = self.db.get(441, CWECategory.HARDWARE_DESIGN)
        self.assertEqual(cwe.cwe_id, "441")
        self.assertEqual(cwe.name, "Unintended Proxy or Intermediary ('Confused Deputy')")

    def test_cwe_get(self):
        cwe = self.db.get(15)
        self.assertEqual(cwe.cwe_id, "15")
        self.assertEqual(cwe.name, "External Control of System or Configuration Setting")
        self.assertEqual(cwe.weakness_abstraction, "Base")
        self.assertEqual(cwe.status, "Incomplete")
        self.assertEqual(
            cwe.description,
            "One or more system settings or configuration elements can be externally "
            "controlled by a user.",
        )
        self.assertEqual(
            cwe.extended_description,
            "Allowing external control of system settings can disrupt service "
            "or cause an application to behave in unexpected, and potentially "
            "malicious ways.",
        )

        self.assertEqual(
            cwe.related_weaknesses,
            "::NATURE:ChildOf:CWE ID:642:VIEW "
            "ID:1000:ORDINAL:Primary::NATURE:ChildOf:CWE ID:610:VIEW "
            "ID:1000::NATURE:ChildOf:CWE ID:20:VIEW ID:700:ORDINAL:Primary::",
        )
        self.assertEqual(cwe.related_attack_patterns, "::13::146::176::203::270::271::69::76::77::")

        self.assertEqual(
            cwe.potential_mitigations,
            "::PHASE:Architecture and Design:STRATEGY:Separation of "
            "Privilege:DESCRIPTION:Compartmentalize the system to have safe "
            "areas where trust boundaries can be unambiguously drawn. Do not "
            "allow sensitive data to go outside of the trust boundary and "
            "always be careful when interfacing with a compartment outside of "
            "the safe area. Ensure that appropriate compartmentalization is "
            "built into the system design, and the compartmentalization "
            "allows for and reinforces privilege separation functionality. "
            "Architects and designers should rely on the principle of least "
            "privilege to decide the appropriate time to use privileges and "
            "the time to drop privileges.::PHASE:Implementation Architecture "
            "and Design:DESCRIPTION:Because setting manipulation covers a "
            "diverse set of functions, any attempt at illustrating it will "
            "inevitably be incomplete. Rather than searching for a tight-knit "
            "relationship between the functions addressed in the setting "
            "manipulation category, take a step back and consider the sorts "
            "of system values that an attacker should not be allowed to "
            "control.::PHASE:Implementation Architecture and "
            "Design:DESCRIPTION:In general, do not allow user-provided or "
            "otherwise untrusted data to control sensitive values. The "
            "leverage that an attacker gains by controlling these values is "
            "not always immediately obvious, but do not underestimate the "
            "creativity of the attacker.::",
        )
        self.assertEqual(
            cwe.taxonomy_mappings,
            "::TAXONOMY NAME:7 Pernicious Kingdoms:ENTRY NAME:Setting "
            "Manipulation::TAXONOMY NAME:Software Fault Patterns:ENTRY "
            "ID:SFP25:ENTRY NAME:Tainted input to variable::",
        )

    def test_cwe_error(self):
        with self.assertRaises(Exception):
            self.db.get(1000000)

    def test_is_top_25_cwe(self):
        self.assertTrue(self.db.is_cwe_top_25(20))
        self.assertTrue(self.db.is_cwe_top_25("20"))
        self.assertFalse(self.db.is_cwe_top_25(0))
        self.assertFalse(self.db.is_cwe_top_25("0"))

    def test_is_owasp_top_ten_2021(self):
        self.assertTrue(self.db.is_owasp_top_ten_2021(11))
        self.assertTrue(self.db.is_owasp_top_ten_2021("11"))
        self.assertFalse(self.db.is_owasp_top_ten_2021(0))
        self.assertFalse(self.db.is_cwe_top_25("0"))

    def test_get_top_25_cwe(self):
        self.assertEqual(len(self.db.get_top_25_cwe()), 25)
        self.assertTrue(isinstance(self.db.get_top_25_cwe()[0], Weakness))

    def test_get_owasp_top_ten_2021(self):
        self.assertEqual(len(self.db.get_owasp_top_ten_2021()), 182)
        self.assertTrue(isinstance(self.db.get_owasp_top_ten_2021()[0], Weakness))

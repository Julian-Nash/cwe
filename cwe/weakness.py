from typing import Optional, Any, Union


class Weakness(object):
    """ Common weakness object """

    def __init__(
        self,
        cwe_id: str,
        name: str,
        weakness_abstraction: Optional[str] = None,
        status: Optional[str] = None,
        description: Optional[str] = None,
        extended_description: Optional[str] = None,
        related_weaknesses: Optional[str] = None,
        weakness_ordinalities: Optional[str] = None,
        applicable_platforms: Optional[str] = None,
        background_details: Optional[str] = None,
        alternate_terms: Optional[str] = None,
        modes_of_introduction: Optional[str] = None,
        exploitation_factors: Optional[str] = None,
        likelihood_of_exploit: Optional[str] = None,
        common_consequences: Optional[str] = None,
        detection_methods: Optional[str] = None,
        potential_mitigations: Optional[str] = None,
        observed_examples: Optional[str] = None,
        functional_areas: Optional[str] = None,
        affected_resources: Optional[str] = None,
        taxonomy_mappings: Optional[str] = None,
        related_attack_patterns: Optional[str] = None,
        notes: Optional[str] = None,
    ):
        self._cwe_id = cwe_id
        self._name = name
        self._weakness_abstraction = weakness_abstraction
        self._status = status
        self._description = description
        self._extended_description = extended_description
        self._related_weaknesses = related_weaknesses
        self._weakness_ordinalities = weakness_ordinalities
        self._applicable_platforms = applicable_platforms
        self._background_details = background_details
        self._alternate_terms = alternate_terms
        self._modes_of_introduction = modes_of_introduction
        self._exploitation_factors = exploitation_factors
        self._likelihood_of_exploit = likelihood_of_exploit
        self._common_consequences = common_consequences
        self._detection_methods = detection_methods
        self._potential_mitigations = potential_mitigations
        self._observed_examples = observed_examples
        self._functional_areas = functional_areas
        self._affected_resources = affected_resources
        self._taxonomy_mappings = taxonomy_mappings
        self._related_attack_patterns = related_attack_patterns
        self._notes = notes

    def __repr__(self) -> str:
        return f"Weakness(cwe_id={self.cwe_id}, name={self.name})"

    @property
    def cwe_id(self) -> str:
        return self._cwe_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def weakness_abstraction(self) -> Union[str, None]:
        return self._weakness_abstraction

    @property
    def status(self) -> Union[str, None]:
        return self._status

    @property
    def description(self) -> Union[str, None]:
        return self._description

    @property
    def extended_description(self) -> Union[str, None]:
        return self._extended_description

    @property
    def related_weaknesses(self) -> Union[str, None]:
        return self._related_weaknesses

    @property
    def weakness_ordinalities(self) -> Union[str, None]:
        return self._weakness_ordinalities

    @property
    def applicable_platforms(self) -> Union[str, None]:
        return self._applicable_platforms

    @property
    def background_details(self) -> Union[str, None]:
        return self._background_details

    @property
    def alternate_terms(self) -> Union[str, None]:
        return self._alternate_terms

    @property
    def modes_of_introduction(self) -> Union[str, None]:
        return self._modes_of_introduction

    @property
    def exploitation_factors(self) -> Union[str, None]:
        return self._exploitation_factors

    @property
    def likelihood_of_exploit(self) -> Union[str, None]:
        return self._likelihood_of_exploit

    @property
    def common_consequences(self) -> Union[str, None]:
        return self._common_consequences

    @property
    def detection_methods(self) -> Union[str, None]:
        return self._detection_methods

    @property
    def potential_mitigations(self) -> Union[str, None]:
        return self._potential_mitigations

    @property
    def observed_examples(self) -> Union[str, None]:
        return self._observed_examples

    @property
    def functional_areas(self) -> Union[str, None]:
        return self._functional_areas

    @property
    def affected_resources(self) -> Union[str, None]:
        return self._affected_resources

    @property
    def taxonomy_mappings(self) -> Union[str, None]:
        return self._taxonomy_mappings

    @property
    def related_attack_patterns(self) -> Union[str, None]:
        return self._related_attack_patterns

    @property
    def notes(self):
        return self._notes

    def get(self, prop: str, default: Optional[Any] = None) -> Union[str, Any]:
        """ Get a property of the weakness

        Args:
            prop: The weakness property
            default: A default value to return (None)
        Returns:
            str: The property
        """
        return getattr(self, prop, default)

    def to_dict(self) -> dict:
        """ Returns a dictionary of the Weakness """

        return {
            "cwe_id": self._cwe_id,
            "name": self._name,
            "weakness_abstraction": self._weakness_abstraction,
            "status": self._status,
            "description": self._description,
            "extended_description": self._extended_description,
            "related_weaknesses": self._related_weaknesses,
            "weakness_ordinalities": self._weakness_ordinalities,
            "applicable_platforms": self._applicable_platforms,
            "background_details": self._background_details,
            "alternate_terms": self._alternate_terms,
            "modes_of_introduction": self._modes_of_introduction,
            "exploitation_factors": self._exploitation_factors,
            "likelihood_of_exploit": self._likelihood_of_exploit,
            "common_consequences": self._common_consequences,
            "detection_methods": self._detection_methods,
            "potential_mitigations": self._potential_mitigations,
            "observed_examples": self._observed_examples,
            "functional_areas": self._functional_areas,
            "affected_resources": self._affected_resources,
            "taxonomy_mappings": self._taxonomy_mappings,
            "related_attack_patterns": self._related_attack_patterns,
            "notes": self._notes,
        }

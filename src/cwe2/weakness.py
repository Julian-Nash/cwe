from dataclasses import dataclass
from typing import Any, Optional, Union


@dataclass
class Weakness(object):
    """Common weakness object"""

    cwe_id: str
    name: str
    weakness_abstraction: Optional[str] = (None,)
    status: Optional[str] = (None,)
    description: Optional[str] = (None,)
    extended_description: Optional[str] = (None,)
    related_weaknesses: Optional[str] = (None,)
    weakness_ordinalities: Optional[str] = (None,)
    applicable_platforms: Optional[str] = None
    background_details: Optional[str] = None
    alternate_terms: Optional[str] = None
    modes_of_introduction: Optional[str] = None
    exploitation_factors: Optional[str] = None
    likelihood_of_exploit: Optional[str] = None
    common_consequences: Optional[str] = None
    detection_methods: Optional[str] = None
    potential_mitigations: Optional[str] = None
    observed_examples: Optional[str] = None
    functional_areas: Optional[str] = None
    affected_resources: Optional[str] = None
    taxonomy_mappings: Optional[str] = None
    related_attack_patterns: Optional[str] = None
    notes: Optional[str] = None

    def get(self, prop: str, default: Optional[Any] = None) -> Union[str, Any]:
        """Get a property of the weakness

        Args:
            prop: The weakness property
            default: A default value to return (None)
        Returns:
            str: The property
        """
        return getattr(self, prop, default)

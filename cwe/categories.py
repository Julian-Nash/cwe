import enum


@enum.unique
class CWECategory(enum.Enum):

    HARDWARE_DESIGN: str = "hardware_design"
    RESEARCH_CONCEPTS: str = "research_concepts"
    SOFTWARE_DEVELOPMENT: str = "software_development"

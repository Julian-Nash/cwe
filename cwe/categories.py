import enum


@enum.unique
class CWECategory(enum.Enum):

    HARDWARE_DESIGN = "hardware_design"
    RESEARCH_CONCEPTS = "research_concepts"
    SOFTWARE_DEVELOPMENT = "software_development"

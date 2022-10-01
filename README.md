## Common weakness enumeration library for Python

![Python package](https://github.com/Julian-Nash/cwe/workflows/Python%20package/badge.svg)

https://cwe.mitre.org/index.html

#### Installation

```sh
pip install cwe2
```

#### Usage

- Get a CWE by ID:

```pycon
>>> from cwe.database import Database
>>> db = Database()
>>> db.get(15)
Weakness(cwe_id=15, name='External Control of System or Configuration Setting', weakness_abstraction='Base', status='Incomplete', description='One or more system settings or configuration elements can be externally controlled by a user.', extended_description='Allowing external control of system settings can disrupt service or cause an application to behave in unexpected, and potentially malicious ways.', related_weaknesses='::NATURE:ChildOf:CWE ID:642:VIEW ID:1000:ORDINAL:Primary::NATURE:ChildOf:CWE ID:610:VIEW ID:1000::NATURE:ChildOf:CWE ID:20:VIEW ID:700:ORDINAL:Primary::', weakness_ordinalities=nan, applicable_platforms=nan, background_details=nan, alternate_terms=nan, modes_of_introduction='::PHASE:Implementation:NOTE:Setting manipulation vulnerabilities occur when an attacker can control values that govern the behavior of the system, manage specific resources, or in some way affect the functionality of the application.::PHASE:Implementation:NOTE:REALIZATION: This weakness is caused during implementation of an architectural security tactic.::', exploitation_factors=nan, likelihood_of_exploit=nan, common_consequences='::SCOPE:Other:IMPACT:Varies by Context::', detection_methods=nan, potential_mitigations='::PHASE:Architecture and Design:STRATEGY:Separation of Privilege:DESCRIPTION:Compartmentalize the system to have safe areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area. Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.::PHASE:Implementation Architecture and Design:DESCRIPTION:Because setting manipulation covers a diverse set of functions, any attempt at illustrating it will inevitably be incomplete. Rather than searching for a tight-knit relationship between the functions addressed in the setting manipulation category, take a step back and consider the sorts of system values that an attacker should not be allowed to control.::PHASE:Implementation Architecture and Design:DESCRIPTION:In general, do not allow user-provided or otherwise untrusted data to control sensitive values. The leverage that an attacker gains by controlling these values is not always immediately obvious, but do not underestimate the creativity of the attacker.::', observed_examples=nan, functional_areas=nan, affected_resources=nan, taxonomy_mappings='::TAXONOMY NAME:7 Pernicious Kingdoms:ENTRY NAME:Setting Manipulation::TAXONOMY NAME:Software Fault Patterns:ENTRY ID:SFP25:ENTRY NAME:Tainted input to variable::', related_attack_patterns='::13::146::176::203::270::271::69::76::77::', notes=nan)
```

- Access attributes of the Weakness using dot notation

```pycon
>>> weakness = db.get(15)
>>> weakness.description
'One or more system settings or configuration elements can be externally controlled by a user.'
```

- Or use the weakness `get` method

```pycon
>>> weakness.get("status")
'Incomplete'
```

- Get a dictionary of the weakness (Truncated for this example)

```pycon
>>> weakness.__dict__
{'cwe_id': 15, 'name': 'External Control of System or Configuration Setting', 'weakness_abstraction': 'Base', 'status': 'Incomplete', 'description': 'One or more system settings or configuration elements can be externally controlled by a user.', 'extended_description': 'Allowing external control of system settings can disrupt service or cause an application to behave in unexpected, and potentially malicious ways.', 'related_weaknesses': '::NATURE:ChildOf:CWE ID:642:VIEW ID:1000:ORDINAL:Primary::NATURE:ChildOf:CWE ID:610:VIEW ID:1000::NATURE:ChildOf:CWE ID:20:VIEW ID:700:ORDINAL:Primary::', 'weakness_ordinalities': nan, 'applicable_platforms': nan, 'background_details': nan, 'alternate_terms': nan, 'modes_of_introduction': '::PHASE:Implementation:NOTE:Setting manipulation vulnerabilities occur when an attacker can control values that govern the behavior of the system, manage specific resources, or in some way affect the functionality of the application.::PHASE:Implementation:NOTE:REALIZATION: This weakness is caused during implementation of an architectural security tactic.::', 'exploitation_factors': nan, 'likelihood_of_exploit': nan, 'common_consequences': '::SCOPE:Other:IMPACT:Varies by Context::', 'detection_methods': nan, 'potential_mitigations': '::PHASE:Architecture and Design:STRATEGY:Separation of Privilege:DESCRIPTION:Compartmentalize the system to have safe areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area. Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.::PHASE:Implementation Architecture and Design:DESCRIPTION:Because setting manipulation covers a diverse set of functions, any attempt at illustrating it will inevitably be incomplete. Rather than searching for a tight-knit relationship between the functions addressed in the setting manipulation category, take a step back and consider the sorts of system values that an attacker should not be allowed to control.::PHASE:Implementation Architecture and Design:DESCRIPTION:In general, do not allow user-provided or otherwise untrusted data to control sensitive values. The leverage that an attacker gains by controlling these values is not always immediately obvious, but do not underestimate the creativity of the attacker.::', 'observed_examples': nan, 'functional_areas': nan, 'affected_resources': nan, 'taxonomy_mappings': '::TAXONOMY NAME:7 Pernicious Kingdoms:ENTRY NAME:Setting Manipulation::TAXONOMY NAME:Software Fault Patterns:ENTRY ID:SFP25:ENTRY NAME:Tainted input to variable::', 'related_attack_patterns': '::13::146::176::203::270::271::69::76::77::', 'notes': nan}
```

- Get the top 25 weaknesses `get_top_25_cwe`
- Get the top ten OWASP 2021 weaknesses `get_owasp_top_ten_2021` 
```pycon
>>> from cwe.database import Database
>>> db = Database()
>>> db.get_top_25_cwe()
```


- Is in a OWASP Top Ten (2021) `is_owasp_top_ten_2021`
- Is in a CWE Top 25 (2022) `is_cwe_top_25`

```pycon
>>> from cwe.database import Database
>>> db = Database()
>>> db.is_owasp_top_ten_2021(11)
True
>>> db.is_cwe_top_25(11)
False
```

#### Weakness attributes

The following weakness object attributes can accessed:

- `cwe_id`
- `name`
- `weakness_abstraction`
- `status`
- `description`
- `extended_description`
- `related_weaknesses`
- `weakness_ordinalities`
- `applicable_platforms`
- `background_details`
- `alternate_terms`
- `modes_of_introduction`
- `exploitation_factors`
- `likelihood_of_exploit`
- `common_consequences`
- `detection_methods`
- `potential_mitigations`
- `observed_examples`
- `functional_areas`
- `affected_resources`
- `taxonomy_mappings`
- `related_attack_patterns`
- `notes`

#### Tests

There's a small `unittest` test suite in the `tests` directory

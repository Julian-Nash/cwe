## Common weakness enumeration library for Python

![Python package](https://github.com/Julian-Nash/cwe/workflows/Python%20package/badge.svg)

https://cwe.mitre.org/index.html

#### Installation

```sh
pip install cwe
```

#### Usage

- Get a CWE by ID:

```pycon
>>> from cwe import Database
>>> db = Database()
>>> db.get(15)
Weakness(cwe_id=15, name=External Control of System or Configuration Setting)
```

- Access attributes of the Weakness using dot notation

```pycon
>>> weakness = db.get(15)
>>> weakness.description
'One or more system settings or configuration elements can be externally controlled by a user.'
```

- Or use the weakness `get` method

```pycon
>>> weakness.get("status", None)
'Incomplete'
```

- Get a dictionary of the weakness (Truncated for this example)

```pycon
>>> weakness.to_dict()
{'cwe_id': '15', 'name': 'External Control of System or Configuration Setting', 'weakness_abstraction': 'Base'}
```

- Get the top 25 weaknesses

```pycon
>>> from cwe import Database
>>> db = Database()
>>> db.get_top_25()

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

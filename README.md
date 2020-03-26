# `Common weakness enumeration library for Python`

### `Installation`

```sh
pip install cwe
```

### `Usage`

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
>>> db.get(15)
```

### Tests

There's a small `unittest` test suite in the `/tests` directory

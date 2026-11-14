Implement `slugify(value: str) -> str` in `src/slugify.py`.

Requirements:
- lowercase the input;
- replace every run of non-alphanumeric characters with one hyphen;
- remove leading and trailing hyphens;
- return an empty string for an input with no alphanumeric characters;
- preserve Unicode letters when deciding which characters are alphanumeric (for example, `café déjà vu` becomes `café-déjà-vu`);
- add or update tests in `tests/test_slugify.py`.

Do not modify files outside `src/slugify.py` and `tests/test_slugify.py`.

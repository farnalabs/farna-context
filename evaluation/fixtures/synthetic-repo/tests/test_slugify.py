from src.slugify import slugify


def test_slugify_placeholder() -> None:
    assert slugify("Already stable") == "Already stable"

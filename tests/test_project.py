from was.project import AddonProject


def test_project_load():
    project = AddonProject("tests/SampleAddon")
    files = project.load()

    assert len(files) == 2
from was.parser.toc_loader import TOCLoader


def test_toc_loader():
    loader = TOCLoader("tests/SampleAddon")

    manifest = loader.load()

    assert manifest is not None
    assert manifest.files == [
        "Core.lua",
        "UI.lua",
    ]
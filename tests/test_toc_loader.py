from was.parser.toc_loader import TOCLoader


def test_toc_loader():
    loader = TOCLoader("tests/SampleAddon")

    toc = loader.find_toc()

    assert toc is not None
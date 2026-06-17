import activerecon.cli as cli_module
import activerecon.main as main_module


def test_main_module_is_thin_cli_wrapper():
    assert main_module.main is cli_module.main

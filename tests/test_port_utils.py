import pytest
from port_prowler.port_utils import parse_ports

@pytest.mark.parametrize(('spec', 'expected'), [('80', [80]), ('22,80,443', [22, 80, 443]), ('1000-1002', [1000, 1001, 1002]), ('22,80-82', [22, 80, 81, 82]), ('  53 , 80-81 , 443 ', [53, 80, 81, 443])])
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected

@pytest.mark.parametrize('spec', ['', '0', '70000', '10-', '-10', 'a', '1,abc'])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)

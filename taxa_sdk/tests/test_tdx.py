"""
TDX Mode Tests for Taxa SDK

These tests verify the TDX mode functionality of TaxaRequest.
They require a running TDX API server at the configured URL.
"""

import unittest
import os

from taxa_sdk import TaxaRequest


# Path to test contracts
TEST_CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), 'test_contracts')


def get_contract_path(filename):
    """Get the full path to a test contract file."""
    return os.path.join(TEST_CONTRACTS_DIR, filename)


class TDXBasicTest(unittest.TestCase):
    """Basic tests for TDX mode using TaxaRequest."""

    def setUp(self):
        """Create a TaxaRequest instance in TDX mode."""
        self.req = TaxaRequest(mode='tdx', verbose=False)

    def test_syntax_error(self):
        """Test that syntax errors in contracts are properly reported."""
        result = self.req.send(
            code_path=get_contract_path('syntax_error.py'),
            function='main2',
            data={'x': 5}
        )
        # The SDK raises InvalidRequest for syntax errors, so this should not reach here
        # If it does, check that the response indicates an error
        self.fail("Expected InvalidRequest to be raised for syntax error")

    def test_syntax_error_exception(self):
        """Test that syntax errors raise InvalidRequest exception."""
        from taxa_sdk.exceptions import InvalidRequest
        with self.assertRaises(InvalidRequest) as context:
            self.req.send(
                code_path=get_contract_path('syntax_error.py'),
                function='main2',
                data={'x': 5}
            )
        self.assertIn('Syntax error', str(context.exception))

    def test_simple_working(self):
        """Test a simple working contract."""
        result = self.req.send(
            code_path=get_contract_path('tdx_test.py'),
            function='main2',
            data={'x': 5}
        )
        self.assertEqual(result['result'], 10)

    def test_call_by_cid(self):
        """Test calling a contract by its content ID (CID)."""
        result = self.req.send(
            cid='bafkreic24erxvwo2mp7hcw5wztd4nce6pqtuqoha2eokaoflhi2lw2ryz4',
            function='main2',
            data={'x': 55}
        )
        self.assertEqual(result['result'], 60)

    def test_broken_contract(self):
        """Test that runtime errors in contracts are properly reported."""
        from taxa_sdk.exceptions import TserviceError
        with self.assertRaises(TserviceError) as context:
            self.req.send(
                code_path=get_contract_path('tdx_test.py'),
                function='broken',
                data={'x': 5}
            )
        self.assertIn('NameError', str(context.exception))

    def test_install_libs(self):
        """Test that pip libraries can be installed for contracts."""
        result = self.req.send(
            code_path=get_contract_path('lib_test.py'),
            function='main',
            data={'x': 1},
            libs=['requests']
        )
        self.assertEqual(result['result'], "KELP")

    def test_response_contains_cid(self):
        """Test that successful responses contain a CID."""
        result = self.req.send(
            code_path=get_contract_path('tdx_test.py'),
            function='main2',
            data={'x': 5}
        )
        self.assertIn('cid', result)
        self.assertIsNotNone(result['cid'])

    def test_response_contains_log(self):
        """Test that contract print() output appears in the log."""
        result = self.req.send(
            code_path=get_contract_path('tdx_test.py'),
            function='main2',
            data={'x': 5}
        )
        self.assertIn('log', result)
        self.assertIn('into the log', result['log'])

    def test_response_contains_time(self):
        """Test that responses contain execution time."""
        result = self.req.send(
            code_path=get_contract_path('tdx_test.py'),
            function='main2',
            data={'x': 5}
        )
        self.assertIn('time', result)
        self.assertIsInstance(result['time'], (int, float))

    def test_inline_code(self):
        """Test sending inline code instead of a file."""
        code = """
def add_numbers(input_obj):
    return input_obj['a'] + input_obj['b']
"""
        result = self.req.send(
            code=code,
            function='add_numbers',
            data={'a': 10, 'b': 20}
        )
        self.assertEqual(result['result'], 30)


if __name__ == '__main__':
    unittest.main()

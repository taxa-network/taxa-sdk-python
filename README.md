# Taxa Network Python SDK

Library used to aid developers in building applications on the Taxa Network.
It works with both Python 2.7 and Python 3.5+.

## Installation

1. Download the zip file from Github. Extract into a folder anywhere.
2. On the command line, navigate to that folder and run the install script: `python setup.py install`

## Documentation

The documentation for this SDK can be found [here](https://docs.taxa.network/python-sdk).

## Running tests

To run the tests for this module, run the following commands:

### Testing through the WebUI

To test just the attestation process, using the WebUI:
```
python -m taxa_sdk.tests TestAttestationWebUI
```

To test the full millionaire test using the WebUI, run this command:
```
python -m taxa_sdk.tests TestMillionaireByIdentity
```

Note: If you want to limit your tests to just a WebUI running of a specific server,
then modify the `FORCEIP` variable at the top of `taxa_sdk/tests.py`. If `FORCEIP`
is set to `None` (The default), then the node distributer will pick a server
for you.

Also note that all tests ran though the WebUI will use the version of
`taxa_client` that comes bundled with the SDK.

### Running tests through the command line (bypassing WebUI)

To run the millionaire test via `taxa_server` via command line, bypassing the
WebUI, then use the following command:

```
python -m taxa_sdk.tests TestBypassWebUI
```

To just run the attestation via the `taxa_server` via command line, use this
command:
```
python -m taxa_sdk.tests TestBypassWebUI.test_attestation
```

Note: you must modify the tests.py file at the top to include the paths to the
command line `taxa_client` and `taxa_server` to do the `BypassWebUI` tests.

### Testing parameters

There are a few things you can change via the command line. These extra\
parameters must be placed *before* the name of the test classes.

#### --forceip

```
python -m taxa_sdk.tests --forceip=13.92.194.125 TestMillionaireByIdentity
```

This will force the test to run on the node at the passed in IP. If this option
is not used, the ip will be gotten from the P2P network.

#### --nop2p

This will force the IP to be gotten from the node distributor web service instead
of the P2P network.


#### --keepkeys

By default all tests delete their keys after finishing. With this option included,
the keys will not be deleted. This means you can run the tests over and over, and it
will skip attestation. hence speeding up the tests.

# SocialProofVerifier

On-chain identity verification via social media proof for GenLayer.

## Deployed Contract

| Field | Value |
|-------|-------|
| **Address** | `0x76cEd526f6F7A52322d0F319Fe6711Ef2B176416` |
| **Network** | GenLayer Studio (studionet) |
| **Chain ID** | 61999 |
| **Explorer** | [View on Explorer](https://explorer-studio.genlayer.com/address/0x76cEd526f6F7A52322d0F319Fe6711Ef2B176416) |
| **Deployer** | `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` |

## Overview

Users register social media profiles (Twitter, GitHub, Discord, etc.) and specify verification messages. The validator network fetches these profiles, uses AI to check for the specified messages, and reaches consensus on the verification result.

## Key Features

- **Immutable verification rules**: Set once at deploy
- **Multi-validator consensus**: Independent verification by multiple validators
- **Deterministic trust scoring**: 0-100 score with 5 levels (unverified → premium)
- **Composable primitive**: `get_verified(address, min_trust_score)`
- **Security hardening**: Based on staff GenLayer feedback from previous contracts

## Supported Platforms

Twitter, GitHub, Discord, Telegram, LinkedIn

## Trust Levels

| Score | Level |
|-------|-------|
| 90-100 | premium |
| 75-89 | enhanced |
| 50-74 | standard |
| 25-49 | basic |
| 0-24 | unverified |

## Usage

```python
from genlayer_py import create_client, studionet
from eth_account import Account

# Connect to GenLayer Studio
account = Account.from_key("your_private_key")
client = create_client(chain=studionet, account=account)

CONTRACT_ADDRESS = "0x76cEd526f6F7A52322d0F319Fe6711Ef2B176416"

# Get scheme info
scheme = client.read_contract(CONTRACT_ADDRESS, "get_scheme")

# Register profile
client.write_contract(
    CONTRACT_ADDRESS,
    "register_profile",
    account=account,
    args=[user_address, "twitter", "https://twitter.com/user", "@myhandle"]
)

# Request verification
tx_hash = client.write_contract(
    CONTRACT_ADDRESS,
    "request_verification",
    account=account,
    args=[user_address]
)

# Check trust score
trust_score = client.read_contract(CONTRACT_ADDRESS, "get_trust_score", args=[user_address])
trust_level = client.read_contract(CONTRACT_ADDRESS, "get_trust_level", args=[user_address])

# Check verified status
is_verified = client.read_contract(CONTRACT_ADDRESS, "is_verified", args=[user_address])
```

## Testing

Run the studio test script:

```bash
python test_studio.py
```

Or run unit tests:

```bash
pytest contracts/social_proof_verifier.py -v
```

## Files

```
social-proof-verifier/
├── contracts/
│   └── social_proof_verifier.py     # Contract + unit tests
├── tests/
│   ├── direct/
│   │   └── test_social_proof_verifier.py
│   └── integration/
│       └── test_deploy_and_test.py
├── test_studio.py                   # Studio testing script
├── deployment.toml
├── gltest.config.yaml
├── requirements.txt
├── README.md
├── SECURITY_AUDIT.md
└── DEPLOYMENT.md
```

## Security

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for details on security hardening based on staff GenLayer feedback.

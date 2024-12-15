import json
from solcx import compile_standard  # type: ignore # To compile the contract.sol file
from web3 import Web3 # type: ignore
import solcx # type: ignore

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Adjust if using a different provider

# Check if Web3 is connected
if not w3.is_connected():
    raise Exception("Failed to connect to Ganache!")

# Read contract from the Solidity file
with open('MediChain.sol', 'r') as file:
    contract_source_code = file.read()

solcx.set_solc_version("0.8.0")
compiled_sol = compile_standard({
    "language": "Solidity",
    "sources": {
        "contract.sol": {
            "content": contract_source_code
        }
    },
    "settings": {
        "outputSelection": {
            "*": {
                "*": ["abi", "evm.bytecode"]
            }
        }
    }
})

# Get ABI and Bytecode
contract_abi = compiled_sol['contracts']['contract.sol']['MediChain']['abi']
contract_bytecode = compiled_sol['contracts']['contract.sol']['MediChain']['evm']['bytecode']['object']

# Set up account to deploy from
deployer_address = w3.eth.accounts[0]  # Default Ganache account
private_key = '0xfe26f4199872e8f8d9ad141a2dbcc919044cebf2fead403d87042ad4bf4fe9c3'  # Replace with your deployer's private key

# Check if the deployer address has enough funds
balance = w3.eth.get_balance(deployer_address)
print(f"Deployer balance: {w3.from_wei(balance, 'ether')} ETH")

# Create contract instance
MediChain = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

# Build transaction
transaction = MediChain.constructor().build_transaction({
    'from': deployer_address,
    'gas': 6721975,  # Adjust if necessary
    'gasPrice': w3.to_wei('20', 'gwei'),
    'nonce': w3.eth.get_transaction_count(deployer_address),
})

# Sign the transaction
signed_transaction = w3.eth.account.sign_transaction(transaction, private_key)

# Send the transaction
tx_hash = w3.eth.send_raw_transaction(signed_transaction.raw_transaction)

# Wait for the receipt of the transaction (confirm contract deployment)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Print the contract address
print(f"Contract deployed at address: {tx_receipt.contractAddress}")

# Optionally save compiled contract (ABI and Bytecode) to a file
compiled_contract_path = "compiled_contract.json"
with open(compiled_contract_path, 'w') as compiled_file:
    json.dump(compiled_sol, compiled_file, indent=4)

print(f"Compiled contract saved to {compiled_contract_path}")

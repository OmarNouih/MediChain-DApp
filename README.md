# MediChain-DApp

## Overview
MediChain-DApp is a decentralized desktop application designed to manage and secure medical records using blockchain technology. It leverages the Ethereum blockchain, IPFS for storage, and a Python/Flask backend integrated with FlaskGUI for a seamless desktop experience. This approach ensures data integrity, privacy, and accessibility for patients and authorized healthcare providers.

## Features
- **User Registration:** Patients and doctors can register with unique credentials.
- **Medical Records Management:** Securely create, update, and delete medical records stored on IPFS.
- **Access Control:** Patients can grant or revoke access to their medical records for specific doctors.
- **Transaction Tracking:** Record and settle transactions between patients and doctors.
- **Audit History:** Maintain a transparent audit trail of all medical events and modifications.

## Technologies Used
- **Smart Contract:** Solidity (`MediChain.sol`)
- **Blockchain Network:** Ethereum (Ganache for local development)
- **Backend & Desktop Interface:** Python, Flask, and FlaskGUI
- **IPFS Integration:** Pinata for decentralized storage
- **Blockchain Interaction:** Web3.py for communicating with the Ethereum network

## Demonstration Video

Click the link below to watch the demonstration video of **MediChain-DApp**:

[Link to Video Demonstration](https://github.com/user-attachments/assets/99630596-6538-4bd5-a314-d1c3d56d6292)

## Getting Started

### Prerequisites
- **Python 3.x:** [Download Python](https://www.python.org/downloads/)
- **Ganache:** [Download Ganache](https://trufflesuite.com/ganache/)
- **Pinata Account:** [Sign up at Pinata](https://pinata.cloud/)
- **Solidity Compiler (`solc`):** Install via `solcx` in Python

### Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/MediChain-DApp.git
    cd MediChain-DApp
    ```

2. **Create and Activate a Virtual Environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set Up Environment Variables:**
    Create a `.env` file in the root directory and add:
    ```
    WEB3_PROVIDER_URL=http://127.0.0.1:7545
    CONTRACT_ADDRESS=your_contract_address
    PINATA_API_KEY=your_pinata_api_key
    PINATA_SECRET_API_KEY=your_pinata_secret_api_key
    ```
    Update these values after you deploy the contract and set up Pinata.

5. **Deploy the Smart Contract:**
    Make sure Ganache is running, then:
    ```bash
    python deploy_contract.py
    ```
    Note the deployed contract address and update the `CONTRACT_ADDRESS` in `.env`.

6. **Run the Application:**
    ```bash
    python app.py
    ```
    A desktop interface will launch, allowing you to interact with MediChain-DApp.

## Usage
- **Register:** Users can register as patients or doctors. Patients must provide an initial medical record file.
- **Login:** Authenticate using email, Ethereum address, and private key.
- **Dashboard:** 
  - Patients: Manage your records, grant/revoke doctor access, and view transaction history.
  - Doctors: Access authorized patient records, update them, and review transactions.
- **Medical Records Management:** Doctors can upload new IPFS-hosted records and patients can review or delete them.
- **Access Control & Audit Trails:** Patients control who can view their records, and all record actions are logged.

## Security Considerations
- **Private Keys:** For demonstration, private keys are stored in the session. In production, consider secure wallet integrations or off-chain methods.
- **Data Privacy:** Use this DApp responsibly and ensure compliance with any applicable medical data regulations.
- **.env & Sensitive Data:** Protect your `.env` file and do not commit it to version control.

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes (`git commit -m 'Add new feature'`).
4. Push the branch (`git push origin feature/YourFeature`).
5. Open a pull request on GitHub.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements
- [Ethereum](https://ethereum.org/)
- [Web3.py](https://web3py.readthedocs.io/)
- [Pinata](https://pinata.cloud/)
- [Flask](https://flask.palletsprojects.com/)
- [FlaskGUI](https://github.com/ClimenteA/flaskwebgui)

import os
from flask import Flask, redirect, render_template, request, jsonify, session, url_for, flash
from web3 import Web3  # type: ignore
import json
import requests
from flaskwebgui import FlaskUI
from dotenv import load_dotenv # type: ignore

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generates a random secret key

# Initialize Web3
WEB3_PROVIDER_URL = os.getenv('WEB3_PROVIDER_URL')
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS')
PINATA_API_KEY = os.getenv('PINATA_API_KEY')
PINATA_SECRET_API_KEY = os.getenv('PINATA_SECRET_API_KEY')

w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))
if not w3.is_connected():
    raise Exception("Failed to connect to the Ethereum network!")

# Load the compiled contract
with open('compiled_contract.json') as f:
    compiled_sol = json.load(f)

contract_abi = compiled_sol['contracts']['contract.sol']['MediChain']['abi']
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    address = request.form.get('address')
    private_key = request.form.get('private_key')

    if not email or not address or not private_key:
        flash("Please provide email, Ethereum address, and private key.", "danger")
        return redirect(url_for('index'))

    try:
        address = w3.to_checksum_address(address)
        account = w3.eth.account.from_key(private_key)
        if account.address != address:
            flash("Private key does not match the Ethereum address.", "danger")
            return redirect(url_for('index'))
        
    except Exception as e:
        flash("Invalid Ethereum address or private key.", "danger")
        return redirect(url_for('index'))

    try:
        designation = contract.functions.emailToDesignation(email).call()
    except Exception as e:
        flash("Error fetching designation: " + str(e), "danger")
        return redirect(url_for('index'))

    if designation == 0:
        flash("User not found. Please register.", "danger")
        return redirect(url_for('index'))

    # Determine the role based on designation
    role = None
    if designation == 1:
        role = 'patient'
    elif designation == 2:
        role = 'doctor'
    else:
        flash("Invalid designation.", "danger")
        return redirect(url_for('index'))

    # Fetch user's name from contract storage (depending on role)
    try:
        if role == 'patient':
            # Patient info
            patient = contract.functions.getPatientBasicInfo(address).call()
            name = patient[0]
        elif role == 'doctor':
            # Doctor info
            doctor = contract.functions.getDoctorInfo(address).call()
            name = doctor[0]
        else:
            name = "Unknown"
    except Exception as e:
        flash("Error verifying role: " + str(e), "danger")
        return redirect(url_for('index'))

    # **Security Note:** Storing private keys in session is insecure. Consider using client-side signing.
    session['address'] = address
    session['name'] = name
    session['role'] = role
    session['private_key'] = private_key  # Insecure in production!
    flash("Login successful!", "success")
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        age = request.form.get('age')
        email = request.form.get('email')
        designation = request.form.get('designation')
        private_key = request.form.get('private_key')
        file = request.files.get('file')  # For patients, initial medical record

        if not name or not email or not designation or not private_key:
            flash("All fields are required.", "danger")
            return redirect(url_for('index'))

        try:
            designation_int = int(designation)
            if designation_int == 1:
                age = int(age)
                if age <= 0:
                    flash("Age must be greater than 0 for patients.", "danger")
                    return redirect(url_for('index'))
            else:
                age = 0  # Not used for doctors

            account = w3.eth.account.from_key(private_key)
            address = account.address
        except ValueError:
            flash("Invalid age or designation.", "danger")
            return redirect(url_for('index'))
        except Exception as e:
            flash("Invalid private key.", "danger")
            return redirect(url_for('index'))

        try:
            # Check if email is already registered
            existing_address = contract.functions.emailToAddress(email).call()
            if existing_address != '0x0000000000000000000000000000000000000000':
                flash("Email already registered.", "danger")
                return redirect(url_for('index'))
        except Exception as e:
            # Handle the case where emailToAddress returns default value
            pass  # Assuming if it fails, proceed to register

        try:
            # Upload initial medical record if patient
            ipfs_hash = ""
            if designation_int == 1:
                if not file:
                    flash("Medical record file is required for patients.", "danger")
                    return redirect(url_for('index'))
                ipfs_hash = upload_to_ipfs(file)
            else:
                # For doctors, ipfs_hash is not required
                ipfs_hash = ""

            # Call register function on the contract
            tx = contract.functions.register(name, age, designation_int, email, ipfs_hash).build_transaction({
                'from': address,
                'gas': 2000000,
                'gasPrice': w3.to_wei('10', 'gwei'),
                'nonce': w3.eth.get_transaction_count(address),
            })

            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('index'))
        
        except Exception as e:
            flash("Error during contract interaction: " + str(e), "danger")
            return redirect(url_for('index'))
    
    return render_template('index.html')

def upload_to_ipfs(file):
    """Uploads a file to IPFS via Pinata and returns the IPFS hash."""
    url = 'https://api.pinata.cloud/pinning/pinFileToIPFS'
    headers = {
        'pinata_api_key': PINATA_API_KEY,
        'pinata_secret_api_key': PINATA_SECRET_API_KEY
    }

    try:
        # For Pinata, use 'file' as the key and pass the file properly
        files = {'file': (file.filename, file.stream, file.content_type)}
        response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            ipfs_hash = response.json()['IpfsHash']
            return ipfs_hash
        else:
            app.logger.error(f"Pinata upload failed: {response.text}")
            raise Exception("IPFS upload failed.")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error uploading file to Pinata: {e}")
        raise Exception("IPFS upload error.")

@app.route('/dashboard')
def dashboard():
    if 'address' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('index'))

    address = session['address']
    role = session['role']
    name = session['name']

    user_info = {}
    transactions = []
    patients = []
    doctors = []

    try:
        if role == 'patient':
            # Fetch basic patient info using a custom getter
            pinfo = contract.functions.getPatientBasicInfo(address).call()
            # pinfo expected format: (name, email, age, exists, policyActive)
            user_info = {
                'Name': pinfo[0],
                'Email': pinfo[1],
                'Age': pinfo[2],
                'Exists': pinfo[3],
                'Policy Active': pinfo[4],  # If using policies
            }

            # Fetch medical records (IPFS hashes)
            medical_records = contract.functions.getMedicalRecords(address).call()
            user_info['Medical Records'] = medical_records

            # Fetch medical events for the patient
            events_count = contract.functions.getPatientEventsCount(address).call()
            user_info['Medical Events'] = []
            for i in range(events_count):
                evt = contract.functions.getPatientEvent(address, i).call()
                # evt format: (actor, action, timestamp)
                user_info['Medical Events'].append({
                    "actor": evt[0],
                    "action": evt[1],
                    "timestamp": evt[2]
                })

            # Fetch patient transactions
            txn_data = contract.functions.getTransactionsForAddress(address).call()
            transactions = []
            for txn in txn_data:
                # txn = (id, sender, receiver, value, settled)
                transactions.append({
                    "TransactionID": txn[0],
                    "Sender": txn[1],
                    "Receiver": txn[2],
                    "Value": txn[3],
                    "Settled": txn[4]
                })

            # Fetch all doctors for 'Manage Doctor Access'
            doctors_addresses = contract.functions.getAllDoctors().call()
            for doc_addr in doctors_addresses:
                if doc_addr != '0x0000000000000000000000000000000000000000':
                    doc_info = contract.functions.getDoctorInfo(doc_addr).call()
                    doctors.append({
                        'name': doc_info[0],
                        'address': doc_addr
                    })

            return render_template('patient_dashboard.html', user_info=user_info, transactions=transactions, name=name, role=role, doctors=doctors)

        elif role == 'doctor':
            # Fetch doctor info using a custom getter
            dinfo = contract.functions.getDoctorInfo(address).call()
            # dinfo expected format: (name, email, exists, transactions[], patientAccessList[])
            user_info = {
                'Name': dinfo[0],
                'Email': dinfo[1],
                'Exists': dinfo[2],
            }

            patient_access_list = dinfo[4]
            if patient_access_list:
                for patient_address in patient_access_list:
                    pinfo = contract.functions.getPatientBasicInfo(patient_address).call()
                    # pinfo format: (name, email, age, exists, policyActive)
                    medical_records = contract.functions.getMedicalRecords(patient_address).call()
                    patients.append({
                        'name': pinfo[0],
                        'address': patient_address,
                        'medicalRecords': medical_records  # To display IPFS links
                    })

            # Fetch doctor transactions
            txn_data = contract.functions.getTransactionsForAddress(address).call()
            for txn in txn_data:
                transactions.append({
                    "Sender": txn['sender'],
                    "Receiver": txn['receiver'],
                    "Value": txn['value'],
                    "Settled": txn['settled']
                })

            return render_template('doctor_dashboard.html', user_info=user_info, transactions=transactions, name=name, role=role, patients=patients)

        else:
            user_info = {'Error': 'Unknown role.'}
            return render_template('dashboard.html', user_info=user_info, name=name, role=role)

    except Exception as e:
        app.logger.error(f"Error fetching dashboard data: {e}")
        flash("Error fetching dashboard data.", "danger")
        return redirect(url_for('index'))

@app.route('/update_medical_record_page')
def update_medical_record_page():
    if 'address' not in session or session['role'] != 'doctor':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('index'))

    name = session['name']
    patient_address = request.args.get('patient_address', '')
    if not patient_address:
        flash("No patient address provided.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('update_medical_record.html', name=name, patient_address=patient_address)

@app.route('/update_medical_record', methods=['POST'])
def update_medical_record():
    if 'address' not in session or session['role'] != 'doctor':
        flash("Only doctors can update medical records.", "danger")
        return redirect(url_for('index'))

    doctor_address = session['address']
    private_key = session['private_key']

    patient_address = request.form.get('patient_address')
    if not patient_address:
        flash("No patient address provided.", "danger")
        return redirect(url_for('dashboard'))
    try:
        patient_address = w3.to_checksum_address(patient_address)
    except Exception as e:
        flash(f"Invalid patient address format: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

    file = request.files.get('file')
    if not file:
        flash("No file uploaded.", "danger")
        return redirect(url_for('dashboard'))

    # Upload file to IPFS via Pinata
    try:
        ipfs_hash = upload_to_ipfs(file)
    except Exception as e:
        flash(str(e), "danger")
        return redirect(url_for('dashboard'))

    # Now call createOrUpdateMedicalRecord on the contract
    try:
        txn = contract.functions.createOrUpdateMedicalRecord(patient_address, ipfs_hash).build_transaction({
            'from': doctor_address,
            'gas': 500000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(doctor_address),
        })

        signed_txn = w3.eth.account.sign_transaction(txn, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        flash("Medical record updated successfully.", "success")
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error processing the transaction: {e}")
        flash("Error processing the transaction.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/delete_medical_record', methods=['POST'])
def delete_medical_record():
    if 'address' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('index'))
    
    role = session['role']
    address = session['address']
    private_key = session['private_key']

    if role != 'patient' and role != 'doctor':
        flash("Unauthorized role.", "danger")
        return redirect(url_for('dashboard'))

    # Get the patient address and record index from the form
    patient_address = request.form.get('patient_address')
    record_index = request.form.get('record_index')

    if not patient_address or record_index is None:
        flash("Missing patient address or record index.", "danger")
        return redirect(url_for('dashboard'))

    try:
        patient_address = w3.to_checksum_address(patient_address)
        record_index = int(record_index) - 1  # Assuming record_id starts at 1
    except Exception as e:
        flash(f"Invalid input: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

    try:
        # Check if the user is authorized to delete the record
        if role == 'patient':
            # Patients can delete their own records
            if patient_address != address:
                flash("Patients can only delete their own records.", "danger")
                return redirect(url_for('dashboard'))
        elif role == 'doctor':
            # Doctors can delete records of their authorized patients
            if not contract.functions.isDoctorAuthorized(patient_address, address).call():
                flash("You are not authorized to delete records for this patient.", "danger")
                return redirect(url_for('dashboard'))

        # Call deleteMedicalRecord on the contract
        txn = contract.functions.deleteMedicalRecord(patient_address, record_index).build_transaction({
            'from': address,
            'gas': 500000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(address),
        })

        signed_txn = w3.eth.account.sign_transaction(txn, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        flash("Medical record deleted successfully.", "success")
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error deleting medical record: {e}")
        flash("Error deleting medical record.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('index'))

# Grant access (patient calls this to grant a doctor access)
@app.route('/grant_access', methods=['POST'])
def grant_access():
    if 'address' not in session or session['role'] != 'patient':
        flash("Only patients can grant access.", "danger")
        return redirect(url_for('index'))

    patient_address = session['address']
    private_key = session['private_key']
    doctor_address = request.form.get('doctor_address')

    if not doctor_address:
        flash("No doctor address provided.", "danger")
        return redirect(url_for('dashboard'))
    try:
        doctor_address = w3.to_checksum_address(doctor_address)
    except Exception as e:
        flash(f"Invalid doctor address format: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

    try:
        # Ensure the doctor exists
        doctor_info = contract.functions.getDoctorInfo(doctor_address).call()
        if not doctor_info[2]:  # exists
            flash("Doctor does not exist.", "danger")
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash("Error verifying doctor existence.", "danger")
        return redirect(url_for('dashboard'))

    try:
        txn = contract.functions.grantAccessToDoctor(doctor_address).build_transaction({
            'from': patient_address,
            'gas': 500000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(patient_address),
        })
        signed_txn = w3.eth.account.sign_transaction(txn, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        flash("Access granted successfully.", "success")
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        app.logger.error(f"Error granting access: {e}")
        flash("Error granting access.", "danger")
        return redirect(url_for('dashboard'))

# Revoke access (patient calls this to revoke doctor's access)
@app.route('/revoke_access', methods=['POST'])
def revoke_access():
    if 'address' not in session or session['role'] != 'patient':
        flash("Only patients can revoke access.", "danger")
        return redirect(url_for('index'))

    patient_address = session['address']
    private_key = session['private_key']
    doctor_address = request.form.get('doctor_address')

    if not doctor_address:
        flash("No doctor address provided.", "danger")
        return redirect(url_for('dashboard'))
    try:
        doctor_address = w3.to_checksum_address(doctor_address)
    except Exception as e:
        flash(f"Invalid doctor address format: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

    try:
        # Ensure the doctor exists
        doctor_info = contract.functions.getDoctorInfo(doctor_address).call()
        if not doctor_info[2]:  # exists
            flash("Doctor does not exist.", "danger")
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash("Error verifying doctor existence.", "danger")
        return redirect(url_for('dashboard'))

    try:
        txn = contract.functions.revokeAccessToDoctor(doctor_address).build_transaction({
            'from': patient_address,
            'gas': 500000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(patient_address),
        })
        signed_txn = w3.eth.account.sign_transaction(txn, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        flash("Access revoked successfully.", "success")
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error revoking access: {e}")
        flash("Error revoking access.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/get_patient_audit', methods=['GET'])
def get_patient_audit():
    patient_address = request.args.get('patient_address')

    if not patient_address:
        return jsonify({"error": "patient_address is required"}), 400

    patient_address = patient_address.strip()
    try:
        patient_address = w3.to_checksum_address(patient_address)
    except Exception as e:
        return jsonify({"error": f"Invalid address format: {str(e)}"}), 400

    try:
        audit_history = contract.functions.getPatientAuditHistory(patient_address).call()
        if not audit_history:
            return jsonify({"error": "No audit history found for this address"}), 404

        events_list = []
        for evt in audit_history:
            events_list.append({
                "actor": evt[0],
                "action": evt[1],
                "timestamp": evt[2]
            })
        return jsonify(events_list)

    except Exception as e:
        return jsonify({"error": f"Failed to get audit history: {str(e)}"}), 500

if __name__ == "__main__":
    FlaskUI(app=app, server="flask", fullscreen=True).run()

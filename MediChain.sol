// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract MediChain {
    // State Variables
    string public name;
    uint public transactionCount;
    address[] public patientList;
    address[] public doctorList;

    mapping(address => Patient) public patientInfo;
    mapping(address => Doctor) public doctorInfo;
    mapping(string => address) public emailToAddress;
    mapping(string => uint) public emailToDesignation;
    mapping(uint => Transactions) public transactions;
    uint[] public transactionIds; // Store the list of transaction IDs

    struct Patient {
        string name;
        string email;
        uint age;
        bool exists;
        bool policyActive; // Placeholder for future policies
        uint[] transactions;
        address[] doctorAccessList;
        Event[] medicalEvents;  // Audit history for medical events
        string[] medicalRecords; // IPFS hashes of medical records (versioned)
    }

    struct Doctor {
        string name;
        string email;
        bool exists;
        uint[] transactions;
        address[] patientAccessList;
    }

    struct Transactions {
        uint id;
        address sender;
        address receiver;
        uint value;
        bool settled;
    }

    struct Event {
        address actor;  // Who modified the record
        string action;  // Action performed (e.g., "update", "access", "delete")
        uint timestamp;  // When it happened
    }

    // Events for frontend notifications
    event MedicalRecordUpdated(address indexed patient, string ipfsHash, uint timestamp);
    event MedicalRecordDeleted(address indexed patient, uint index, uint timestamp);
    event AccessGranted(address indexed patient, address indexed doctor);
    event AccessRevoked(address indexed patient, address indexed doctor);
    event PatientRegistered(address indexed patient, string email, uint designation);
    event DoctorRegistered(address indexed doctor, string email);

    constructor() {
        name = "MediChain";
        transactionCount = 0;
    }

    // Register patients and doctors
    function register(string memory _name, uint _age, uint _designation, string memory _email, string memory _ipfsHash) public {
        require(msg.sender != address(0), "Invalid address");
        require(bytes(_name).length > 0, "Name is required");
        require(bytes(_email).length > 0, "Email is required");
        require(emailToAddress[_email] == address(0), "Email already registered");
        require(emailToDesignation[_email] == 0, "Designation already set");

        address _addr = msg.sender;
        require(!patientInfo[_addr].exists, "Already registered as patient");
        require(!doctorInfo[_addr].exists, "Already registered as doctor");

        if (_designation == 1) { // Patient
            require(_age > 0, "Age must be greater than 0");
            require(bytes(_ipfsHash).length > 0, "IPFS hash is required for patient");

            Patient storage pinfo = patientInfo[_addr];
            pinfo.name = _name;
            pinfo.email = _email;
            pinfo.age = _age;
            pinfo.exists = true;
            pinfo.medicalRecords.push(_ipfsHash);
            pinfo.medicalEvents.push(Event(_addr, "register", block.timestamp));
            patientList.push(_addr);
            emailToAddress[_email] = _addr;
            emailToDesignation[_email] = _designation;

            emit PatientRegistered(_addr, _email, _designation);

        } else if (_designation == 2) { // Doctor
            Doctor storage dinfo = doctorInfo[_addr];
            dinfo.name = _name;
            dinfo.email = _email;
            dinfo.exists = true;
            doctorList.push(_addr);
            emailToAddress[_email] = _addr;
            emailToDesignation[_email] = _designation;

            emit DoctorRegistered(_addr, _email);

        } else {
            revert("Invalid designation");
        }
    }

    // Create or update the medical record
    function createOrUpdateMedicalRecord(address _patient, string memory _ipfsHash) public {
        require(doctorInfo[msg.sender].exists, "Only registered doctors can create/update medical records");
        require(patientInfo[_patient].exists, "Patient is not registered");
        require(isDoctorAuthorized(_patient, msg.sender), "Doctor not authorized for this patient");

        // Update the medical record of the patient (versioning)
        patientInfo[_patient].medicalRecords.push(_ipfsHash);
        // Add event for auditing
        patientInfo[_patient].medicalEvents.push(Event(msg.sender, "create/update record", block.timestamp));

        emit MedicalRecordUpdated(_patient, _ipfsHash, block.timestamp);
    }

    // Delete a medical record
    function deleteMedicalRecord(address _patient, uint _index) public {
        require(patientInfo[_patient].exists, "Patient does not exist");
        // Only the patient or authorized doctor can delete
        require(msg.sender == _patient || isDoctorAuthorized(_patient, msg.sender), "Not authorized to delete records");
        uint length = patientInfo[_patient].medicalRecords.length;
        require(_index < length, "Index out of bounds");

        // Remove the record at _index by shifting and popping
        for (uint i = _index; i < length - 1; i++) {
            patientInfo[_patient].medicalRecords[i] = patientInfo[_patient].medicalRecords[i + 1];
        }
        patientInfo[_patient].medicalRecords.pop();

        // Add event for auditing
        patientInfo[_patient].medicalEvents.push(Event(msg.sender, "delete record", block.timestamp));

        emit MedicalRecordDeleted(_patient, _index, block.timestamp);
    }

    // Grant access to a doctor for a patient's medical record
    function grantAccessToDoctor(address _doctor) public {
        require(patientInfo[msg.sender].exists, "Patient not registered");
        require(doctorInfo[_doctor].exists, "Doctor not registered");
        require(!isDoctorAuthorized(msg.sender, _doctor), "Doctor already has access");

        // Add doctor to the patient's access list
        patientInfo[msg.sender].doctorAccessList.push(_doctor);
        doctorInfo[_doctor].patientAccessList.push(msg.sender);

        emit AccessGranted(msg.sender, _doctor);
    }

    // Revoke access from a doctor
    function revokeAccessToDoctor(address _doctor) public {
        require(patientInfo[msg.sender].exists, "Patient not registered");
        require(doctorInfo[_doctor].exists, "Doctor not registered");
        require(isDoctorAuthorized(msg.sender, _doctor), "Doctor does not have access");

        // Remove doctor from the access list
        removeFromList(patientInfo[msg.sender].doctorAccessList, _doctor);
        removeFromList(doctorInfo[_doctor].patientAccessList, msg.sender);

        emit AccessRevoked(msg.sender, _doctor);
    }

    // Create a transaction and store its ID
    function createTransaction(address _receiver, uint _value) public {
        require(msg.sender != _receiver, "Sender and receiver must be different");

        transactionCount++;
        Transactions memory newTxn = Transactions({
            id: transactionCount,
            sender: msg.sender,
            receiver: _receiver,
            value: _value,
            settled: false
        });

        transactions[transactionCount] = newTxn;
        transactionIds.push(transactionCount); // Add transaction ID to list

        Patient storage pinfo = patientInfo[msg.sender];
        pinfo.transactions.push(transactionCount);
        Doctor storage dinfo = doctorInfo[_receiver];
        dinfo.transactions.push(transactionCount);
    }

    // Settle a transaction (update status)
    function settleTransaction(uint _transactionId) public {
        Transactions storage txn = transactions[_transactionId];
        require(msg.sender == txn.sender || msg.sender == txn.receiver, "Not authorized to settle this transaction");
        txn.settled = true;
    }

    // Get all transactions related to a specific address
    function getTransactionsForAddress(address _addr) public view returns (Transactions[] memory) {
        if (patientInfo[_addr].exists) {
            uint[] memory txnIds = patientInfo[_addr].transactions;
            Transactions[] memory result = new Transactions[](txnIds.length);
            for (uint i = 0; i < txnIds.length; i++) {
                result[i] = transactions[txnIds[i]];
            }
            return result;
        } else if (doctorInfo[_addr].exists) {
            uint[] memory txnIds = doctorInfo[_addr].transactions;
            Transactions[] memory result = new Transactions[](txnIds.length);
            for (uint i = 0; i < txnIds.length; i++) {
                result[i] = transactions[txnIds[i]];
            }
            return result;
        } else {
            return new Transactions[](0);
        }
    }

    // Get audit history of patient records
    function getPatientAuditHistory(address _addr) view public returns (Event[] memory) {
        require(_addr != address(0), "Invalid address");
        require(patientInfo[_addr].exists, "Patient does not exist");
        return patientInfo[_addr].medicalEvents;
    }

    // Get all medical records of a patient
    function getMedicalRecords(address _addr) view public returns (string[] memory) {
        require(patientInfo[_addr].exists, "Patient does not exist");
        return patientInfo[_addr].medicalRecords;
    }

    // Get patient access list
    function getPatientAccessList(address _patient) view public returns (address[] memory) {
        require(patientInfo[_patient].exists, "Patient does not exist");
        return patientInfo[_patient].doctorAccessList;
    }

    // Get doctor access list
    function getDoctorAccessList(address _doctor) view public returns (address[] memory) {
        require(doctorInfo[_doctor].exists, "Doctor does not exist");
        return doctorInfo[_doctor].patientAccessList;
    }

    // Get all doctors
    function getAllDoctors() public view returns (address[] memory) {
        return doctorList;
    }

    // Internal function to check if a doctor is authorized for a patient
    function isDoctorAuthorized(address _patient, address _doctor) internal view returns (bool) {
        address[] memory accessList = patientInfo[_patient].doctorAccessList;
        for (uint i = 0; i < accessList.length; i++) {
            if (accessList[i] == _doctor) {
                return true;
            }
        }
        return false;
    }

    // Internal function to remove an address from a list
    function removeFromList(address[] storage Array, address addr) internal {
        require(addr != address(0), "Invalid address");
        bool found = false;
        uint index = 0;

        for (uint i = 0; i < Array.length; i++) {
            if (Array[i] == addr) {
                found = true;
                index = i;
                break;
            }
        }

        require(found, "Address not found in the list");

        if (index < Array.length - 1) {
            Array[index] = Array[Array.length - 1];
        }
        Array.pop();
    }

    // Get the length of the patient list
    function getPatientListLength() public view returns (uint) {
        return patientList.length;
    }

    // Get the length of the doctor list
    function getDoctorListLength() public view returns (uint) {
        return doctorList.length;
    }

    // Get Doctor Information
    function getDoctorInfo(address _doctor) public view returns (string memory, string memory, bool, uint[] memory, address[] memory) {
        Doctor storage d = doctorInfo[_doctor];
        return (d.name, d.email, d.exists, d.transactions, d.patientAccessList);
    }

    // Get Patient Basic Information
    function getPatientBasicInfo(address _patient) public view returns (string memory, string memory, uint, bool, bool) {
        Patient storage p = patientInfo[_patient];
        return (p.name, p.email, p.age, p.exists, p.policyActive);
    }

    // Get Patient Events Count
    function getPatientEventsCount(address _patient) public view returns (uint) {
        return patientInfo[_patient].medicalEvents.length;
    }

    // Get a specific Patient Event by index
    function getPatientEvent(address _patient, uint index) public view returns (address, string memory, uint) {
        Event storage evt = patientInfo[_patient].medicalEvents[index];
        return (evt.actor, evt.action, evt.timestamp);
    }
}

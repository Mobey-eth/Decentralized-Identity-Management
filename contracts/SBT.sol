// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

abstract contract AccessControl {
    address public owner;

    enum Roles {
        Admin,
        regular
    }

    mapping(Roles => mapping(address => bool)) public accountToRole;
    event UpdateUserRole(address _user, Roles _role);
    event DeleteUserRole(address _user, Roles _role);

    // We also can and should call our update role on the constructor and pass in
    // msg.sender and the uint 0 - to make ourselves admins from the start.
    constructor() {
        owner = msg.sender;
        updateRoles(msg.sender, 0);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Function reserved for only owner!");
        _;
    }

    modifier onlyAuthorised(address _student) {
        require(
            msg.sender == owner ||
                accountToRole[Roles.Admin][msg.sender] == true,
            "You're not authorised to call this function!"
        );

        _;
    }

    function updateRoles(address _user, uint256 _role) public onlyOwner {
        Roles role;
        _role == 0 ? role = Roles.Admin : role = Roles.regular;
        // Roles role = Roles.Admin;
        accountToRole[role][_user] = true;
        emit UpdateUserRole(_user, role);
    }

    function deleteRole(address _user, uint256 _role) public onlyOwner {
        Roles role;
        _role == 0 ? role = Roles.Admin : role = Roles.regular;
        delete accountToRole[role][_user];
        emit DeleteUserRole(_user, role);
    }
}

contract DecentralisedIdentityManagement is AccessControl {
    struct Student {
        string name;
        uint regNo;
        string department;
        uint timestamp;
    }

    struct StudentDoc {
        string name;
        uint regNo;
        string department;
        string docName;
        string docHash;
        uint timestamp;
    }

    mapping(address => Student) private students;
    mapping(uint256 => mapping(address => StudentDoc)) public studentProfiles;
    mapping(address => address[]) private profiles;

    mapping(address => bool) public Approved;
    mapping(address => bool) public approvedToDelete;

    uint256 public studentCount;
    mapping(address => uint) public studentProfileCount;

    string public name;
    string public ticker;

    uint256[] private regNumbers;
    bytes32 private nullRegNoHash =
        0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563;
    bytes32 private zeroHash =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    event Mint(address _student);
    event Burn(address _student);
    event Update(address _student);
    event SetProfile(uint256 profileID, address _student);
    event RemoveProfile(uint256 profileID, address _student);
    event StudentApproved(address STUDENT);
    event StudentRevoked(address STUDENT);
    event StudentApprovedToDelete(address STUDENT);

    constructor() {
        name = "Decentralised Identity Management";
        ticker = "DIM";
    }

    function approve(address _studentAddress) external onlyOwner {
        Approved[_studentAddress] = true;
        updateRoles(_studentAddress, 0);
        emit StudentApproved(_studentAddress);
    }

    function revokeApprove(address _studentAddress) external onlyOwner {
        Approved[_studentAddress] = false;
        deleteRole(_studentAddress, 0);
        emit StudentRevoked(_studentAddress);
    }

    function approveDeleteforStudentId(
        address _studentAddress
    ) external onlyOwner {
        approvedToDelete[_studentAddress] = true;
        emit StudentApprovedToDelete(_studentAddress);
    }

    function revokeApproveDeleteforProfile(
        address _studentAddress
    ) external onlyOwner {
        approvedToDelete[_studentAddress] = false;
    }

    function batchApprove(address[] memory _students) external onlyOwner {
        for (uint i = 0; i < _students.length; i++) {
            address person = _students[i];
            Approved[person] = true;
            updateRoles(person, 0);
            emit StudentApproved(person);
        }
    }

    function mint(
        address _student,
        string memory _name,
        uint256 _regNo,
        string memory _department
    ) external onlyAuthorised(msg.sender) {
        require(
            keccak256(abi.encodePacked(students[_student].regNo)) ==
                nullRegNoHash,
            "Student already exists"
        );
        uint _time = block.timestamp;
        students[_student] = Student(_name, _regNo, _department, _time);
        studentCount += 1;
        regNumbers.push(_regNo);
        emit Mint(_student);
    }

    function burn(address _student) external {
        require(
            msg.sender == _student || msg.sender == owner,
            "Only users and issuers have rights to delete their data"
        );
        delete students[_student];
        delete profiles[_student];
        for (uint i = 0; i <= studentProfileCount[_student]; i++) {
            delete studentProfiles[i][_student];
        }
        emit Burn(_student);
    }

    function update(
        address _student,
        string calldata _name,
        uint256 _regNo,
        string calldata _department
    ) external {
        require(
            msg.sender == _student || msg.sender == owner,
            "Only users and issuers have rights to update their data"
        );

        require(
            keccak256(abi.encodePacked(students[_student].regNo)) !=
                nullRegNoHash,
            "Student does not exist"
        );

        Student storage _person = students[_student];
        _person.name = _name;
        _person.regNo = _regNo;
        _person.department = _department;
        emit Update(_student);
    }

    function hasStudent(address _student) external view returns (bool) {
        if (keccak256(bytes(students[_student].name)) == zeroHash) {
            return false;
        } else {
            return true;
        }
    }

    function getStudent(
        address _student
    ) external view onlyOwner returns (Student memory) {
        return students[_student];
    }

    /**
     * Profiles are used by 3rd parties and individual users to store data.
     * Data is stored in a nested mapping relative to msg.sender
     * By default they can only store data on addresses that have been minted
     */
    function createProfile(
        address _student,
        string memory _name,
        uint256 _regNo,
        string memory _department,
        string memory _docName,
        string memory _docHash
    ) external {
        require(
            msg.sender == _student || msg.sender == owner,
            "Only users and issuers have right to create profiles"
        );
        require(
            keccak256(abi.encodePacked(students[_student].regNo)) !=
                nullRegNoHash,
            "Cannot create a profile for a student that has not been minted"
        );
        uint _time = block.timestamp;
        studentProfiles[studentProfileCount[_student]][_student] = StudentDoc(
            _name,
            _regNo,
            _department,
            _docName,
            _docHash,
            _time
        );
        profiles[_student].push(msg.sender);
        emit SetProfile(studentProfileCount[_student], _student);
        studentProfileCount[_student] = studentProfileCount[_student] + 1;
    }

    function getProfile(
        uint _profileID,
        address _student
    ) external view returns (StudentDoc memory) {
        return studentProfiles[_profileID][_student];
    }

    function listProfiles(
        address _student
    ) external view returns (address[] memory) {
        return profiles[_student];
    }

    function hasProfile(
        uint _profileID,
        address _student
    ) public view returns (bool) {
        if (
            keccak256(bytes(studentProfiles[_profileID][_student].name)) ==
            zeroHash
        ) {
            return false;
        } else {
            return true;
        }
    }

    function removeProfile(uint _profileID, address _student) external {
        require(
            msg.sender == _student,
            "Only users have rights to delete their profile data"
        );
        require(
            approvedToDelete[_student] == true,
            "Student needs admin approval to delete a profile"
        );
        require(hasProfile(_profileID, _student), "Profile does not exist");
        delete studentProfiles[_profileID][msg.sender];
        emit RemoveProfile(_profileID, _student);
    }
}

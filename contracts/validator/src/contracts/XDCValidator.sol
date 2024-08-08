// SPDX-License-Identifier: MIT
pragma solidity =0.4.26;

import {SafeMath} from "./libraries/SafeMath.sol";

contract XDCValidator {
    using SafeMath for uint256;

    event Vote(address _voter, address _candidate, uint256 _cap);
    event Unvote(address _voter, address _candidate, uint256 _cap);
    event Propose(address _owner, address _candidate, uint256 _cap);
    event Resign(address _owner, address _candidate);
    event Withdraw(address _owner, uint256 _blockNumber, uint256 _cap);
    event UploadedKYC(address _owner, string kycHash);
    event InvalidatedNode(address _masternodeOwner, address[] _masternodes);

    struct ValidatorState {
        address owner;
        bool isCandidate;
        uint256 cap;
        mapping(address => uint256) voters;
    }

    struct WithdrawState {
        mapping(uint256 => uint256) caps;
        uint256[] blockNumbers;
    }

    mapping(address => WithdrawState) withdrawsState;

    mapping(address => ValidatorState) public validatorsState;
    mapping(address => address[]) public voters;

    // Mapping structures added for KYC feature.
    mapping(address => string[]) public KYCString;
    mapping(address => uint) public invalidKYCCount;
    mapping(address => mapping(address => bool)) public hasVotedInvalid;
    mapping(address => address[]) public ownerToCandidate;
    address[] public owners;

    address[] public candidates;

    uint256 public candidateCount = 0;
    uint256 public ownerCount = 0;
    uint256 public minCandidateCap;
    uint256 public minVoterCap;
    uint256 public maxValidatorNumber;
    uint256 public candidateWithdrawDelay;
    uint256 public voterWithdrawDelay;
    // owner => invalid
    mapping(address => bool) public invalidOwner;
    // candaite => invalid
    mapping(address => bool) public invalidCandidate;

    struct PendingKYCState {
        uint256 blockNumber;
        string kycHash;
    }

    mapping(address => PendingKYCState) public pendingKYC;

    modifier onlyValidCandidateCap() {
        // anyone can deposit X XDC to become a candidate
        require(msg.value >= minCandidateCap, "Invalid Candidate Cap");
        _;
    }

    modifier onlyValidVoterCap() {
        require(msg.value >= minVoterCap, "Invalid Voter Cap");
        _;
    }

    modifier onlyKYCWhitelisted() {
        require(
            KYCString[msg.sender].length != 0 ||
                ownerToCandidate[msg.sender].length > 0,
            "KYC not uploaded"
        );
        _;
    }

    modifier onlyOwner(address _candidate) {
        require(
            validatorsState[_candidate].owner == msg.sender,
            "Only owner can call this function"
        );
        _;
    }

    modifier onlyCandidate(address _candidate) {
        require(
            validatorsState[_candidate].isCandidate,
            "Only candidate can call this function"
        );
        _;
    }

    modifier onlyValidCandidate(address _candidate) {
        require(!invalidCandidate[_candidate], "Invalid Candidate");
        require(validatorsState[_candidate].isCandidate, "Invalid Candidate");
        _;
    }

    modifier onlyNotCandidate(address _candidate) {
        require(!invalidCandidate[_candidate], "Invalid Candidate");
        require(
            !validatorsState[_candidate].isCandidate,
            "Already a candidate"
        );
        _;
    }

    modifier onlyValidVote(address _candidate, uint256 _cap) {
        require(
            validatorsState[_candidate].voters[msg.sender] >= _cap,
            "Invalid Vote"
        );
        if (validatorsState[_candidate].owner == msg.sender) {
            require(
                validatorsState[_candidate].voters[msg.sender].sub(_cap) >=
                    minCandidateCap,
                "Minimum cap should be maintained"
            );
        }
        _;
    }

    modifier onlyValidWithdraw(uint256 _blockNumber, uint _index) {
        require(!invalidOwner[msg.sender], "Invalid Owner");
        require(_blockNumber > 0, "Invalid block number");
        require(
            block.number >= _blockNumber,
            "Block number should be less than current block number"
        );
        require(
            withdrawsState[msg.sender].caps[_blockNumber] > 0,
            "No cap to withdraw"
        );
        require(
            withdrawsState[msg.sender].blockNumbers[_index] == _blockNumber,
            "Invalid index"
        );
        _;
    }

    constructor(
        address[] _candidates,
        uint256[] _caps,
        address _firstOwner,
        uint256 _minCandidateCap,
        uint256 _minVoterCap,
        uint256 _maxValidatorNumber,
        uint256 _candidateWithdrawDelay,
        uint256 _voterWithdrawDelay
    ) public {
        minCandidateCap = _minCandidateCap;
        minVoterCap = _minVoterCap;
        maxValidatorNumber = _maxValidatorNumber;
        candidateWithdrawDelay = _candidateWithdrawDelay;
        voterWithdrawDelay = _voterWithdrawDelay;
        candidateCount = _candidates.length;
        owners.push(_firstOwner);
        ownerCount++;
        for (uint256 i = 0; i < _candidates.length; i++) {
            candidates.push(_candidates[i]);
            validatorsState[_candidates[i]] = ValidatorState({
                owner: _firstOwner,
                isCandidate: true,
                cap: _caps[i]
            });
            voters[_candidates[i]].push(_firstOwner);
            ownerToCandidate[_firstOwner].push(_candidates[i]);
            validatorsState[_candidates[i]].voters[_firstOwner] = _caps[i];
        }
    }

    function uploadKYC(string kychash) external {
        require(!invalidOwner[msg.sender], "Invalid Owner");
        pendingKYC[msg.sender] = PendingKYCState({
            blockNumber: block.number,
            kycHash: kychash
        });
    }

    function claimKYC() external {
        require(!invalidOwner[msg.sender], "Invalid Owner");
        string memory kychash = pendingKYC[msg.sender].kycHash;
        uint256 blockNumber = pendingKYC[msg.sender].blockNumber;
        require(bytes(kychash).length > 0, "No KYC uploaded");
        require(
            block.number > blockNumber + 10 * 43200,
            "KYC not verified yet"
        );

        pendingKYC[msg.sender].blockNumber = 0;
        pendingKYC[msg.sender].kycHash = "";
        KYCString[msg.sender].push(kychash);

        emit UploadedKYC(msg.sender, kychash);
    }

    // propose : any non-candidate who has uploaded its KYC can become an owner by proposing a candidate.
    function propose(
        address _candidate
    )
        external
        payable
        onlyValidCandidateCap
        onlyKYCWhitelisted
        onlyNotCandidate(_candidate)
    {
        uint256 cap = validatorsState[_candidate].cap.add(msg.value);
        candidates.push(_candidate);
        validatorsState[_candidate] = ValidatorState({
            owner: msg.sender,
            isCandidate: true,
            cap: cap
        });
        validatorsState[_candidate].voters[msg.sender] = validatorsState[
            _candidate
        ].voters[msg.sender].add(msg.value);
        candidateCount = candidateCount.add(1);
        if (ownerToCandidate[msg.sender].length == 0) {
            owners.push(msg.sender);
            ownerCount++;
        }
        ownerToCandidate[msg.sender].push(_candidate);
        voters[_candidate].push(msg.sender);
        emit Propose(msg.sender, _candidate, msg.value);
    }

    function vote(
        address _candidate
    ) external payable onlyValidVoterCap onlyValidCandidate(_candidate) {
        validatorsState[_candidate].cap = validatorsState[_candidate].cap.add(
            msg.value
        );
        if (validatorsState[_candidate].voters[msg.sender] == 0) {
            voters[_candidate].push(msg.sender);
        }
        validatorsState[_candidate].voters[msg.sender] = validatorsState[
            _candidate
        ].voters[msg.sender].add(msg.value);
        emit Vote(msg.sender, _candidate, msg.value);
    }

    function getCandidates() public view returns (address[]) {
        return candidates;
    }

    function getCandidateCap(address _candidate) public view returns (uint256) {
        return validatorsState[_candidate].cap;
    }

    function getCandidateOwner(
        address _candidate
    ) public view returns (address) {
        return validatorsState[_candidate].owner;
    }

    function getVoterCap(
        address _candidate,
        address _voter
    ) public view returns (uint256) {
        return validatorsState[_candidate].voters[_voter];
    }

    function getVoters(address _candidate) public view returns (address[]) {
        return voters[_candidate];
    }

    function isCandidate(address _candidate) public view returns (bool) {
        return validatorsState[_candidate].isCandidate;
    }

    function getWithdrawBlockNumbers() public view returns (uint256[]) {
        return withdrawsState[msg.sender].blockNumbers;
    }

    function getWithdrawCap(
        uint256 _blockNumber
    ) public view returns (uint256) {
        return withdrawsState[msg.sender].caps[_blockNumber];
    }

    function unvote(
        address _candidate,
        uint256 _cap
    ) public onlyValidVote(_candidate, _cap) {
        validatorsState[_candidate].cap = validatorsState[_candidate].cap.sub(
            _cap
        );
        validatorsState[_candidate].voters[msg.sender] = validatorsState[
            _candidate
        ].voters[msg.sender].sub(_cap);

        // refund after delay X blocks
        uint256 withdrawBlockNumber = voterWithdrawDelay.add(block.number);
        withdrawsState[msg.sender].caps[withdrawBlockNumber] = withdrawsState[
            msg.sender
        ].caps[withdrawBlockNumber].add(_cap);
        withdrawsState[msg.sender].blockNumbers.push(withdrawBlockNumber);

        emit Unvote(msg.sender, _candidate, _cap);
    }

    function resign(
        address _candidate
    ) public onlyOwner(_candidate) onlyCandidate(_candidate) {
        validatorsState[_candidate].isCandidate = false;
        candidateCount = candidateCount.sub(1);

        deleteCandidate(_candidate);

        // Cleanup the ownerToCandidate mapping for the resigning candidate's owner
        address[] storage ownedCandidates = ownerToCandidate[msg.sender];
        uint256 ownedCandidatesLength = ownedCandidates.length;
        for (uint256 j = 0; j < ownedCandidatesLength; j++) {
            if (ownedCandidates[j] == _candidate) {
                ownedCandidates[j] = ownedCandidates[ownedCandidatesLength - 1];
                delete ownedCandidates[ownedCandidatesLength - 1];
                ownedCandidates.length--; // Manually decrease the array length
                break;
            }
        }

        // Optionally, consider adjusting ownerCount if needed
        if (ownedCandidates.length == 0) {
            // If specific logic is needed to manage the owners array, implement here
            deleteOwner(msg.sender);
        }

        uint256 cap = validatorsState[_candidate].voters[msg.sender];
        validatorsState[_candidate].cap = validatorsState[_candidate].cap.sub(
            cap
        );
        validatorsState[_candidate].voters[msg.sender] = 0;
        // refunding after resigning X blocks
        uint256 withdrawBlockNumber = candidateWithdrawDelay.add(block.number);
        withdrawsState[msg.sender].caps[withdrawBlockNumber] = withdrawsState[
            msg.sender
        ].caps[withdrawBlockNumber].add(cap);
        withdrawsState[msg.sender].blockNumbers.push(withdrawBlockNumber);
        emit Resign(msg.sender, _candidate);
    }

    // voteInvalidKYC : any candidate can vote for invalid KYC i.e. a particular candidate's owner has uploaded a bad KYC.
    // On securing 75% votes against an owner ( not candidate ), owner & all its candidates will lose their funds.
    function voteInvalidKYC(
        address _owner
    ) public onlyValidCandidate(msg.sender) {
        address candidateOwner = getCandidateOwner(msg.sender);

        require(!hasVotedInvalid[candidateOwner][_owner], "Already voted");
        hasVotedInvalid[candidateOwner][_owner] = true;
        invalidKYCCount[_owner] += 1;
        if ((invalidKYCCount[_owner] * 100) / getOwnerCount() >= 75) {
            // 75% owners say that the KYC is invalid
            invalidOwner[_owner] = true;
            pendingKYC[_owner].blockNumber = 0;
            pendingKYC[_owner].kycHash = "";

            (bool isOwnerNow, uint ownerIndex) = isOwner(_owner);
            if (isOwnerNow) {
                uint j = 0;
                uint count = 0;
                address[] memory allInvalidMasternodes = new address[](
                    candidates.length
                );
                address[] memory newCandidates = new address[](
                    candidates.length
                );

                for (uint i = 0; i < candidates.length; i++) {
                    address candidate = candidates[i];
                    if (getCandidateOwner(candidate) == _owner) {
                        // logic to remove cap.
                        candidateCount = candidateCount.sub(1);
                        allInvalidMasternodes[count++] = candidate;
                        invalidCandidate[candidate] = true;
                        delete validatorsState[candidate];
                        delete KYCString[_owner];
                        delete ownerToCandidate[_owner];
                        delete invalidKYCCount[_owner];
                    } else {
                        newCandidates[j++] = candidate;
                    }
                }

                // Resize the array.
                assembly {
                    mstore(newCandidates, j)
                    mstore(allInvalidMasternodes, count)
                }
                candidates = newCandidates;

                removeOwnerByIndex(ownerIndex);
                emit InvalidatedNode(_owner, allInvalidMasternodes);
            }
        }
    }

    // invalidPercent : get votes against an owner in percentage.
    function invalidPercent(
        address _owner
    ) public view onlyValidCandidate(_owner) returns (uint) {
        return ((invalidKYCCount[_owner] * 100) / getOwnerCount());
    }

    // getOwnerCount : get count of total owners; accounts who own atleast one masternode.
    function getOwnerCount() public view returns (uint) {
        return ownerCount;
    }

    // getKYC : get KYC uploaded of the owner of the given masternode or the owner themselves
    function getLatestKYC(address _address) public view returns (string) {
        if (isCandidate(_address)) {
            return
                KYCString[getCandidateOwner(_address)][
                    KYCString[getCandidateOwner(_address)].length - 1
                ];
        } else {
            return KYCString[_address][KYCString[_address].length - 1];
        }
    }

    function getHashCount(address _address) public view returns (uint) {
        return KYCString[_address].length;
    }

    function withdraw(
        uint256 _blockNumber,
        uint _index
    ) public onlyValidWithdraw(_blockNumber, _index) {
        uint256 cap = withdrawsState[msg.sender].caps[_blockNumber];
        delete withdrawsState[msg.sender].caps[_blockNumber];
        delete withdrawsState[msg.sender].blockNumbers[_index];
        msg.sender.transfer(cap);
        emit Withdraw(msg.sender, _blockNumber, cap);
    }

    function removeZeroAddresses(
        address[] memory addresses
    ) private pure returns (address[] memory) {
        address[] memory newAddresses = new address[](addresses.length);
        uint256 j = 0;
        for (uint256 i = 0; i < addresses.length; i++) {
            if (addresses[i] != address(0)) {
                newAddresses[j] = addresses[i];
                j++;
            }
        }
        // Resize the array.
        assembly {
            mstore(newAddresses, j)
        }
        return newAddresses;
    }

    function removeCandidatesZeroAddresses() external {
        address[] memory newAddresses = new address[](candidates.length);
        uint256 j = 0;
        for (uint256 i = 0; i < candidates.length; i++) {
            if (candidates[i] != address(0)) {
                newAddresses[j] = candidates[i];
                j++;
            }
        }
        // Resize the array.
        assembly {
            mstore(newAddresses, j)
        }
        candidates = newAddresses;
    }

    function removeOwnersZeroAddresses() external {
        address[] memory newAddresses = new address[](owners.length);
        uint256 j = 0;
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] != address(0)) {
                newAddresses[j] = owners[i];
                j++;
            }
        }
        // Resize the array.
        assembly {
            mstore(newAddresses, j)
        }
        owners = newAddresses;
    }

    // Efficiently remove _candidate from the candidates array
    function deleteCandidate(address candidate) private {
        uint256 candidatesLength = candidates.length;
        for (uint256 i = 0; i < candidatesLength; i++) {
            if (candidates[i] == candidate) {
                candidates[i] = candidates[candidatesLength - 1];
                delete candidates[candidatesLength - 1];
                candidates.length--; // Manually decrease the array length
                break;
            }
        }
    }

    // Efficiently remove the invalid owner from the owners array
    function deleteOwner(address owner) private {
        uint256 ownersLength = owners.length;
        for (uint k = 0; k < ownersLength; k++) {
            if (owners[k] == owner) {
                owners[k] = owners[ownersLength - 1]; // Swap with the last element
                delete owners[ownersLength - 1]; // Delete the last element
                owners.length--; // Decrease the array size
                ownerCount--; // Decrease the owner count
                break;
            }
        }
    }

    // isOwner : check if the given address is an owner or not.
    function isOwner(address owner) public view returns (bool, uint256) {
        for (uint i = 0; i < owners.length; i++) {
            if (owners[i] == owner) {
                return (true, i);
            }
        }
        return (false, 0);
    }

    function removeOwnerByIndex(uint256 index) private {
        // no need to check: index <= lastIndex
        uint256 lastIndex = owners.length - 1;
        owners[index] = owners[lastIndex];
        delete owners[lastIndex];
        owners.length--;
        ownerCount--;
    }

    function getOwnerToCandidateLength(
        address _address
    ) external view returns (uint256) {
        return ownerToCandidate[_address].length;
    }
}

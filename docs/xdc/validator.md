The `XDCValidator.sol` contract helps with decentralized identity checks (called KYC) and managing validators. It does these tasks: handles user identity verification, lets users suggest and choose validators, and allows the community to vote on whether to accept identity checks that might not pass the standards.
 
## Modifers

The contract incorporates several Modifiers to govern the execution conditions of functions, serving specific purposes as outlined below:
- **onlyValidCandidateCap**: The deposited amount (`msg.value`) must exceed `minCandidateCap`.
- **onlyValidVoterCap**: The amount deposited into the contract (`msg.value`) must be greater than `minVoteCap`.
- **onlyKYCWhitelisted**: A KYC record is required, or the address must have proposed or owns another candidate.
- **onlyOwner(address _candidate)**: restricts calls to the owner associated with the specified candidate.
- **onlyCandidate(address _candidate)**: allows calls only from the candidate specified.
- **onlyValidCandidate(address _candidate)**: permits calls exclusively from a legitimate candidate.
- **onlyNotCandidate(address _candidate)**: permits calls only from addresses that are not candidates.
- **onlyValidVote(address _candidate, uint256 _cap)**: requires the vote to be legitimate with respect to the candidate and the cap.
- **onlyValidWithdraw(uint256 _blockNumber, uint _index)**: demands that the block number is reasonable and valid for the withdrawal operation.

## Functions

Implementing KYC management and Validator management through several functions, with specific roles as follows:
### uploadKYC
Uploads user KYC. This operation only stores the user's verification details and does not confer owner status.
**Function Signature:** 
```solidity
function uploadKYC(string memory kychash)
```
**Parameters:** 
- `kychash` : The hash of the user's KYC information.
### propose
Owner proposes `_candidate` to become a masternode.
**Function Signature:** 
```solidity
function propose(address _candidate)
```
**Parameters:** 
- `_candidate` : The address of the nominee.

### vote

Deposits an amount not less than minVoterCap into the contract to cast a vote for the candidate.During voting, the candidate's total cap value will be updated.If it's the first time voting:

- The voter will be added to the candidate's voter list.
- The voter's stake for that candidate will be updated.

**Function Signature:** 
```solidity
function vote(address _candidate)
```
**Parameters:** 
- `_candidate` : The address of the candidate receiving the vote.
### unvote
Revokes a vote for a candidate, with the corresponding funds refunded after X blocks.
**Function Signature:** 
```solidity
function unvote(
    address _candidate,
    uint256 _cap
)
```
**Parameters:** 
- `_candidate` : The address of the candidate for whom the vote is to be revoked.
- `_cap` : The amount to be refunded.

### voteInvalidKYC
Allows the masternode, through a vote among masternode owner , to decide if another owner's KYC information meets the requirements. If over 75% of the owners deem it invalid, the KYC is considered Unqualified, leading to the forfeiture of funds from that owner and all their candidates.
**Function Signature:** 
```solidity
function voteInvalidKYC(address _invalidCandidate)
```
**Parameters:** 
- `_invalidCandidate` : The address of the candidate whose owner's KYC validity is under judgment.

### invalidPercent
Checks the percentage of "Invalid KYC" votes for a particular owner, indicating the level of community approval regarding that owner's KYC information.
**Function Signature:** 
```solidity
function invalidPercent(address _invalidCandidate) returns (uint)
```
**Parameters:** 
- `_invalidCandidate` : The address of the candidate whose owner's KYC recognition level needs to be queried.

The user can withdraw from candidacy and reclaim their funds upon meeting certain conditions. The process is shown in the diagram below.

```text
User ---------> resign() -----------30 days lock up period-----------> withdraw()
                [Withdraws         [Locking Period]                   [Withdraw funds
                 candidacy]                                           from contract]
```

 
### resign
Withdraws candidacy, with the corresponding deposit refunded after X blocks. This function can only be called by the owner.
**Function Signature:** 
```solidity
function resign(address _candidate)
```
**Parameters:** 
- `_candidate` : The address of the candidate wishing to withdraw their candidacy.
### withdraw
This function allows for the withdrawal of funds from the contract, exclusively available to approved candidates.
**Function Signature:** 
```solidity
function withdraw(uint256 _blockNumber, uint _index)
```
**Parameters:** 
- `_blockNumber` : The block height associated with the withdrawal request. This is used to link the withdrawal action to a specific point in the blockchain's history.
- `_index` : An index pointing to the user's current withdrawal request in the record. This helps in locating and processing the correct withdrawal operation for the candidate.
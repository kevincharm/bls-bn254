import type { HardhatUserConfig } from 'hardhat/config'
import '@nomicfoundation/hardhat-toolbox'
import 'hardhat-contract-sizer'
import 'hardhat-gas-reporter'
import * as dotenv from 'dotenv'

dotenv.config()

const config: HardhatUserConfig = {
    solidity: {
        version: '0.8.23',
        settings: {
            viaIR: false,
            optimizer: {
                enabled: true,
                runs: 1000,
            },
        },
    },
    networks: {
        hardhat: {
            chainId: 534352,
            forking: {
                enabled: true,
                url: process.env.SCROLL_URL as string,
                blockNumber: 3195700,
            },
            blockGasLimit: 10_000_000,
            accounts: {
                count: 10,
            },
        },
        scroll: {
            chainId: 534352,
            url: process.env.SCROLL_URL as string,
            accounts: [process.env.MAINNET_PK as string],
        },
        scrollSepolia: {
            chainId: 534351,
            url: process.env.SCROLL_SEPOLIA_URL as string,
            accounts: [process.env.MAINNET_PK as string],
        },
    },
    gasReporter: {
        enabled: true,
        currency: 'USD',
        gasPrice: 1,
    },
    etherscan: {
        apiKey: {
            mainnet: process.env.ETHERSCAN_API_KEY as string,
            scroll: process.env.SCROLLSCAN_API_KEY as string,
            scrollSepolia: process.env.SCROLLSCAN_API_KEY as string,
        },
        customChains: [
            {
                network: 'scroll',
                chainId: 534352,
                urls: {
                    apiURL: 'https://api.scrollscan.com/api',
                    browserURL: 'https://scrollscan.com',
                },
            },
            {
                network: 'scrollSepolia',
                chainId: 534351,
                urls: {
                    apiURL: 'https://api-sepolia.scrollscan.com/api',
                    browserURL: 'https://sepolia.scrollscan.dev',
                },
            },
        ],
    },
    contractSizer: {
        alphaSort: true,
        disambiguatePaths: false,
        runOnCompile: false,
        strict: true,
    },
}

export default config

const crypto = require('crypto');
const crypto1 = require('crypto-js');
const net = require('net');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat")

class Administrator {
    constructor() {
        this.PORT = 1000;
        this.initializeServer();
    }

    initializeServer() {
        const server = net.createServer((socket) => {
            socket.on('data', (data) => {
                this.handleClientData(socket, data.toString());
            });

            socket.on('end', () => {
                console.log('Client disconnected');
            });
        });

        server.listen(this.PORT, () => {
            console.log(`Server listening on port ${this.PORT}`);
        });
    }

   async handleClientData(socket, data) {
        try {
            const input = data.trim();
            const Message_1 = input.split(' ');
            const mode = Message_1[0];
            const user_id = Message_1[1];
            console.log(`${mode} ${user_id}`);

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 2   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            const challenge = this.generateChallenge();
            const message_2 = challenge.join(' ');
            console.log(message_2);
            await socket.write(message_2 + '\n');
            console.log("1!!!");

            ///Fuzzy/////
            
            //////////////Fuzzy///////////  
            ////////////////Hash//////////////////
            // function hash(message) {
            //     // getInstance() method is called with algorithm SHA-256
            //     const md = require('crypto').createHash('sha256');
            
            //     // digest() method is called
            //     // to calculate the message digest of the input string
            //     // returned as an array of byte
            //     const messageDigest = md.update(message).digest();
            
            //     // Convert the byte array into a hexadecimal representation
            //     const hashtext = messageDigest.toString('hex');
            
            //     // Add preceding 0s to make it 32 bits
            //     return hashtext.padStart(32, '0');
            // } 

            function hash(message) {
                const hash = crypto1.SHA256(message);
                return BigInt('0x' + hash.toString(crypto1.enc.Hex));
            }
            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 3   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   
            const input2 =  data.trim(); // await this.readFromSocket(socket);
            const Message_3 = input2.split(' '); 
            const alpha = Message_3[0];
            console.log('CHeck');
            console.log(input2);
            console.log(alpha);
            const Ru = Message_3[1];
            const t = hash(Ru);
            console.log(t);
            console.log(alpha);
            console.log("111");
            
            
            //////////////Blockchain Interaction///////////////////////
            // const IoTContract = await ethers.getContractFactory("IoT");
            // const lock= await IoTContract.deploy()
            // const txReceipt = await lock.deployTransaction.wait();
            // const transactionHash = txReceipt.transactionHash;
            // const blockNumber = txReceipt.blockNumber;
            // const contractCreator = txReceipt.from;
            // const CA= lock.address;
            // const transactionFee = ethers.utils.formatEther(txReceipt.gasUsed.mul(lock.deployTransaction.gasPrice));
            // const gasUsed = txReceipt.gasUsed.toString();
            // console.log('Transaction Hash:', transactionHash);
            // console.log('Contract Address:', CA);

            // /////////////////V/////////////////////////////////
            // const [deployer] = await ethers.getSigners();
            // const contract = await ethers.getContractAt('IoT', contractAddress, deployer);
            // const t1 = ethers.BigNumber.from(t);
            // const tx = await contract.addUnD(t1, t1);
            // console.log('Hi');
            // const receipt = await tx.wait();
            // const TH2 = receipt.transactionHash;
            // // //////////////////M4//////////////////////////////
            // console.log('Transaction Hash:', TH2);
            //////////////////////Message///////////////////////
            // Function to generate a pseudo-identity
            // function generatePseudoIdentity() {
            // const pseudoIdentity = crypto.randomBytes(16).toString('hex');
            // return pseudoIdentity;
            //      }
  
            // // Function to generate a gateway secret
            // function generateGatewaySecret() {
            // const gatewaySecret = crypto.randomBytes(32).toString('hex');
            // return gatewaySecret;
            // }
            // const PI = generatePseudoIdentity();
            // const GS = generateGatewaySecret();
            // const Message_5 = TH2+" "+CA+" "+PI+" "+GS;
            // socket.write(Message_5 + '\n');
            // console.log(
            // ` deployed to ${bcontract.target}`
            // );
            

        } finally {
            socket.end();
        }
    }

    async readFromSocket(socket) {
        return new Promise((resolve) => {
            let data = '';
    
            socket.on('data', (chunk) => {
                data += chunk.toString();
            });
    
            socket.on('end', () => {
                resolve(data.trim());
            });
        });
    }

    // PUF Challenge
    generateChallenge() {
        // In a real PUF system, the challenge would be obtained from the hardware
        const challenge = crypto.randomBytes(16); // Adjust the size as needed
        return Array.from(challenge);
    }
}

class FuzzyExtractor {

    constructor(length, hamErr, repErr) {
        this.length = length;
        this.secLen = 2;
        this.numHelpers = this.calculateNumHelpers(hamErr, repErr);
        this.hashFunc = "sha256";
        this.nonceLen = 16;
    }

    parseLockerArgs() {
        this.hashFunc = "SHA-256";
        this.nonceLen = 16;
    }

    calculateNumHelpers(hamErr, repErr) {
        const bits = this.length * 8;
        const constValue = hamErr / Math.log(bits);
        const numHelpersDouble = Math.pow(bits, constValue) * Math.log(2.0 / repErr) / Math.log(2);
        return Math.round(numHelpersDouble);
    }

    generate(value) {
        const key = crypto.randomBytes(this.length);
        const keyPad = Buffer.concat([key, Buffer.alloc(this.secLen)]);

        const nonces = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.nonceLen));
        const masks = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.length));
        const digests = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.length + this.secLen));

        const vectors = new Array(this.numHelpers).fill().map((_, helper) => {
            const vector = Buffer.alloc(this.length);
            for (let i = 0; i < this.length; i++) {
                vector[i] = masks[helper][i] & value[i];
            }
            return vector;
        });

        const ciphers = new Array(this.numHelpers).fill().map(() => Buffer.alloc(this.length + this.secLen));

        for (let helper = 0; helper < this.numHelpers; helper++) {
            const dVector = vectors[helper];
            const dNonce = nonces[helper];
            const digest = this.pbkdf2Hmac(this.hashFunc, dVector, dNonce, 1, this.length + this.secLen);
            digests[helper] = digest;
        }

        for (let helper = 0; helper < this.numHelpers; helper++) {
            for (let i = 0; i < this.length + this.secLen; i++) {
                ciphers[helper][i] = digests[helper][i] ^ keyPad[i];
            }
        }

        return {
            key,
            publicHelper: {
                ciphers,
                masks,
                nonces
            }
        };
    }

    reproduce(value, helpers) {
        if (this.length !== value.length) {
            throw new Error("Cannot reproduce key for value of different length");
        }

        const ciphers = helpers.ciphers;
        const masks = helpers.masks;
        const nonces = helpers.nonces;

        const vectors = new Array(this.numHelpers).fill().map((_, helper) => {
            const vector = Buffer.alloc(this.length);
            for (let i = 0; i < this.length; i++) {
                vector[i] = masks[helper][i] & value[i];
            }
            return vector;
        });

        const digests = new Array(this.numHelpers).fill().map(() => crypto.randomBytes(this.length + this.secLen));

        for (let helper = 0; helper < this.numHelpers; helper++) {
            const dVector = vectors[helper];
            const dNonce = nonces[helper];
            const digest = this.pbkdf2Hmac(this.hashFunc, dVector, dNonce, 1, this.length + this.secLen);
            digests[helper] = digest;
        }

        const plains = new Array(this.numHelpers).fill().map(() => Buffer.alloc(this.length + this.secLen));

        for (let helper = 0; helper < this.numHelpers; helper++) {
            for (let i = 0; i < this.length + this.secLen; i++) {
                plains[helper][i] = digests[helper][i] ^ ciphers[helper][i];
            }
        }

        for (let helper = 0; helper < this.numHelpers; helper++) {
            const checkBytes = plains[helper].slice(this.length, this.length + this.secLen);
            if (checkBytes.equals(Buffer.alloc(this.secLen))) {
                return plains[helper].slice(0, this.length);
            }
        }

        return null;
    }

    pbkdf2Hmac(hashFunc, value, salt, iterations, length) {
        try {
            const hmac = crypto.createHmac(hashFunc, salt);
            const result = Buffer.alloc(length);
            const block = Buffer.concat([salt, Buffer.alloc(4)]);
            let offset = 0;

            while (offset < length) {
                block.writeUInt32BE(++iterations, salt.length);
                const u = hmac.update(block).digest();

                for (let i = 0; i < u.length && offset < length; i++) {
                    result[offset++] = u[i];
                }
            }

            return result;
        } catch (error) {
            throw new Error("Error initializing crypto");
        }
    }

    pack(bytes, offset, value) {
        bytes[offset + 0] = (value >> 24) & 0xFF;
        bytes[offset + 1] = (value >> 16) & 0xFF;
        bytes[offset + 2] = (value >> 8) & 0xFF;
        bytes[offset + 3] = value & 0xFF;
    }

    static KeyAndHelper(key, publicHelper) {
        this.key = key;
        this.publicHelper = publicHelper;
    }
    
}

async function main() {
    try {
        const AS = new Administrator();
    } catch (error) {
        console.error(error);
    }
}

main();

const crypto = require('crypto');
const crypto1 = require('crypto-js');
const net = require('net');
const hre = require("hardhat");
const { ethers, run, network } = require("hardhat")

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
        const AS = new Sensor();
    } catch (error) {
        console.error(error);
    }
}
class Sensor{
    constructor() {
        this.PORT = 1000;
        this.ID = "";
        this.initializeServer();
        this.challenge="";
        this.response="";
        this.alpha="";
        this.TH2 = "";
        this.CA = "";
        this.PI = "";
        this.GS = "";
    }

    initializeServer() {
        const server = net.createServer((socket) => {
            socket.on('data', (data) => {
                const receivedMessage = JSON.parse(data.toString());
                this.handleClientMessage(socket, receivedMessage);
            });

            socket.on('end', () => {
                console.log('Admin disconnected');
            });
        });

        server.listen(this.PORT, () => {
            console.log(`Sensor listening on port ${this.PORT}`);
        });
    }

    async handleClientMessage(socket, message) {
        //console.log(`Received message from Client: ${JSON.stringify(message)}`);
        
        // Check the type of message and execute the corresponding logic
        switch (message.type) {
            case 'Type6':
                this.processType1Message(socket, message.content);
                break;
            case 'Type9':
                this.processType3Message(socket, message.content);
                break;
            default:
                console.log(`Unknown message type: ${message.type}`);
        }
    }
    hash(message) {
        const hash = crypto1.SHA256(message);
        return BigInt('0x' + hash.toString(crypto1.enc.Hex));
    }
    convertNumbersStringToByteArray(numbersString) {
        const numberStrings = numbersString.split(/\s+/); // Split by one or more spaces
        const byteArray = new Uint8Array(numberStrings.length);
    
        for (let i = 0; i < numberStrings.length; i++) {
            try {
                // Convert each number string to byte and store in the array
                byteArray[i] = parseInt(numberStrings[i], 10);
            } catch (error) {
                // Handle the case where the string is not a valid byte
                console.error(error);
            }
        }
    
        return byteArray;
    }
    
    generateResponse(challenge) {
        // In a real PUF system, the response would be generated based on the unique physical characteristics
        // For simulation purposes, we'll use a cryptographic hash function (SHA-256) as an example
        try {
            const crypto = require('crypto');
            const digest = crypto.createHash('sha256');
            return Buffer.from(digest.update(Buffer.from(challenge)).digest());
        } catch (error) {
            console.error(error);
            return null;
        }
    }
    processType6Message(socket, content) {
        // Process Type1 message content
       // console.log(`Processing Type1 message: ${content}`);
       const challenge = this.convertNumbersStringToByteArray(content);
       const response = this.generateResponse(challenge);
       const ans = response.join(' ');
       const Ru = response.toString();
       this.ID = 'Sensor1'
       const message_1 = this.ID+" "+Ru;
        // PUF Challenge
        const responseMessage = {
            type: 'Type7',
            content: message_1
        };

        // Send response back to the Client
        this.sendMessage(socket, responseMessage);
    }

    generatePseudoIdentity() {
            const pseudoIdentity = crypto.randomBytes(16).toString('hex');
            return pseudoIdentity;
                 }
  
            // Function to generate a gateway secret
    generateGatewaySecret() {
            const gatewaySecret = crypto.randomBytes(32).toString('hex');
            return gatewaySecret;
            }
    async processType9Message(socket, content) {
        // Process Type3 message content
        console.log(`Processing Type4 message: ${content}`);
        const parts = content.split(' ');
        this.TH2 = parts[0];
        this.CA = parts[1];
        this.PI = parts[2];
        this.GS = parts[3];
        console.log('M4UA');
        console.log(this.TH2);
        console.log(this.CA);
        console.log(this.PI);
        console.log(this.GS);
        socket.end();
    }

    
    
    sendMessage(socket, message) {
        // Send the message object to the Client
        socket.write(JSON.stringify(message) + '\n');
        console.log(`Sent message to Client: ${JSON.stringify(message)}`);
    }
    generateChallenge() {
        // In a real PUF system, the challenge would be obtained from the hardware
        const challenge = crypto.randomBytes(16); // Adjust the size as needed
        return Array.from(challenge);
    }
}

// Create an instance of the Administrator
const sensor = new Sensor();

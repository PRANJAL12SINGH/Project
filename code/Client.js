const net = require('net');
const crypto = require('crypto');
const crypto1 = require('crypto-js');

class Client {
    constructor() {
        this.PORT = 1000;
        this.ID = "USER1";
        this.mode = "";
        this.initializeClient();
    }

    initializeClient() {
        const ipAddress = '127.0.0.1'; // Replace with the actual IP address if needed
        const socket = new net.Socket();

        socket.connect(this.PORT, ipAddress, () => {
            console.log('Connected to server');
            this.handleServerCommunication(socket);
        });
    }

    async handleServerCommunication(socket) {
        try {
            const outStream = socket;

            this.mode = "Registration";

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 1   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            const Message_1 = `${this.mode} ${this.ID}`;
            console.log(Message_1);
            outStream.write(Message_1 + '\n');

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 2   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            console.log("!!!!")
            
            const input = await this.readFromSocket(socket);
            console.log("!!!!")
            console.log(input);
            //////////////////////////////////////////////////////////////////////////////////
            function convertNumbersStringToByteArray(numbersString) {
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
            
            function generateResponse(challenge) {
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
            const challenge = convertNumbersStringToByteArray(input);
            const response = generateResponse(challenge);
            const ans = response.join(' ');
            console.log("!!!");
            console.log(ans);

            //////////////////////////////////////////////////////////////////////////////////
            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 3   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            // console.log(keyAndHelper.key); // Uncomment this line to print the key
            // Generating alpha

            ////Fuzzy////

            /////////////////Fuzzy/////////////////
            console.log("!!!!!");
            const fuzzyExtractor = new FuzzyExtractor(16, 4, 0.001);
            const keyAndHelper = fuzzyExtractor.generate(response);
            const S1 = Buffer.from(keyAndHelper.key).toString('utf-8');
            const alpha = hash(S1 + this.ID);
            const Ru = response.toString();
            const Message_2 = alpha + " " + Ru;
            console.log("!!!cqalled");
            console.log(Message_2);
            console.log(!outStream.destroyed);
            
            try{
                socket.write(Message_2 + '\n');
                console.log("sdasd");
            }
            catch{
                console.log("soc wr failed");
            }
            
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
            /////////////////Message////////////////
            // const input2 = await this.readFromSocket(socket);
            // const Message_5 = input2.split(' '); 
            // const TH = Message_5[0];
            // const CA = Message_5[1];
            // const PI = Message_5[2];
            // const GS = Message_5[3];
        } finally {
            socket.end();
            console.log("ssadas");
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
        const client = new Client();
    } catch (error) {
        console.error(error);
    }
}

main();

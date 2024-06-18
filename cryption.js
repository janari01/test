require('dotenv').config()
const crypto = require('crypto')
const { decrypt } = require('dotenv')


const generateKeyPair = () => {
  const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048, // 2048 bits, increase to make more harder
      publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
      },
      privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
      }
      }, (err) => {
      if (err) { return Error('error') } 
  })

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey
  }
}

const crypt = () => {
    return {
      encrypt: (key, message) => { // encrypt with public key
        const bufferMsg = Buffer.from(message, 'utf8')
        return crypto.publicEncrypt(key, bufferMsg)
      },
  
      decrypt: (key, message) => { // decrypt with private key
        return crypto.privateDecrypt(key, message)
      }
    }
}

const privateKeyCrypt = () => {
  return {
    encrypt: (privateKey, envPas) => {
      const salt = crypto.randomBytes(16)
      const envPasBuffer = Buffer.from(envPas, 'utf8')
      const key = crypto.scryptSync(envPasBuffer, salt, 16)

      const iv = crypto.randomBytes(16)
      const cipher = crypto.createCipheriv('aes-128-cbc', key, iv)
   
      let encrypted = cipher.update(privateKey, 'utf8', 'hex')
      encrypted += cipher.final('hex')

      const concatenatedData = `${salt.toString('hex')}:${iv.toString('hex')}:${encrypted}`
      const encodedData = Buffer.from(concatenatedData).toString('base64')

      return encodedData
    },
    
    decrypt: (privateKey, envPas) => {
      const concatenatedData = Buffer.from(privateKey, 'base64').toString('utf8')
      const [saltHex, ivHex, encryptedKey] = concatenatedData.split(':')
  
      const salt = Buffer.from(saltHex, 'hex')
      const iv = Buffer.from(ivHex, 'hex')
      const envPasBuffer = Buffer.from(envPas, 'utf8')
      const key = crypto.scryptSync(envPasBuffer, salt, 16)
      const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv)  
  
      let decrypted = decipher.update(encryptedKey, 'hex', 'utf8')
      decrypted += decipher.final('utf8')
  
      return decrypted
    }
  }
}

// const one = privateKeyCrypt().encrypt('mis siin toimub?', process.env.MESSAGE_KEY)
// console.log(one)
// privateKeyCrypt().decrypt(one, process.env.MESSAGE_KEY)
// console.log(privateKeyCrypt().decrypt(one, process.env.MESSAGE_KEY))

// const f = generateKeyPair()
// console.log(f.privateKey)
// console.log(f.publicKey)

module.exports = {
  generateKeyPair,
  crypt,
  privateKeyCrypt
}

// let enc = crypt().encrypt(keyGen.privateKey, 'hello there')
// console.log(enc.toString())

// console.log(crypt().decrypt(keyGen.privateKey, enc).toString())

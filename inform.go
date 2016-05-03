package mFi

import (
	"io"
	"encoding/hex"
	"log"
	"errors"
	"crypto/aes"
	"crypto/cipher"
)

// References
// https://github.com/mcrute/ubntmfi/blob/master/inform_protocol.md
// https://github.com/jk-5/unifi-inform-protocol
// https://github.com/calmh/unifi-api


// Format in order of reading
// -------------------------------------------------------------------
// MagicHeader  - 4 bytes: Magic header. Always TNBU (UBNT reversed) or 1414414933 as int
// Version		- 4 bytes: Version
// 						   0 = payload is K/V pairs seperated by newlines
// 					       1 = payload is JSON
// APMAC		- 6 bytes: Access Point MAC address
// Flags		- 2 bytes: Flags
// 						   0x01: isEncrypted != 0 then payload is encrypted
//						   0x02: isCompressed != 0 then payload is compressed
// EncV		    - 16 bytes: Initialization Vector (IV) for encryption
// Data Version	- 4 bytes: Always 1. Some kind of protocol version?
// PayloadLen   - 4 bytes: Payload length l
// Payload		- l bytes: Payload

//
// Default enc key is "ba86f2bbe107c7c57eb5f2690775c712"
//
// The encryption of the payload is aes-128-cbc, without padding.
// The encryption key is the key sent to the UAP while adopting
// it (see Adoption Process section). If the UAP is already adopted,
// you can find the encryption key in the cfg/mgmt file in the default
// ssh folder on the UAP. See the mgmt.authkey line for the encryption key.
// When decrypted, you see some json data. What all these values mean should be pretty clear.

var (
	defaultKey = "ba86f2bbe107c7c57eb5f2690775c712"
)

type InformPacket struct {
	MagicHeader string `json:"magicHeader"`
	Version int	`json:"version"`
	MACBinary []byte `json:"-"`
	MACHex string `json:"MACAddress"`
	DataVersion int	`json:"dataVersion"`
	Data string `json:"data"`
}

func ParseInformPacket(r io.Reader) ( *InformPacket, error ) {

	newPacket := InformPacket{}

	// Magic Header - 4bytes = TNBU
	bMagicHeader := make([]byte, 4)
	c1, err := r.Read(bMagicHeader)
	if( c1 != 4 || err != nil){
		return nil, err
	}
	log.Printf("Magic: %s\n", bMagicHeader)
	newPacket.MagicHeader = string(bMagicHeader)

	// Version - 4 bytes
	bVersion := make([]byte, 4)
	c2, err := r.Read(bVersion)
	if( c2 != 4 || err != nil){
		return nil, err
	}
	newPacket.Version = int(bVersion[0]) << 24 | int(bVersion[1]) << 16 | int(bVersion[2]) << 8| int(bVersion[3])
	log.Printf("Version: %d\n", newPacket.Version)

	// AP MAC Address - 6 bytes
	bApMac := make([]byte, 6)
	c3, err := r.Read(bApMac)
	if( c3 != 6 || err != nil){
		return nil, err
	}
	newPacket.MACBinary = bApMac
	newPacket.MACHex = hex.EncodeToString(bApMac)
	log.Printf("MAC: %s\n", newPacket.MACHex)

	// isEncrypted and isCompressed options on packet - 2 bytes
	bFlags := make([]byte, 2)
	c4, err := r.Read(bFlags)
	if( c4 != 2 || err != nil){
		return nil, err
	}
	isEncrypted := bFlags[0] != 0x00
	isCompressed := bFlags[1] != 0x00
	log.Printf("isEncrypted: %t\n", isEncrypted)
	log.Printf("isCompressed: %t\n", isCompressed)

	// Encryption Initialization Vector - 16 bytes
	bEncIV := make([]byte, 16)
	c5, err := r.Read(bEncIV)
	if( c5 !=  16 || err != nil){
		return nil, err
	}
	log.Printf("bEncIV: %s\n", bEncIV)

	// Data Version - 4 bytes
	bDataVersion := make([]byte, 4)
	c6, err := r.Read(bDataVersion)
	if( c6 != 4 || err != nil){
		return nil, err
	}
	newPacket.DataVersion = int(bDataVersion[0]) << 24 | int(bDataVersion[1]) << 16 | int(bDataVersion[2]) << 8| int(bDataVersion[3])
	log.Printf("DataVersion: %d\n", newPacket.DataVersion)

	// Data Length - 4 bytes
	bDataLength := make([]byte, 4)
	c7, err := r.Read(bDataLength)
	if( c7 != 4 || err != nil){
		return nil, err
	}
	dataLength := int(bDataLength[0]) << 24 | int(bDataLength[1]) << 16 | int(bDataLength[2]) << 8| int(bDataLength[3])
	log.Printf("dataLength: %d\n", dataLength)

	// Things we know now
	// isEncrypted
	// isCompressed
	// Encryption Vector
	// the data as binary and possibly compressed or encrypted

	bData := make([]byte, dataLength)
	c8, err := r.Read(bData)
	log.Printf("Read Size: %d\n", c8)
	if c8 != dataLength && !isCompressed {
		return nil, errors.New("Data is incorrect size")
	}
	if err != nil && c8 != dataLength {
		return nil, err
	}

	if isEncrypted == true {
		log.Println("Data is encrypted")
	}
	if isCompressed == true {
		log.Println("Data is compressed")
	}

	bDefaultKey, _ := hex.DecodeString(defaultKey)
	block, err := aes.NewCipher(bDefaultKey)
	if err != nil {
		log.Println("Cannot init IV")
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, bEncIV)
	mode.CryptBlocks(bData, bData)
	newPacket.Data = string(bData)


	return &newPacket, nil
}
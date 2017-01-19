package mFi

import (
	"io"
	"encoding/hex"
	"log"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
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

type RawInformPacket struct {
	MagicHeader int `json:"magicHeader"`
	Version int	`json:"version"`
	MACBinary []byte `json:"-"`
	MACHex string `json:"MACAddress"`
	DataVersion int	`json:"dataVersion"`
	Data string `json:"data"`
}

type InformPacket interface {

}

func bytesToInt(raw []byte) int {
	if len(raw) == 2 { return int(raw[2]) << 8 | int(raw[3]) }
	if len(raw) == 4 { return int(raw[0]) << 24 | int(raw[1]) << 16 | int(raw[2]) << 8 | int(raw[3]) }
	return 0;
}

func readInt(r io.Reader) (int, error) {
	bInt := make([]byte, 4)
	rCount, err := r.Read(bInt)
	if rCount != 4 { return 0, errors.New("Could not read int") }
	if err != nil { return 0, err }
	return bytesToInt(bInt), nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func ParseInformPacket(r io.Reader) ( *interface{}, error ) {

	rawPacket := RawInformPacket{}

	// Magic Header - 4bytes = 0x55424E54 = TNBU = 1430408788
	bMagicHeader, err := readInt(r)
	if err != nil { return nil, err }
	rawPacket.MagicHeader = bMagicHeader
	log.Printf("Magic: %d\n", rawPacket.MagicHeader)

	// Version - 4 bytes
	bVersion, err := readInt(r)
	if( err != nil){ return nil, err }
	rawPacket.Version = bVersion
	log.Printf("Version: %d\n", rawPacket.Version)

	// AP MAC Address - 6 bytes
	bApMac := make([]byte, 6)
	c3, err := r.Read(bApMac)
	if( c3 != 6 || err != nil){
		return nil, err
	}
	rawPacket.MACBinary = bApMac
	rawPacket.MACHex = hex.EncodeToString(bApMac)
	log.Printf("MAC: %s\n", rawPacket.MACHex)

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
	rawPacket.DataVersion = bytesToInt(bDataVersion)
	log.Printf("DataVersion: %d\n", rawPacket.DataVersion)

	// Data Length - 4 bytes
	bDataLength := make([]byte, 4)
	c7, err := r.Read(bDataLength)
	if( c7 != 4 || err != nil){
		return nil, err
	}
	dataLength := bytesToInt(bDataLength)
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

	log.Println("Decrypting packet")
	bDefaultKey, _ := hex.DecodeString(defaultKey)
	block, err := aes.NewCipher(bDefaultKey)
	if err != nil {
		log.Println("Cannot init IV")
		return nil, err
	}
	if len(bData)%aes.BlockSize != 0 {
		log.Println("ciphertext is not a multiple of the block size")
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, bEncIV)

	bDataDecoded := make([]byte, dataLength)
	mode.CryptBlocks(bData, bData)
	bData = PKCS5UnPadding(bData)
	rawPacket.Data = string(bData)

	log.Printf("RAW bData: %s\n", hex.EncodeToString(bData))
	log.Printf("RAW bDataDecoded: %s\n", hex.EncodeToString(bDataDecoded))


	log.Println("Decocing packet JSON")
	var newPacket interface{}
	jsonErr := json.Unmarshal(bData, &newPacket)
	if jsonErr != nil {
		log.Printf("Could not parse packet json: %s\n", jsonErr.Error())
		log.Println("Raw JSON:")
		log.Println(string(bData))
		return nil, jsonErr
	}

	return &newPacket, nil
}


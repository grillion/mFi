package mFi

import (
	"fmt"
	"io/ioutil"
)

type MPower struct {
	connection *MFiConnection
}

func NewMPower(connection *MFiConnection) (*MPower, error) {

	if(connection.IsLoggedIn()) {
		fmt.Printf("MPower already connected")
	} else {
		loginResp, err := connection.Login()
		if(err != nil){
			return nil, err
		}
		fmt.Printf("MPower connected: %s\n", loginResp)
	}

	return &MPower{connection: connection}, nil
}

func (m MPower) GetSensors() ([]byte, error) {
	httpResp, getErr := m.connection.HttpGet("sensors", nil)

	if(getErr != nil) {
		return nil, getErr
	}

	//Decode resp
	return ioutil.ReadAll(httpResp.Body)
}


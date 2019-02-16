package util

import (
	"crypto/cipher"
	"math/rand"
	"encoding/binary"
	"bytes"
	"net"
	"crypto/aes"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
	"errors"
	"fmt"

)

var Crypt Crypt_interface

type Crypt_interface interface {
	Encrypt([]byte) ([]byte)
	Decrypt([]byte) ([]byte, error)

	Get_passwd() ([]byte)
	Write(net.Conn, []byte) error
	Read(net.Conn) ([]byte, error)
	String() string
}

type Chacha20 struct {
	Aead     cipher.AEAD
	password []byte
}


func (cha *Chacha20) Get_passwd() []byte {
	return cha.password

}

func (cha *Chacha20) Encrypt(data []byte) []byte {

	nonce := make([]byte, 12)
	rand.Read(nonce)
	dst := cha.Aead.Seal(nil, nonce, data, []byte("0_~ ka wa ii miku ~_0"))

	return bytes.Join([][]byte{nonce, dst}, nil)

}

func (cha *Chacha20) Decrypt(data []byte) (dst []byte, err error) {
	if len(data)<12{
		return nil,errors.New("data len error")
	}
	dst, err = cha.Aead.Open(nil, data[:12], data[12:], []byte("0_~ ka wa ii miku ~_0"))

	return
}

func (cha *Chacha20) Write(con net.Conn, data []byte) error {
	return write_data(con, data, cha)

}

func (cha *Chacha20) Read(con net.Conn) ([]byte, error) {
	return read_data(con, cha)
}
func (cha *Chacha20)String() string{
	return "chacha20"
}
//==========================================

type Aes256cfb struct {
	Block    cipher.Block
	password []byte
}

func (aes256 *Aes256cfb) Get_passwd() []byte {
	return aes256.password

}

func (aes256 *Aes256cfb) Encrypt(data []byte) ([]byte) {
	iv := make([]byte, aes.BlockSize)

	rand.Read(iv)

	encrypt := cipher.NewCFBEncrypter(aes256.Block, iv)
	enc_data := make([]byte, len(data))
	encrypt.XORKeyStream(enc_data, data)
	return bytes.Join([][]byte{iv, enc_data}, nil)
}

func (aes256 *Aes256cfb) Decrypt(data []byte) ([]byte, error) {
	if len(data)<aes.BlockSize{
		return nil,errors.New("data len error")
	}
	iv := data[:aes.BlockSize]
	decrypt := cipher.NewCFBDecrypter(aes256.Block, iv)
	dec_data := make([]byte, len(data)-aes.BlockSize)
	decrypt.XORKeyStream(dec_data, data[aes.BlockSize:])
	return dec_data, nil
}

func (aes256 *Aes256cfb) Write(con net.Conn, data []byte) error {
	return write_data(con, data, aes256)

}

func (aes256 *Aes256cfb) Read(con net.Conn) ([]byte, error) {
	return read_data(con, aes256)
}

func (*Aes256cfb)String() string{
	return "aes-256-cfb"
}

//===============================================================

type None struct{

}

func (*None) Encrypt(b []byte) ([]byte) {
	return b
}

func (*None) Decrypt(b []byte) ([]byte, error) {
	return b ,nil
}

func (*None) Get_passwd() ([]byte) {
	return []byte{}
}

func (n *None) Write(con net.Conn,b []byte) error {
	return write_data(con, b, n)
}

func (n *None) Read(con net.Conn) ([]byte, error) {
	return read_data(con,n)
}
func ( *None)String()string {
	return "none"
}
//===============================================================
func Get_none_crypt()Crypt_interface{
	return &None{}
}

func Get_crypt(method, password string) Crypt_interface {
	switch method{
	case "chacha20":
		aead, err := chacha20poly1305.New([]byte(password))
		if err != nil {
			log.Fatal(err)
		}
		return &Chacha20{
			Aead:     aead,
			password: []byte(password),
		}

	case "aes-256-cfb":
		block, err := aes.NewCipher([]byte(password))
		if err != nil {
			log.Fatal(err)
		}

		return &Aes256cfb{
			Block:    block,
			password: []byte(password),
		}



	default:
		log.Fatal("unsupport encrypt method")
		return nil
	}

}

func write_data(con net.Conn, data []byte, crypt Crypt_interface) error {
	data_len := make([]byte, 2)
	enc_data := crypt.Encrypt(data)

	binary.BigEndian.PutUint16(data_len, uint16(len(enc_data)))

	if _, err := con.Write(bytes.Join([][]byte{data_len, enc_data}, nil)); err != nil {
		return err
	}
	return nil
}

func read_data(con net.Conn, crypt Crypt_interface) ([]byte, error) {
	data_len, err := Read_data_len(con)

	if err != nil {

		return nil, err
	}
	enc_data, err := Read_tcp_data(con, data_len)

	if err!=nil{
		return nil, errors.New(fmt.Sprintf("can not read full data : %s",err.Error()))
	}else{
		dec_data, err := crypt.Decrypt(enc_data)
		if err!=nil{
			Log.Println("decrypt err:"+err.Error())
		}
		return dec_data, err
	}


}

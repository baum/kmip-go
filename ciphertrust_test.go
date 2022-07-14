package kmip_test

import (
	"bufio"
	"fmt"
	"testing"

	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/baum/kmip-go"
	"github.com/baum/kmip-go/kmip14"
	"github.com/baum/kmip-go/ttlv"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// KMIP version
const protocolMajor = 1
const protocolMinor = 4

/* go test -v -timeout 30s -run ^TestCipherTrust$ github.com/baum/kmip-go */
func TestCipherTrust(t *testing.T) {
	//
	// Connect
	//
	conn := Connect("10.0.2.15:5696")
	defer conn.Close()

	//
	// DiscoverVersions
	//
	respMsg, decoder := Send(conn, kmip14.OperationDiscoverVersions, kmip.DiscoverVersionsRequestPayload{
		ProtocolVersion: []kmip.ProtocolVersion{
			{ProtocolVersionMajor: protocolMajor, ProtocolVersionMinor: protocolMinor},
		},
	})
	bi := assertRespSuccess(t, respMsg, kmip14.OperationDiscoverVersions)
	var respDiscoverVersionsPayload kmip.DiscoverVersionsResponsePayload
	err := decoder.DecodeValue(&respDiscoverVersionsPayload, bi.ResponsePayload.(ttlv.TTLV))
	require.NoError(t, err)
	assert.Len(t, respDiscoverVersionsPayload.ProtocolVersion, 1)
	pv := respDiscoverVersionsPayload.ProtocolVersion[0]
	assert.Equal(t, protocolMajor, pv.ProtocolVersionMajor)
	assert.Equal(t, protocolMinor, pv.ProtocolVersionMinor)

	//
	// Register
	//
	registerPayload := kmip.RegisterRequestPayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
		SymmetricKey: &kmip.SymmetricKey{
			kmip.KeyBlock{
				KeyFormatType: kmip14.KeyFormatTypeRaw,
				KeyValue: kmip.KeyValue{
					KeyMaterial: RandomBytes(32),
				},
				CryptographicLength:    256,
				CryptographicAlgorithm: kmip14.CryptographicAlgorithmAES,
			},
		},
	}
	registerPayload.TemplateAttribute.Append(kmip14.TagCryptographicUsageMask, kmip14.CryptographicUsageMaskExport)
	respMsg, decoder = Send(conn, kmip14.OperationRegister, registerPayload)
	bi = assertRespSuccess(t, respMsg, kmip14.OperationRegister)
	var registerRespPayload kmip.RegisterResponsePayload
	err = decoder.DecodeValue(&registerRespPayload, bi.ResponsePayload.(ttlv.TTLV))
	require.NoError(t, err)
	assert.NotEmpty(t, registerRespPayload.UniqueIdentifier)

	//
	// Get
	//
	respMsg, decoder = Send(conn, kmip14.OperationGet, kmip.GetRequestPayload{
		UniqueIdentifier: registerRespPayload.UniqueIdentifier,
	})
	bi = assertRespSuccess(t, respMsg, kmip14.OperationGet)
	var getRespPayload kmip.GetResponsePayload
	err = decoder.DecodeValue(&getRespPayload, bi.ResponsePayload.(ttlv.TTLV))
	require.NoError(t, err)
	assert.NotEmpty(t, getRespPayload.UniqueIdentifier)
	assert.Equal(t, registerRespPayload.UniqueIdentifier, getRespPayload.UniqueIdentifier)
	assert.Equal(t, kmip14.ObjectTypeSymmetricKey, getRespPayload.ObjectType)
	assert.NotNil(t, getRespPayload.SymmetricKey)
	assert.Equal(t, registerPayload.SymmetricKey, getRespPayload.SymmetricKey)

	//
	// Destroy
	//
	respMsg, decoder = Send(conn, kmip14.OperationDestroy, kmip.DestroyRequestPayload{
		UniqueIdentifier: registerRespPayload.UniqueIdentifier,
	})
	bi = assertRespSuccess(t, respMsg, kmip14.OperationDestroy)
	var destroyRespPayload kmip.DestroyResponsePayload
	err = decoder.DecodeValue(&destroyRespPayload, bi.ResponsePayload.(ttlv.TTLV))
	require.NoError(t, err)
	assert.NotEmpty(t, destroyRespPayload.UniqueIdentifier)
	assert.Equal(t, registerRespPayload.UniqueIdentifier, destroyRespPayload.UniqueIdentifier)
}

func assertRespSuccess(t *testing.T, respMsg kmip.ResponseMessage, operation kmip14.Operation) kmip.ResponseBatchItem {
	assert.Equal(t, 1, respMsg.ResponseHeader.BatchCount)
	assert.Len(t, respMsg.BatchItem, 1)
	bi := respMsg.BatchItem[0]
	assert.Equal(t, operation, bi.Operation)
	assert.NotEmpty(t, bi.UniqueBatchItemID)
	assert.Equal(t, kmip14.ResultStatusSuccess, bi.ResultStatus)

	return bi
}

func RandomBytes(numBytes int) []byte {
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return randomBytes
}

func Connect(endpoint string) *tls.Conn {
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   "kmip.ciphertrustmanager.local",
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", endpoint, tlsConfig)
	if err != nil {
		panic(err)
	}

	/* TODO: handle Read Write timeouts
	if ReadTimeout != 0 {
		_ = conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	}

	if WriteTimeout != 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	}
	*/
	if err = conn.Handshake(); err != nil {
		panic(err)
	}

	return conn
}

func Send(conn *tls.Conn, operation kmip14.Operation, payload interface{}) (kmip.ResponseMessage, *ttlv.Decoder) {
	biID := uuid.New()

	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: protocolMajor,
				ProtocolVersionMinor: protocolMinor,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				UniqueBatchItemID: biID[:],
				Operation:         operation,
				RequestPayload:    payload,
			},
		},
	}

	req, err := ttlv.Marshal(msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(req)

	_, err = conn.Write(req)
	if err != nil {
		panic(err)
	}

	decoder := ttlv.NewDecoder(bufio.NewReader(conn))
	resp, err := decoder.NextTTLV()
	if err != nil {
		panic(err)
	}

	fmt.Println(resp)

	var respMsg kmip.ResponseMessage
	err = decoder.DecodeValue(&respMsg, resp)
	if err != nil {
		panic(err)
	}

	return respMsg, decoder
}

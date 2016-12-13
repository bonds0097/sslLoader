package sslloader

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/Sirupsen/logrus"
)

const (
	sslCertFilename string = "ssl_cert.pem"
	sslKeyFilename  string = "ssl_key.pem"
)

// WriteSSLFiles writes cert and key data to the filesystem and returns the
// file paths.
func WriteSSLFiles(dir string, certData, keyData []byte, logger logrus.FieldLogger) (sslCertPath,
	sslKeyPath string, err error) {
	ctx := logger.WithField("method", "loadSSLFiles")
	sslCertPath = path.Join(dir, sslCertFilename)
	sslKeyPath = path.Join(dir, sslKeyFilename)

	// Write cert and key to file.
	errF := ioutil.WriteFile(sslCertPath, certData, 0644)
	if errF != nil {
		return "", "", fmt.Errorf("failed to write cert to file: %s", errF)
	}
	ctx.WithField("file", sslCertPath).Info("Wrote cert to file.")

	errF = ioutil.WriteFile(sslKeyPath, keyData, 0644)
	if errF != nil {
		return "", "", fmt.Errorf("failed to write key to file: %s", errF)
	}
	ctx.WithField("file", sslKeyPath).Info("Wrote key to file.")

	return sslCertPath, sslKeyPath, nil
}

// LoadPEMBlockFromEnv loads a string from envvar and formats it to be a
// parseable PEM block.
func LoadPEMBlockFromEnv(envvar string) ([]byte, error) {
	s := os.Getenv(envvar)

	sA := strings.SplitAfter(s, "----- ")
	sA2 := strings.Split(sA[1], " -")

	sA = []string{sA[0], sA2[0], sA2[1]}
	sA3 := strings.Split(sA2[0], " ")

	sF := []string{sA[0]}
	sF = append(sF, sA3...)
	sF = append(sF, "-"+sA2[1])

	s = strings.Join(sF, "\n")

	b := []byte(s)

	block, rest := pem.Decode(b)
	if block == nil {
		return []byte{}, fmt.Errorf("failed to decode string as PEM block: %s", string(rest))
	}

	return b, nil
}

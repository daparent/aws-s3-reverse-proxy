package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	log "github.com/sirupsen/logrus"
)

type WrappedToken struct {
	Token            string `json:"token"`
	Accessor         string `json:"accessor"`
	Ttl              int    `json:"ttl"`
	Creation_time    string `json:"creation_time"`
	Creation_path    string `json:"creation_path"`
	Wrapped_accessor string `json:"wrapped_accessor"`
}

type S3Keys struct {
	AccessKey string
	SecretKey string
}

type S3BucketCreds struct {
	ProdWrite S3Keys
	ProdRead  S3Keys
	Users     S3Keys
	Admin     S3Keys
}

func DoesFileExist(path string) (found bool, err error) {
	if _, err = os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
	} else {
		found = true
	}

	return
}

func ParseWrappedSecret(wrappedSecretIdFilename string) (wrappedToken WrappedToken, err error) {
	FileExists, _ := DoesFileExist(wrappedSecretIdFilename)
	if FileExists {
		jsonFile, err := os.Open(wrappedSecretIdFilename)
		if err != nil {
			return WrappedToken{}, err
		}
		defer jsonFile.Close()
		var wrappedToken WrappedToken
		if err := json.NewDecoder(jsonFile).Decode(&wrappedToken); err != nil {
			return WrappedToken{}, err
		}

		// won't need the file while the system is active but also no need to leave a
		// valid wrapped secret lying around
		os.Remove(wrappedSecretIdFilename)
	}

	return WrappedToken{}, nil
}

func TokenRenew(client *vault.Client, token string) {
	secret, err := client.Auth().Token().Lookup(token)
	if err != nil {
		log.Errorf("Unable to lookup vault unwrap token, exiting renew function: %w", err)
		return
	}
	var renewable bool
	if v, ok := secret.Data["renewable"]; ok {
		renewable, _ = v.(bool)
	}

	if !renewable {
		log.Errorf("Token is not renewable, it will expire")
		return
	}

	// renew the token for 72h every 12 hours
	timeCount := 0
	for {
		time.Sleep(15 * time.Minute)
		timeCount += 15
		wrappedSecretIdFilename := "/vault-agent/token-wrapped"
		FileExists, _ := DoesFileExist(wrappedSecretIdFilename)
		if FileExists {
			// open and validate that the wrapped token has not been tampered with, if it has
			// been tampered that should be a fatal error
			_, err := ParseWrappedSecret(wrappedSecretIdFilename)
			if err != nil {
				log.Errorf("Error validating wrapped token, %w", err)
			}
			// won't need the file while the system is active but also no need to leave a
			// valid wrapped secret lying around
			os.Remove(wrappedSecretIdFilename)
		}
		if timeCount >= 720 {
			// Every 12 hours renew the token for 72 hours, on first error that gives 2 1/2 days to react
			timeCount = 0
			tokenSecret, err := client.Auth().Token().Renew(token, 86400) // 86400 is 24h in seconds
			if err != nil {
				log.Errorf("Unable to renew token for 24 hours, exiting renew function: %w", err)
				return
			} else {
				client.SetToken(tokenSecret.Auth.ClientToken)
			}
		}
	}
}

func CreateVaultConfig() (*vault.Client, error) {
	config := vault.DefaultConfig() // modify for more granular configuration
	config.Address = "https://192.168.5.20:8200"
	// config.TLSConfig().InsecureSkipVerify = true

	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSClientConfig.InsecureSkipVerify = true

	return vault.NewClient(config)
}

func GetSecretWithVaultAgentToken(opts Options) (S3BucketCreds, error) {
	client, err := CreateVaultConfig()
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	// read in the wrapped secret-id
	WrappedSecretIdFilename := "/vault-agent/token-wrapped"

	wrappedToken, err := ParseWrappedSecret(WrappedSecretIdFilename)
	if err != nil {
		return S3BucketCreds{}, errors.New("Unable to parse JSON for wrapped secret id")
	}
	unWrappedSecret, err := client.Logical().Unwrap(wrappedToken.Token)
	if err != nil {
		return S3BucketCreds{}, err
	}
	secretIdString := unWrappedSecret.Data["secret_id"].(string)

	// now that roleId and secretId are known it's time to login and get the token that lets us get at the secrets
	secretId := &auth.SecretID{FromString: secretIdString}
	appRoleAuth, err := auth.NewAppRoleAuth(opts.VaultRoleId, secretId)
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}
	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return S3BucketCreds{}, fmt.Errorf("no auth info was returned after login")
	}
	// get secret from the default mount path for KV v2 in dev mode, "secret"

	// NEED TO DELETE THE token when done, it shouldn't be good anymore anyway since it will be used the maximum 4 times
	datalakeWrite, err := client.KVv2("kv/s3").Get(context.Background(), "datalake_write")
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to read datalake-write: %w", err)
	}
	prodWrite := S3Keys{
		AccessKey: datalakeWrite.Data["accessKey"].(string),
		SecretKey: datalakeWrite.Data["secretKey"].(string),
	}
	datalakeRead, err := client.KVv2("kv/s3").Get(context.Background(), "datalake_read")
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to read datalake-read: %w", err)
	}
	prodRead := S3Keys{
		AccessKey: datalakeRead.Data["accessKey"].(string),
		SecretKey: datalakeRead.Data["secretKey"].(string),
	}
	datalakeUsers, err := client.KVv2("kv/s3").Get(context.Background(), "datalake_users")
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to read datalake-users: %w", err)
	}
	users := S3Keys{
		AccessKey: datalakeUsers.Data["accessKey"].(string),
		SecretKey: datalakeUsers.Data["secretKey"].(string),
	}
	datalakeAdmins, err := client.KVv2("kv/s3").Get(context.Background(), "datalake_amdin")
	if err != nil {
		return S3BucketCreds{}, fmt.Errorf("unable to read datalake-admin: %w", err)
	}
	admin := S3Keys{
		AccessKey: datalakeAdmins.Data["accessKey"].(string),
		SecretKey: datalakeAdmins.Data["secretKey"].(string),
	}

	s3BucketCreds := S3BucketCreds{
		ProdRead:  prodRead,
		ProdWrite: prodWrite,
		Users:     users,
		Admin:     admin,
	}

	// data map can contain more than one key-value pair,
	// in this case we're just grabbing one of them
	// value, ok := datalakeWrite.Data["accessKey"].(string)
	// if !ok {
	// 	return "", fmt.Errorf("value type assertion failed: %T %#v", datalakeWrite.Data["accessKey"], datalakeWrite.Data["accessKey"])
	// }

	return s3BucketCreds, nil
}

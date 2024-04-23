package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	log "github.com/sirupsen/logrus"
)

func CreateVaultConfig(address string, insecure bool) (*vault.Client, error) {
	config := vault.DefaultConfig() // modify for more granular configuration
	// TODO: Make this address configurable
	config.Address = address
	if insecure {
		config.TLSConfig().InsecureSkipVerify = true
	}

	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSClientConfig.InsecureSkipVerify = true

	return vault.NewClient(config)
}

func GetTokenFromRoleAndSecretIds(client *vault.Client, roleId string, secretIdString string) (string, error) {
	token := ""
	if roleId != "" && roleId != "VAULT_ROLE_ID" && secretIdString != "" && secretIdString != "VAULT_SECRET_ID" {
		secretId := &auth.SecretID{FromString: secretIdString}
		appRoleAuth, err := auth.NewAppRoleAuth(roleId, secretId)
		if err != nil {
			return token, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
		} else {
			authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
			if err != nil {
				return token, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
			} else {
				token = authInfo.Auth.ClientToken
			}
		}
	}
	return token, nil
}

func GetTokenFromFileLocation(fileLocation string) (string, error) {
	if fileLocation != "" {
		tokenBytes, err := os.ReadFile(fileLocation)
		if err != nil {
			return "", err
		}
		return strings.ReplaceAll(string(tokenBytes), "\n", ""), nil
	}
	return "", fmt.Errorf("unable to read token from file location: %s", fileLocation)
}

func GetReverseProxyToken(client *vault.Client, opts Options) (string, error) {
	if opts.VaultRoleId != "" && opts.VaultRoleId != "VAULT_ROLE_ID" {
		return GetTokenFromRoleAndSecretIds(client, opts.VaultRoleId, opts.VaultSecretId)
	} else if opts.VaultTokenLocation != "" {
		return GetTokenFromFileLocation(opts.VaultTokenLocation)
	}
	return "", fmt.Errorf("unable to determine method for retrieving the reverse proxy vault token")
}

func CreateSigner(client *vault.Client, secretName string) (string, *v4.Signer, error) {
	// TODO: make the key-value path configurable
	secret, err := client.KVv2("kv/s3").Get(context.Background(), secretName)
	if err != nil {
		return "", nil, fmt.Errorf("unable to read %s: %w", secretName, err)
	}
	keyid := secret.Data["keyid"].(string)
	return keyid,
		v4.NewSigner(credentials.NewStaticCredentialsFromCreds(credentials.Value{
			AccessKeyID:     keyid,
			SecretAccessKey: secret.Data["accessKey"].(string),
		})),
		nil
}

func GetSignersWithVaultAgentToken(opts Options) (map[string]*v4.Signer, error) {
	signers := make(map[string]*v4.Signer)
	client, err := CreateVaultConfig(opts.VaultAddress, opts.VaultInsecure)
	if err != nil {
		return signers, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	token, err := GetReverseProxyToken(client, opts)
	if err != nil {
		return signers, err
	}
	client.SetToken(token)

	// TODO: Make all of these secret names configurable
	keyid, signer, err := CreateSigner(client, "datalake_write")
	if err != nil {
		return signers, err
	}
	signers[keyid] = signer

	keyid, signer, err = CreateSigner(client, "datalake_read")
	if err != nil {
		return signers, err
	}
	signers[keyid] = signer

	keyid, signer, err = CreateSigner(client, "datalake_users")
	if err != nil {
		return signers, err
	}
	signers[keyid] = signer

	keyid, signer, err = CreateSigner(client, "datalake_admin")
	if err != nil {
		return signers, err
	}
	signers[keyid] = signer

	return signers, nil
}

/*** If token wrapping is chosen here is the starting point of that support ***/

type WrappedToken struct {
	Token            string `json:"token"`
	Accessor         string `json:"accessor"`
	Ttl              int    `json:"ttl"`
	Creation_time    string `json:"creation_time"`
	Creation_path    string `json:"creation_path"`
	Wrapped_accessor string `json:"wrapped_accessor"`
}

func GetSecretId(client *vault.Client) (string, error) {
	// read in the wrapped secret-id
	WrappedSecretIdFilename := "/vault-agent/token-wrapped"

	wrappedToken, err := ParseWrappedSecret(WrappedSecretIdFilename)
	if err != nil {
		return "", errors.New("unable to parse JSON for wrapped secret id")
	}
	unWrappedSecret, err := client.Logical().Unwrap(wrappedToken.Token)
	if err != nil {
		return "", err
	}
	return unWrappedSecret.Data["secret_id"].(string), nil
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

package daytona

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	vaultTagPath = "vault_path"
	vaultTagKey  = "vault_key"

	vaultTagPathKey = "vault_path_key"

	defaultVaultTagField = "value"
)

var ErrValueInput = errors.New("the provided value must be a struct pointer")

// UnmarshalSecrets traverses the value v recursively looking for tagged fields that
// can be populated with secret data using the provided client and optional apex.
// If the apex is provided, the tag vault_path_key is appened to the apex to construct
// the final secret path. If the tag vault_path is provided, the apex is ignored.
// A default key of 'default' is used on each path, it can be overridden using the vault_key tag.
//
//  Apex of 'secret/application' provided, combined to form 'secret/application/db_password'
//  Field string `vault_path_key:"db_password"`
//
//  Apex of 'secret/application' provided, with key override
//  Field string `vault_path_key:"db_password" vault_key:"password"`
//
//  vault_path represents a full secret path to fetch
//  Field string `vault_path:"secret/application/db_password"`
//  Field string `vault_path:"secret/application/db_password" vault_key:"password"` // key override
func UnmarshalSecrets(client *api.Client, v interface{}, apex string) error {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr {
		return ErrValueInput
	}

	val = val.Elem()
	if val.Kind() != reflect.Struct {
		return ErrValueInput
	}

	for i := 0; i < val.NumField(); i++ {
		path, valueIndex := parsePath(apex, val.Type().Field(i).Tag)

		switch val.Field(i).Kind() {
		case reflect.Struct:
			err := UnmarshalSecrets(client, val.Field(i).Addr().Interface(), apex)
			if err != nil {
				return err
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if path == "" {
				continue
			}

			var iv int64

			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}
			if val.Field(i).Kind() == reflect.Int64 && val.Field(i).Type().String() == "time.Duration" {
				var d time.Duration
				d, err = time.ParseDuration(v.(string))
				if err != nil {
					return err
				}
				iv = int64(d)
			} else {
				if value, err := v.(json.Number).Int64(); err == nil {
					iv = value
				}
			}
			val.Field(i).SetInt(iv)
		case reflect.Float32, reflect.Float64:
			if path == "" {
				continue
			}
			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}
			if value, err := v.(json.Number).Float64(); err == nil {
				val.Field(i).SetFloat(value)
			}
		case reflect.String:
			if path == "" {
				continue
			}
			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}
			if value := v.(string); value != "" {
				val.Field(i).SetString(value)
			}
		case reflect.Bool:
			if path == "" {
				continue
			}
			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}
			val.Field(i).SetBool(v.(bool))
		default:
			continue
		}
	}
	return nil
}

func parsePath(apex string, tag reflect.StructTag) (path, valueIndex string) {
	p, ok := tag.Lookup(vaultTagPath)
	if ok {
		path = p
	} else {
		// try to use an apex
		if apex != "" {
			p, ok := tag.Lookup(vaultTagPathKey)
			if ok {
				path = fmt.Sprintf("%s/%s", strings.TrimSuffix(apex, "/"), p)
			}
		}
	}

	vi, ok := tag.Lookup(vaultTagKey)
	if !ok {
		valueIndex = defaultVaultTagField
	} else {
		valueIndex = vi
	}

	return path, valueIndex
}

func fetchValue(client *api.Client, path, valueIndex string) (interface{}, error) {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("path did not return any data")
	}

	value := secret.Data[valueIndex]

	if value == nil {
		return nil, fmt.Errorf("could not extract value from data %s %s", path, valueIndex)
	}

	return value, nil
}

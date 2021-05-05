package daytona

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
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

type unmarshalSecretsConfig struct {
	apex string
}

// An UnmarshalSecretsOption is an option for the UnmarshalSecrets function
type UnmarshalSecretsOption interface {
	apply(c *unmarshalSecretsConfig)
}

// WithApex returns an UnmarshalSecretsOption sets the apex value
// for which the secrets unmarshaler should use
func WithApex(apex string) UnmarshalSecretsOption {
	return withApex(apex)
}

type withApex string

func (w withApex) apply(c *unmarshalSecretsConfig) {
	c.apex = strings.TrimSuffix(string(w), "/")
}

// UnmarshalSecrets traverses the value v recursively looking for tagged fields that
// can be populated with secret data using the provided client and optional configured apex.
// If the apex is configured, the tag vault_path_key is appended to the apex to construct
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
func UnmarshalSecrets(client *api.Client, v interface{}, opts ...UnmarshalSecretsOption) error {
	config := unmarshalSecretsConfig{}

	for _, opt := range opts {
		opt.apply(&config)
	}

	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr {
		return ErrValueInput
	}

	val = val.Elem()
	if val.Kind() != reflect.Struct {
		return ErrValueInput
	}

	for i := 0; i < val.NumField(); i++ {
		fName := val.Type().Field(i).Name
		f := val.Field(i)
		if f.Kind() == reflect.Ptr {
			if f.IsNil() {
				f.Set(reflect.New(f.Type().Elem()))
			}
			f = f.Elem()
		}

		path, valueIndex := parsePath(config.apex, val.Type().Field(i).Tag)
		switch f.Kind() {
		case reflect.Struct:
			err := UnmarshalSecrets(client, f.Addr().Interface(), opts...)
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

			if f.Kind() == reflect.Int64 && f.Type().String() == "time.Duration" {
				var d time.Duration
				dur, ok := v.(string)
				if ok {
					d, err = time.ParseDuration(dur)
					if err != nil {
						return err
					}
					iv = int64(d)
				} else {
					return fmt.Errorf("expected a string but was given type %T for field %s", v, fName)
				}
			} else {
				switch v := v.(type) {
				case json.Number:
					if value, err := v.Int64(); err == nil {
						iv = value
					} else {
						return err
					}
				case string:
					vv, err := strconv.ParseInt(v, 0, f.Type().Bits())
					if err != nil {
						return err
					}
					iv = vv
				default:
					return fmt.Errorf("expected a number or string but was given type %T for field %s", v, fName)
				}
			}
			f.SetInt(iv)
		case reflect.Float32, reflect.Float64:
			if path == "" {
				continue
			}

			var iv float64

			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}
			switch v := v.(type) {
			case json.Number:
				if value, err := v.Float64(); err == nil {
					iv = value
				} else {
					return err
				}
			case string:
				vv, err := strconv.ParseFloat(v, f.Type().Bits())
				if err != nil {
					return err
				}
				iv = vv
			default:
				return fmt.Errorf("expected a float or string but was given type %T for field %s", v, fName)
			}
			f.SetFloat(iv)
		case reflect.String:
			if path == "" {
				continue
			}
			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}
			if vv, ok := v.(string); ok {
				f.SetString(vv)
			} else {
				return fmt.Errorf("expected a string but was given type %T for field %s", v, fName)
			}
		case reflect.Bool:
			if path == "" {
				continue
			}
			v, err := fetchValue(client, path, valueIndex)
			if err != nil {
				return err
			}

			var b bool
			switch v := v.(type) {
			case bool:
				b = v
			case string:
				pb, err := strconv.ParseBool(v)
				if err != nil {
					return err
				}
				b = pb

			default:
				return fmt.Errorf("expected a bool or string but was given type %T for field %s", v, fName)
			}
			f.SetBool(b)
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
				path = fmt.Sprintf("%s/%s", apex, p)
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

package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	tagVaultPathKeyName     = "vault_path_key"
	tagVaultPathDataKeyName = "vault_path_data_key"

	tagVaultDataKeyName = "vault_data_key"

	defaultDataKeyFieldName = "value"
)

var (
	// ErrValueInput indicates the provided value is not a struct pointer
	ErrValueInput = errors.New("the provided value must be a struct pointer")
)

// SecretUnmarshler reads data from Vault and stores the result(s) in the
// a provided struct. This can be useful to inject sensitive configuration
// items directly into config structs
type SecretUnmarshler struct {
	client      *api.Client
	tokenString string
	tokenFile   string
}

// NewSecretUnmarshler returns a new SecretUnmarshler, applying any options
// that are supplied.
func NewSecretUnmarshler(opts ...Option) (*SecretUnmarshler, error) {
	var s SecretUnmarshler
	for _, opt := range opts {
		opt.Apply(&s)
	}

	if s.client == nil {
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create new vault client: %w", err)
		}
		s.client = client
	}

	if s.tokenString != "" && s.tokenFile != "" {
		return nil, errors.New("cannot use dual token sources, pick one")
	}

	if s.tokenString != "" {
		s.client.SetToken(s.tokenString)
	}

	if s.tokenFile != "" {
		b, err := os.ReadFile(s.tokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read token from %s: %w", s.tokenFile, err)
		}

		s.client.SetToken(string(b))
	}
	return &s, nil
}

// Unmarshal makes a read request to vault using the supplied vault apex path
// and stores the result(s) in the value pointed to by v. Unmarshal traverses the value v
// recursively looking for tagged fields that can be populated with secret data.
//
// (DATA EXAMPLE #1) Consider the design of the following secret path: secret/application, that contains
// several sub-keys:
//
//	API_KEY - the data being stored in the data key 'value'
//	DB_PASSWORD - the data being stored in the data key 'value'
//
// (DATA EXAMPLE #2) Consider the design of the following secret path: secret/application/configs, that contains
// several data keys
//
//	api_key
//	db_password
//
// A field tagged with 'vault_path_key' implies that the apex is a top-level secret path,
// and the value provided by 'vault_path_key' is the suffix key in the path. The full final path will
// be a combination of the apex and the path key. e.g. Using the example #1 above, an apex of secret/application
// with a 'vault_path_key' of DB_PASSWORD, will attempt to read the data stored in secret/application/DB_PASSSWORD.
// By default a data key of 'value' is used. The data key can be customized via the tag `vault_path_data_key`
//
//	Field string `vault_path_key:"DB_PASSWORD"`
//	Field string `vault_path_key:"DB_PASSWORD" vault_path_data_key:"password"` // data key override
//
// A field tagged with 'vault_data_key' implies that the apex is a full, final secret path
// and the value provided by 'vault_data_key' is the name of the data key. e.g. an apex of secret/application/configs
// with a 'vault_data_key' of db_password, will attempt to read the data stored in secret/application/configs, referncing
// the db_password data key.
//
//	Field string `vault_data_key:"db_password"`
func (su SecretUnmarshler) Unmarshal(ctx context.Context, apex string, v interface{}) error {
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

		qualified, path, valueIndex := introspect(apex, val.Type().Field(i).Tag)
		if !qualified && f.Kind() != reflect.Struct {
			continue
		}

		switch f.Kind() {
		case reflect.Struct:
			err := su.Unmarshal(ctx, path, f.Addr().Interface())
			if err != nil {
				return err
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			var iv int64

			v, err := fetchValue(ctx, su.client, path, valueIndex)
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
			var iv float64

			v, err := fetchValue(ctx, su.client, path, valueIndex)
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
			v, err := fetchValue(ctx, su.client, path, valueIndex)
			if err != nil {
				return err
			}
			if vv, ok := v.(string); ok {
				f.SetString(vv)
			} else {
				return fmt.Errorf("expected a string but was given type %T for field %s", v, fName)
			}
		case reflect.Bool:
			v, err := fetchValue(ctx, su.client, path, valueIndex)
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

func introspect(apex string, tag reflect.StructTag) (qualified bool, path string, key string) {
	pathKey, isPathKey := tag.Lookup(tagVaultPathKeyName)
	dataKey, isDataKey := tag.Lookup(tagVaultDataKeyName)

	if isPathKey && isDataKey {
		// disqualified, unsolveable
		return
	}

	path = apex
	key = defaultDataKeyFieldName

	if isPathKey {
		qualified = true
		path = fmt.Sprintf("%s/%s", apex, pathKey)
		if dk, ok := tag.Lookup(tagVaultPathDataKeyName); ok {
			key = dk
		}
	}

	if isDataKey {
		qualified = true
		key = dataKey
	}
	return
}

func fetchValue(ctx context.Context, client *api.Client, path, valueIndex string) (interface{}, error) {
	secret, err := client.Logical().ReadWithContext(ctx, path)
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

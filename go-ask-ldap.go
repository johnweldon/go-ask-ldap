package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ldap.v0"
)

const (
	unixepoch int64 = 116444736000000000
)

var (
	config            Config
	writeconfig       bool
	configfile        string
	allAttributes     []string = []string{"*"}
	shortAttributes   []string = []string{"cn", "distinguishedName"}
	defaultAttributes []string = []string{
		"accountExpires",
		"badPasswordTime",
		"badPwdCount",
		"cn",
		"displayName",
		"distinguishedName",
		"employeeType",
		"homeDirectory",
		"homeDrive",
		"lastLogon",
		"lastLogonTimestamp",
		"lockoutTime",
		"logonCount",
		"mail",
		"mailNickname",
		"manager",
		"member",
		"memberOf",
		"name",
		"pwdLastSet",
		"title",
		"userPrincipalName",
		"whenCreated",
	}
)

var verbosity [][]string = [][]string{
	shortAttributes,
	defaultAttributes,
	allAttributes,
}

type Config struct {
	BaseDn    string
	Hostname  string
	Password  string
	Port      int
	UseTLS    bool
	Username  string
	Verbosity int
}

func init() {
	flag.StringVar(&config.Hostname, "hostname", "localhost", "the FQDN of your LDAP host")
	flag.IntVar(&config.Port, "port", 389, "port number on host")
	flag.BoolVar(&config.UseTLS, "useTLS", false, "'true' if you want to use TLS")
	flag.BoolVar(&writeconfig, "writeconfig", false, "'true' if you want to write config settings out")
	flag.StringVar(&config.BaseDn, "baseDn", "", "base Dn string")
	flag.StringVar(&config.Username, "username", "", "username (user@example.com)")
	flag.StringVar(&config.Password, "password", "", "password (secret)")
	flag.StringVar(&configfile, "configfile", "~/.go-ask-ldap.conf", "config file in JSON format")
	flag.IntVar(&config.Verbosity, "verbosity", 1, "0,1,2 are the options")
}

func resolvePath(path string) string {
	if strings.Contains(path, "~") {
		if u, e := user.Current(); e == nil {
			path = strings.Replace(path, "~", u.HomeDir, -1)
		}
	}
	return filepath.Clean(path)
}

func writeConfig() {
	if !writeconfig {
		return
	}
	configfile = resolvePath(configfile)
	file, _ := os.Create(configfile)
	conf, _ := json.MarshalIndent(config, "", "  ")
	file.Write(conf)
}

func readConfig() {
	configfile = resolvePath(configfile)
	if _, err := os.Stat(configfile); err == nil {
		file, _ := os.Open(configfile)
		decoder := json.NewDecoder(file)
		decoder.Decode(&config)
	}
}

func main() {
	readConfig()
	flag.Parse()

	conn := connect()
	defer conn.Close()
	defer writeConfig()

	for _, arg := range flag.Args() {
		search(conn, arg)
	}
}

func search(conn *ldap.Conn, search string) {
	request := ldap.NewSearchRequest(config.BaseDn, ldap.ScopeWholeSubtree, ldap.DerefAlways, 10000, 30, false, search, verbosity[config.Verbosity], []ldap.Control{})
	result, err := conn.Search(request)
	if err != nil {
		log.Printf("ERROR:: %+v\n", err)
		return
	}
	fmt.Fprintf(os.Stdout, "SEARCH:: '%s'\nRESULT::\n%+v\n", search, result)
	for _, entry := range result.Entries {
		fmt.Fprintf(os.Stdout, "ENTRY: '%s'\n", entry.DN)
		for _, attribute := range entry.Attributes {
			fmt.Fprintf(os.Stdout, "    %20s:", attribute.Name)
			if len(attribute.Values) == 1 {
				fmt.Fprintf(os.Stdout, " %s\n", display(attribute.Name)(attribute.Values[0]))
			} else {
				fmt.Fprintf(os.Stdout, "\n")
				for _, val := range attribute.Values {
					fmt.Fprintf(os.Stdout, "    %20s  %s\n", "", display(attribute.Name)(val))
				}
			}
		}
	}
}

func connect() *ldap.Conn {
	conn := connectFn(config.UseTLS)()
	if err := conn.Bind(config.Username, config.Password); err != nil {
		log.Fatal("BIND: ", err)
	}
	return conn
}

func connectFn(secure bool) func() *ldap.Conn {
	if secure {
		return connectTLS
	}
	return connectPlain
}

func connectTLS() *ldap.Conn {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", config.Hostname, config.Port), tlsConfig)
	if err != nil {
		log.Fatal("CONNECT TLS: ", err)
	}
	return conn
}
func connectPlain() *ldap.Conn {
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.Hostname, config.Port))
	if err != nil {
		log.Fatal("CONNECT PLAIN: ", err)
	}
	return conn
}

func display(key string) func(string) string {
	switch key {
	case "jpegPhoto", "objectGUID", "objectSid":
		return displayBinaryFn
	case "accountExpires", "lastLogon", "lockoutTime", "lastLogonTimestamp", "pwdLastSet", "badPasswordTime":
		return displayTimestampFn
	case "whenCreated":
		return displayTimeFmtFn
	default:
		return displayStringFn
	}
}

func displayBinaryFn(val string) string {
	var buf []byte
	if len(val) > 0x1f {
		buf = []byte(val)[:0x1f]
	} else {
		buf = []byte(val)
	}
	return fmt.Sprintf("<binary %d bytes> '%s'", len(val), hex.EncodeToString(buf))
}

func displayStringFn(val string) string {
	return fmt.Sprintf("'%s'", val)
}

func displayTimeFmtFn(val string) string {
	if t, e := time.ParseInLocation("20060102150405.0Z", val, time.UTC); e == nil {
		return t.String()
	}
	return val
}

func displayTimestampFn(val string) string {
	tsval, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return fmt.Sprintf("ERROR: '%s'", err)
	}
	if tsval == 0 {
		return "n/a"
	}
	epoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	t := epoch.Add(time.Duration((tsval - unixepoch) * 100))
	return t.String()
}

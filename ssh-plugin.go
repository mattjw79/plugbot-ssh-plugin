package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/nlopes/slack"
	"golang.org/x/crypto/ssh"
)

// Options defines the available plugin modules
type Options struct {
	Username   string
	Password   string
	Hosts      []string
	PrivateKey string
	Command    string
}

// Parse will parse an options map into the struct variables
func (o *Options) Parse(options map[string]interface{}) error {
	if err := o.parseHosts(options["hosts"]); err != nil {
		return err
	}
	if err := o.parseUsername(options["username"]); err != nil {
		return err
	}
	o.parsePassword(options["password"])
	o.parsePrivateKey(options["private_key"])
	if o.Password == "" && o.PrivateKey == "" {
		return errors.New("invalid authentication configuration")
	}
	return o.parseCommand(options["command"])
}

func (o *Options) parseHosts(hosts interface{}) error {
	switch hosts.(type) {
	case []interface{}:
		his, _ := hosts.([]interface{})
		for _, hi := range his {
			if hs, ok := hi.(string); ok {
				o.Hosts = append(o.Hosts, hs)
			} else {
				return errors.New("invalid hosts configuration")
			}
		}
	case string:
		hs := hosts.(string)
		if strings.Index(hs, ",") >= 0 {
			o.Hosts = strings.Split(hs, ",")
		} else {
			o.Hosts = append(o.Hosts, hs)
		}
	default:
		return errors.New("invalid hosts configuration")
	}
	return nil
}

func (o *Options) parseCommand(cmd interface{}) error {
	switch cmd.(type) {
	case string:
		o.Command = cmd.(string)
	default:
		return errors.New("invalid command configuration")
	}
	return nil
}

func (o *Options) parseUsername(user interface{}) error {
	switch user.(type) {
	case string:
		o.Username = user.(string)
	default:
		return errors.New("invalid user configuration")
	}
	return nil
}

func (o *Options) parsePassword(pass interface{}) {
	switch pass.(type) {
	case string:
		o.Password = pass.(string)
	}
}

func (o *Options) parsePrivateKey(pKey interface{}) {
	switch pKey.(type) {
	case string:
		o.PrivateKey = pKey.(string)
	}
}

// SSHClientConfig generates a client config struct to be used with the SSH package
func (o *Options) SSHClientConfig() (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            o.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	switch {
	case o.PrivateKey != "":
		buf, err := ioutil.ReadFile(o.PrivateKey)
		if err != nil {
			return nil, err
		}

		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			return nil, err
		}

		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	case o.Username != "":
		config.Auth = []ssh.AuthMethod{ssh.Password(o.Password)}
	default:
		return nil, errors.New("no authentication secrets specified")
	}

	return config, nil
}

func main() {
	fmt.Println("This is a plugin for PlugBot and is useless by itself.")
	fmt.Println("You can find PlugBot at https://github.com/mattjw79/plugbot")
}

// Handler is the entry point for the plugin
func Handler(args ...interface{}) {
	var (
		rtm     *slack.RTM
		ev      *slack.MessageEvent
		options Options
	)

	// divide the incoming interfaces into their respective variables
	failures := 0
	for _, arg := range args {
		switch arg.(type) {
		case *slack.RTM:
			rtm = arg.(*slack.RTM)
		case *slack.MessageEvent:
			ev = arg.(*slack.MessageEvent)
		case map[string]interface{}:
			if err := options.Parse(arg.(map[string]interface{})); err != nil {
				log.Println("error parsing options:", err)
				failures++
			}
		}
	}

	// stop here if the incoming interfaces were not specified or processed correctly
	if failures > 0 {
		rtm.SendMessage(rtm.NewOutgoingMessage("something went wrong, not even attempting", ev.Channel))
		return
	}

	sshConfig, err := options.SSHClientConfig()
	if err != nil {
		log.Println("error creating SSH config:", err)
		return
	}

	// run the command on each of the hosts specified
	failures = 0
	for _, host := range options.Hosts {
		_, err := runSSHCommand(sshConfig, host, options.Command)
		if err != nil {
			log.Println("error running SSH command:", err)
			failures++
		}
	}

	// respond to the original request
	msg := "all successful"
	if failures > 0 {
		if failures == 1 {
			msg = fmt.Sprintf("there was %d failure out of %d", failures, len(options.Hosts))
		} else {
			msg = fmt.Sprintf("there were %d failures out of %d", failures, len(options.Hosts))
		}
		msg = fmt.Sprintf("%s, please have the logs checked", msg)
	}
	rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Channel))
}

func runSSHCommand(sshConfig *ssh.ClientConfig, host string, cmd string) (string, error) {
	conn, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.Output(cmd)
	return fmt.Sprintf("%s", output), err
}

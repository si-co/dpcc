package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/si-co/dpcc"

	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/log"

	"gopkg.in/urfave/cli.v1"
)

// path to the directory where website will be stored for consultation
const (
	cachePath = "/tmp/dpcccache"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = "dpcc"
	cliApp.Usage = "decentralized protocol for content consensus agreement"
	cliApp.Version = "0.1"
	groupsDef := "the group-definition-file"
	cliApp.Commands = []cli.Command{
		{
			Name:      "hashpublic",
			Usage:     "execute hash public protocol",
			ArgsUsage: groupsDef,
			Action:    cmdHashPublic,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url, u",
					Usage: "provide URL for consensus",
				},
			},
		},
	}
	cliApp.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	cliApp.Run(os.Args)
}

func cmdHashPublic(c *cli.Context) error {
	log.Info("hash public protocol request")
	URL := c.String("url")
	if URL == "" {
		log.Fatal("please provide an URL")
	}
	group := readGroup(c)
	client := dpcc.NewClient()
	resp, err := client.PublicHashRequest(group.Roster, URL)
	if err != nil {
		log.Fatal("when asking for hash public protocol", err)
	}

	// print received hashes
	for n, singleResp := range resp.Responses {
		fmt.Println("Node", n, "sent hash", base64.StdEncoding.EncodeToString(singleResp.Hash))
	}
	return nil

}

// read information about the roster
func readGroup(c *cli.Context) *app.Group {
	if c.NArg() != 1 {
		log.Fatal("Please give the group-file as argument")
	}
	name := c.Args().First()
	f, err := os.Open(name)
	log.ErrFatal(err, "Couldn't open group definition file")
	group, err := app.ReadGroupDescToml(f)
	log.ErrFatal(err, "Error while reading group definition file", err)
	if len(group.Roster.List) == 0 {
		log.ErrFatalf(err, "Empty entity or invalid group defintion in: %s",
			name)
	}
	return group
}

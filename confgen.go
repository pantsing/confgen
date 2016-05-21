package main

import (
	"encoding/xml"
	"errors"
	"github.com/codegangsta/cli"
	"github.com/qiniu/log"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var defaultUserName string = ""
var defaultPort int = 22
var defaultConfFile string = "sessions.conf"

func main() {
	app := cli.NewApp()
	app.Version = "1.0.0"
	app.Usage = "Generate SecureCRT sessions configure file for large amount hosts"
	app.UsageText = "为大量HOST快速生成SecureCRT配置文件,支持HOST分组多层嵌套,支持指定HOST用户名和端口,方便快速添加需要管理的服务器。配置文件格式请参见sessions.conf.xml"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "file,f",
			Value: defaultConfFile,
		},
		cli.StringFlag{
			Name:  "username,u",
			Value: defaultUserName,
		},
		cli.IntFlag{
			Name:  "port,p",
			Value: defaultPort,
		},
	}
	app.Action = func(c *cli.Context) {
		file := strings.TrimSpace(c.String("file"))
		if file == "" {
			file = defaultConfFile
		} else {
			defaultConfFile = file
		}
		username := strings.TrimSpace(c.String("username"))
		if username != "" {
			defaultUserName = username
		}
		port := c.Int("port")
		if port > 0 {
			defaultPort = port
		}

		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Error(err)
			return
		}
		sg := new(sessionGroup)
		sg.Name = "root"
		err = parser(sg, string(b))
		if err != nil {
			log.Error(err)
			return
		}
		generator(sg)
	}
	app.Run(os.Args)
}

type sessionGroup struct {
	Name          string
	Port          int
	Host          string
	Username      string
	SessionGroups []sessionGroup
}

func parser(sg *sessionGroup, s string) (err error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return
	}
	isEnd := false
	for len(s) > 0 {
		iProcessed := 0
		iEOL := strings.Index(s, "\n")
		if iEOL < 0 {
			iEOL = len(s)
			isEnd = true
		}
		h := strings.TrimSpace(s[:iEOL])
		if strings.HasSuffix(h, ":[") {
			iStart := strings.Index(s, ":[")
			if iStart == 0 {
				err = errors.New("empty group name")
				return
			}
			subsg := new(sessionGroup)
			subsg.Name = s[:iStart]
			iEnd := iStart + 2
			n := 1
			l := len(s)
			for i := iEnd; i < l; i++ {
				if i <= l-2 && s[i:i+2] == ":[" {
					n++
				}
				if s[i] == ']' {
					n--
				}
				if n == 0 {
					iEnd = i
					break
				}
			}
			if n != 0 {
				err = errors.New("unclosed group")
				return err
			}

			err = parser(subsg, s[iStart+2:iEnd])
			if err != nil {
				return err
			}
			//log.Info(sg.Name, "Add sub group", subsg.Name, "!")
			sg.SessionGroups = append(sg.SessionGroups, *subsg)

			iProcessed = iEnd + 1
		} else {
			if sg == nil {
				err = errors.New("invaild group")
				return
			}
			var subsg *sessionGroup
			subsg, err = hostParser(h)
			if err != nil {
				return err
			}
			//log.Info(sg.Name, "Add session", subsg.Name, "!")
			sg.SessionGroups = append(sg.SessionGroups, *subsg)
			iProcessed = iEOL + 1
		}
		if isEnd {
			break
		}
		s = strings.TrimSpace(s[iProcessed:])
	}

	return
}

func hostParser(h string) (s *sessionGroup, err error) {
	//log.Info(h)
	s = new(sessionGroup)
	p1 := strings.Index(h, "@")
	if p1 == -1 {
		s.Username = defaultUserName
	} else {
		s.Username = h[:p1]
	}
	p1++
	p2 := strings.LastIndex(h, ":")
	if p2 == -1 {
		s.Port = defaultPort
		p2 = len(h)
	} else {
		s.Port, err = strconv.Atoi(h[p2+1:])
		if err != nil {
			return nil, err
		}
	}
	s.Host = h[p1:p2]
	s.Name = s.Host
	return
}

type VanDyke struct {
	Version string
	Keys    []VanDykeKey `xml:",omitempty"`
}

type VanDykeKey struct {
	XMLName xml.Name        `xml:"key"`
	Name    string          `xml:"name,attr"`
	Strings []VanDykeString `xml:",omitempty"`
	Dwords  []VanDykeDWord  `xml:",omitempty"`
	Value   []VanDykeKey    `xml:""`
}

type VanDykeDWord struct {
	XMLName xml.Name `xml:"dword"`
	Name    string   `xml:"name,attr"`
	Value   int      `xml:",chardata"`
}

type VanDykeString struct {
	XMLName xml.Name `xml:"string"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:",chardata"`
}

//type sessionGroup struct {
//	Name          string
//	Port          int
//	Host          string
//	Username      string
//	SessionGroups []sessionGroup
//}

//type VanDykeKey struct {
//	XMLName xml.Name        `xml:"key"`
//	Name    string          `xml:"name,attr"`
//	Strings []VanDykeString `xml:",omitempty"`
//	Dwords  []VanDykeDWord  `xml:",omitempty"`
//	Value   []VanDykeKey    `xml:""`
//}

func sessionGroup2VanDykeKey(sg *sessionGroup) (k *VanDykeKey) {
	k = new(VanDykeKey)
	if sg.Name == "root" {
		k.Name = "Sessions"
	} else {
		k.Name = sg.Name
	}
	if len(sg.SessionGroups) == 0 {
		k.Strings = append(k.Strings, VanDykeString{Name: "Hostname", Value: sg.Host})
		k.Strings = append(k.Strings, VanDykeString{Name: "Username", Value: sg.Username})
		k.Strings = append(k.Strings, VanDykeString{Name: "Output Transformer Name", Value: "UTF-8"})
		k.Dwords = append(k.Dwords, VanDykeDWord{Name: "[SSH2] Port", Value: sg.Port})
		k.Dwords = append(k.Dwords, VanDykeDWord{Name: "ANSI Color", Value: 1})
	}
	for i, _ := range sg.SessionGroups {
		k.Value = append(k.Value, *sessionGroup2VanDykeKey(&sg.SessionGroups[i]))
	}

	return
}

func generator(sg *sessionGroup) {
	//<VanDyke version="3.0">
	//	<key name="Sessions">
	//		<key name="10.143.162.165">
	//			<dword name="[SSH2] Port">22</dword>
	//			<string name="Hostname">10.143.162.165</string>
	//			<string name="Username">panqing</string>
	//			<string name="Output Transformer Name">UTF-8</string>
	//			<dword name="ANSI Color">1</dword>
	//		</key>
	//	</key>
	//</VanDyke>

	crt := new(VanDyke)
	crt.Version = "3.0"
	crt.Keys = append(crt.Keys, *sessionGroup2VanDykeKey(sg))

	b, err := xml.MarshalIndent(crt, "", "\t")
	if err != nil {
		log.Error(err)
		return
	}
	content := xml.Header + string(b)
	ioutil.WriteFile(defaultConfFile+".xml",[]byte(content), 0644)
}

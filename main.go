package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strings"
	"time"

	"net/http"
	"regexp"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"net"

	"github.com/gorilla/handlers"

	"github.com/gorilla/mux"
	//	ps "github.com/mitchellh/go-ps"
	cmap "github.com/streamrail/concurrent-map"
)

type linkData struct {
	//	freerdp  string
	ip          string
	user        string
	password    string
	width       string
	height      string
	connect_cfg string
}

type Linker struct {
	rdklink_machine cmap.ConcurrentMap
}

var __ip string
var __version string = "1"
var __rdp_template string = `
screen mode id:i:1
use multimon:i:0
desktopwidth:i:%s
desktopheight:i:%s
session bpp:i:32
winposstr:s:0,1,67,44,1600,860
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:2
displayconnectionbar:i:1
disable wallpaper:i:1
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:%s
audiomode:i:0
redirectprinters:i:0
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:0
redirectposdevices:i:0
redirectdirectx:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:1
use redirection server name:i:0
drivestoredirect:s:
`
var router = mux.NewRouter()

func (this *Linker) GetRDPLinkInfo(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	port := r.FormValue("port")
	if port == "" {
		port = "3389"
	}
	a := exec.Command("netstat", "-n", "-p", "tcp")
	a.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, exec_err := a.StdoutPipe()
	a.Start()
	log_str, exec_err := ioutil.ReadAll(stdout)
	if exec_err != nil {
		//fmt.Fprintf(w, "%v", fmt.Sprintf(`{"ret":-2,"data":"%s"}`, exec_err.Error()))
		return
	}

	a.Wait()
	aa := strings.SplitN(string(log_str), "\n", -1)
	for _, sf := range aa {
		space := regexp.MustCompile(`\s+`)
		s := space.ReplaceAllString(sf, " ")
		s = strings.TrimSpace(s)
		ss := strings.Split(s, " ")
		if len(ss) < 4 {
			continue
		}
		if strings.Index(ss[1], ":"+port) != -1 && strings.Index(ss[3], "ESTABLISHED") != -1 {
			fmt.Fprintf(w, "%v", fmt.Sprintf(`{"ret":0,"ip":"%s"}`, ss[2]))
			return
		}

	}
	fmt.Fprintf(w, "%v", `{"ret":0,"ip":""}`)
}

func HTTPGet(url_str string) ([]byte, error) {
	client := &http.Client{}

	reqest, err := http.NewRequest("GET", url_str, nil)
	if err != nil {
		return nil, err
	}

	reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqest.Header.Add("Accept-Language", "ja,zh-CN;q=0.8,zh;q=0.6")
	reqest.Header.Add("Connection", "keep-alive")
	reqest.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0")

	response, err := client.Do(reqest) //提交
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("%s ErrorCode:%d", url_str, response.StatusCode)
	}

	return body, nil
}

func getRDKExecIP() []string {
	execIP := []string{}
	a := exec.Command("tasklist", "/v", "/FO:csv")
	a.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, _ := a.StdoutPipe()
	a.Start()
	log_str, _ := ioutil.ReadAll(stdout)
	processinfo := strings.Split(string(log_str), "\n")
	for _, p1 := range processinfo {
		_data := strings.Split(p1, ",")

		if len(_data) > 9 {
			if strings.Count(_data[9], ".") != 3 {
				continue
			}
			if strings.Count(_data[9], "-") != 2 {
				continue
			}
			_tem_data := strings.Replace(_data[9], `"`, ``, -1)
			_tem_data = strings.Replace(_tem_data, ` `, ``, -1)
			_tem_data = strings.Replace(_tem_data, "\n", ``, -1)
			_tem_data = strings.Replace(_tem_data, "\r", ``, -1)
			_rdptitle := strings.Split(_tem_data, "-")
			if strings.Count(_rdptitle[1], ".") == 3 {
				execIP = append(execIP, _rdptitle[1])
			}
		}
	}
	return execIP
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (this *Linker) relinkUI() {
	for true {
		execIP := getRDKExecIP()
		//		fmt.Println(execIP)
		for _, ip := range execIP {
			if !this.rdklink_machine.Has(ip) {
				fmt.Println("Kill:" + ip)
				a := exec.Command("taskkill", "/F", `/FI`, "WINDOWTITLE eq 10 - "+ip+" - *")

				stdout, exec_err := a.StderrPipe()
				a.Start()
				log_str, exec_err := ioutil.ReadAll(stdout)
				if exec_err != nil {
					fmt.Println(log_str)
				}
				a.Wait()
				this.rdklink_machine.Remove(ip)
			}
		}

		for _, ip := range this.rdklink_machine.Keys() {
			//			fmt.Println(ip)
			b_relink := false
			if !stringInSlice(ip, execIP) {
				fmt.Println("ErrorLink:" + ip)
				b_relink = true

			} else {
				//				fmt.Println("http://" + ip + ":9091/rdplink")
				res, err := HTTPGet("http://" + ip + ":9091/rdplink")
				if err != nil {
					continue
				}
				//				fmt.Println("Check:", ip)
				//				__ip = "10.103.1.11"
				if strings.Index(string(res), `"ip":"`+__ip+":") == -1 {
					fmt.Println("AnotherUserLink:" + ip)
					k := exec.Command("taskkill", "/F", `/FI`, "WINDOWTITLE eq 10 - "+ip+" - *")

					stdout, exec_err := k.StderrPipe()
					k.Start()
					log_str, exec_err := ioutil.ReadAll(stdout)
					if exec_err != nil {
						fmt.Println(log_str)
					}
					k.Wait()
					b_relink = true
				}
			}
			if b_relink {
				_data, bexists := this.rdklink_machine.Get(ip)
				if !bexists || _data == nil {
					continue
				}

				data := _data.(linkData)
				a := exec.Command("mstsc",
					data.connect_cfg,
					"/w:"+data.width,
					"/h:"+data.height)
				a.Start()
			}

		}

		time.Sleep(10 * time.Second)
	}

}

func (this *Linker) SetRDPLink(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)

	ip := r.FormValue("ip")
	if ip == "" || strings.Count(ip, ".") < 3 {
		fmt.Fprintf(w, "%v", `{"ret":-1,"msg":"ip not set"}`)
		return
	}
	if this.rdklink_machine.Has(ip) {
		_res, err := HTTPGet("http://" + ip + ":9091/rdplink")
		if err != nil {
			fmt.Fprintf(w, `{"ret":-2,"msg":"%s rdp info get failed."}`, ip)
			return
		}
		if strings.Index(string(_res), `"ip":""`) == -1 {
			fmt.Fprintf(w, `{"ret":-2,"msg":"%s already exist."}`, ip)
			return
		}
		//		data, _ := this.rdklink_machine.Get(ip)
		//		process := data.(*os.Process)

		//		err = process.Kill()
		//		if err != nil {
		//			fmt.Fprintf(w, `{"ret":-2,"msg":"Kill %s already exist failed"}`, ip)
		//			return
		//		}
	}
	relink := r.FormValue("relink")
	if relink == "" {
		relink = "false"
	}

	width := r.FormValue("width")
	if width == "" {
		width = "1600"
	}
	height := r.FormValue("height")
	if height == "" {
		height = "900"
	}

	user := r.FormValue("user")
	if user == "" {
		fmt.Fprintf(w, "%v", `{"ret":-1,"msg":"user not set"}`)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		fmt.Fprintf(w, "%v", `{"ret":-1,"msg":"password not set"}`)
		return
	}

	// Set password and user.
	cmdkey_cmd := exec.Command("cmdkey",
		"/generic:"+ip,
		"/user:"+user,
		"/pass:"+password)
	cmdkey_cmd.Start()
	cmdkey_cmd.Wait()

	// Remove unknown publisher warning.
	root_l := registry.CURRENT_USER
	k, _, err := registry.CreateKey(root_l, `Software\Microsoft\Terminal Server Client\LocalDevices`, registry.ALL_ACCESS)
	if err != nil {
		fmt.Fprintf(w, "%v", fmt.Sprintf(`{"ret":-2,"err":"%s"}`, err.Error()))
		return
	}
	defer k.Close()

	err = k.SetDWordValue(ip, uint32(8))
	if err != nil {
		fmt.Fprintf(w, "%v", fmt.Sprintf(`{"ret":-1,"err":"%s"}`, err.Error()))
		return
	}

	dir, err := ioutil.TempDir("", "fxqa_rdp")
	if err != nil {
		fmt.Println(err)
	}
	defer os.Remove(dir)
	//	fmt.Printf("%s\n", dir)
	f, err := ioutil.TempFile(dir, ip)
	if err != nil {
		fmt.Println(err)
	}
	f.WriteString(fmt.Sprintf(__rdp_template, width, height, ip))
	f.Close()

	//	fmt.Println(f.Name())
	a := exec.Command("mstsc",
		f.Name(),
		"/w:"+width,
		"/h:"+height)
	a.Start()
	if a.Process == nil {
		fmt.Fprintf(w, "%v", `{"ret":-2,"msg":"exec run error"}`)
		return
	}

	//	a.Wait()

	this.rdklink_machine.Set(ip, linkData{ip: ip, connect_cfg: f.Name(), width: width, height: height})

	fmt.Fprintf(w, "%v", `{"ret":0}`)
	//	defer os.Remove(f.Name())
}

func (this *Linker) CloseRDPLink(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)

	vars := mux.Vars(r)
	ip := vars["ip"]
	if ip == "" {
		fmt.Fprintf(w, "%v", `{"ret":-1,"msg":"ip not set"}`)
		return
	}

	if !this.rdklink_machine.Has(ip) {
		fmt.Fprintf(w, "%v", `{"ret":-2,"msg":"ip not found"}`)
		return
	}
	this.rdklink_machine.Remove(ip)
	a := exec.Command("taskkill", "/F", "/FI", "WINDOWTITLE eq 10 - "+ip+" - *")
	a.Start()
	if a.Process == nil {
		fmt.Fprintf(w, "%v", `{"ret":-2}`)
		return
	}
	a.Wait()

	fmt.Fprintf(w, "%v", `{"ret":0}`)
}

func GetEnv() map[string]string {
	getenvironment := func(data []string, getkeyval func(item string) (key, val string)) map[string]string {
		items := make(map[string]string)
		for _, item := range data {
			key, val := getkeyval(item)
			//			fmt.Println(key)
			items[key] = val
		}
		return items
	}
	environment := getenvironment(os.Environ(), func(item string) (key, val string) {
		splits := strings.Split(item, "=")
		key = splits[0]
		val = splits[1]
		return
	})

	return environment
}

func GetLocalIP(filter string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				//			case *net.IPAddr:
				//				ip = v.IP
			}

			if ip.String() == "127.0.0.1" ||
				ip == nil ||
				strings.Count(ip.String(), ".") != 3 {
				continue
			}
			if filter != "" {
				if !strings.Contains(ip.String(), filter) {
					continue
				}
			}

			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("Not found IP")
}

type resData struct {
	IP  string `json:"ip"`
	RES string `json:"res"`
}

func (this *Linker) GetRDPLinkConnectedInfo(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	datas := []resData{}
	for _, _ip := range this.rdklink_machine.Keys() {
		_machinedata, _ := this.rdklink_machine.Get(_ip)
		machinedata := _machinedata.(linkData)
		//		data :=

		datas = append(datas, resData{IP: _ip, RES: machinedata.width + "x" + machinedata.height})
	}

	resdata, _ := json.Marshal(datas)
	fmt.Fprintf(w, `{"ret":0,"data":%s}`, string(resdata))
}

//****************** Important ********************
//Remove cert check before this service running:
//reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f
//*************************************************
func main() {

	fxip := GetEnv()["FXIP"]
	if fxip == "" {
		__ip, _ = GetLocalIP("")
	} else {
		__ip = fxip
	}

	link_serv := Linker{rdklink_machine: cmap.New()}
	router.HandleFunc("/rdplink", link_serv.GetRDPLinkInfo).Methods("GET")
	router.HandleFunc("/rdplink", link_serv.SetRDPLink).Methods("POST")
	router.HandleFunc("/rdplink/{ip}", link_serv.CloseRDPLink).Methods("DELETE")

	router.HandleFunc("/rdplink-connected", link_serv.GetRDPLinkConnectedInfo).Methods("GET")

	http.Handle("/", router)
	fmt.Printf("START Port:%v Version:%v Address:%v\n", 9091, __version, __ip)
	go link_serv.relinkUI()
	http.ListenAndServe(":"+strconv.Itoa(9091), handlers.CORS(handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"POST", "GET", "DELETE"}),
		handlers.AllowedHeaders([]string{"Content-Type", "X-Requested-With"}))(router))
}

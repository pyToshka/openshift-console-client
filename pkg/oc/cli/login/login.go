package login

import (
	"errors"
	"fmt"
	"net/url"
	"net/http"
	"net/http/cookiejar"
	"golang.org/x/net/publicsuffix"
	"crypto/tls"
	curl "github.com/andelf/go-curl"
	"regexp"
	"strings"
	"io/ioutil"
	"html"
	"github.com/manifoldco/promptui"
	"os/user"
	"path/filepath"
	"os"

	"github.com/spf13/cobra"

	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	kclientcmd "k8s.io/client-go/tools/clientcmd"
	kclientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/pkg/kubectl/cmd/templates"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/genericclioptions"
	"k8s.io/kubernetes/pkg/kubectl/util/term"

	"github.com/openshift/origin/pkg/cmd/flagtypes"
	kubeconfiglib "github.com/openshift/origin/pkg/oc/lib/kubeconfig"
)

var (
	loginLong = templates.LongDesc(`
		Log in to your server and save login for subsequent use

		First-time users of the client should run this command to connect to a server,
		establish an authenticated session, and save connection to the configuration file. The
		default configuration will be saved to your home directory under
		".kube/config".

		The information required to login -- like username and password, a session token, or
		the server details -- can be provided through flags. If not provided, the command will
		prompt for user input as needed.`)

	loginExample = templates.Examples(`
		# Log in interactively
	  %[1]s login

	  # Log in to the given server with the given certificate authority file
	  %[1]s login localhost:8443 --certificate-authority=/path/to/cert.crt

	  # Log in to the given server with the given credentials (will not prompt interactively)
	  %[1]s login localhost:8443 --username=myuser --password=mypass`)
)

// NewCmdLogin implements the OpenShift cli login command
func NewCmdLogin(fullName string, f kcmdutil.Factory, streams genericclioptions.IOStreams) *cobra.Command {
	o := NewLoginOptions(streams)
	cmds := &cobra.Command{
		Use:     "login [URL]",
		Short:   "Log in to a server",
		Long:    loginLong,
		Example: fmt.Sprintf(loginExample, fullName),
		Run: func(cmd *cobra.Command, args []string) {
			kcmdutil.CheckErr(o.Complete(f, cmd, args, fullName))
			kcmdutil.CheckErr(o.Validate(cmd, kcmdutil.GetFlagString(cmd, "server"), args))

			if err := o.Run(); kapierrors.IsUnauthorized(err) {
				fmt.Fprintln(streams.Out, "Login failed (401 Unauthorized)")
				fmt.Fprintln(streams.Out, "Verify you have provided correct credentials.")

				if err, isStatusErr := err.(*kapierrors.StatusError); isStatusErr {
					if details := err.Status().Details; details != nil {
						for _, cause := range details.Causes {
							fmt.Fprintln(streams.Out, cause.Message)
						}
					}
				}

				os.Exit(1)

			} else {
				kcmdutil.CheckErr(err)
			}
		},
	}

	// Login is the only command that can negotiate a session token against the auth server using basic auth
	cmds.Flags().StringVarP(&o.Username, "username", "u", o.Username, "Username, will prompt if not provided")
	cmds.Flags().StringVarP(&o.Password, "password", "p", o.Password, "Password, will prompt if not provided")

	return cmds
}

func (o *LoginOptions) Complete(f kcmdutil.Factory, cmd *cobra.Command, args []string, commandName string) error {
	kubeconfig, err := f.ToRawKubeConfigLoader().RawConfig()
	o.StartingKubeConfig = &kubeconfig
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// build a valid object to use if we failed on a non-existent file
		o.StartingKubeConfig = kclientcmdapi.NewConfig()
	}

	unparsedTimeout := kcmdutil.GetFlagString(cmd, "request-timeout")
	timeout, err := kclientcmd.ParseTimeout(unparsedTimeout)
	if err != nil {
		return err
	}
	o.RequestTimeout = timeout

	o.CommandName = commandName
	if o.CommandName == "" {
		o.CommandName = "oc"
	}

	parsedDefaultClusterURL, err := url.Parse(defaultClusterURL)
	if err != nil {
		return err
	}
	addr := flagtypes.Addr{Value: parsedDefaultClusterURL.Host, DefaultScheme: parsedDefaultClusterURL.Scheme, AllowPrefix: true}.Default()

	if serverFlag := kcmdutil.GetFlagString(cmd, "server"); len(serverFlag) > 0 {
		if err := addr.Set(serverFlag); err != nil {
			return err
		}
		o.Server = addr.String()

	} else if len(args) == 1 {
		if err := addr.Set(args[0]); err != nil {
			return err
		}
		o.Server = addr.String()

	} else if len(o.Server) == 0 {
		if defaultContext, defaultContextExists := o.StartingKubeConfig.Contexts[o.StartingKubeConfig.CurrentContext]; defaultContextExists {
			if cluster, exists := o.StartingKubeConfig.Clusters[defaultContext.Cluster]; exists {
				o.Server = cluster.Server
			}
		}
	}

	o.CertFile = kcmdutil.GetFlagString(cmd, "client-certificate")
	o.KeyFile = kcmdutil.GetFlagString(cmd, "client-key")

	o.CAFile = kcmdutil.GetFlagString(cmd, "certificate-authority")
	o.InsecureTLS = kcmdutil.GetFlagBool(cmd, "insecure-skip-tls-verify")
	o.Token = kcmdutil.GetFlagString(cmd, "token")

	o.DefaultNamespace, _, _ = f.ToRawKubeConfigLoader().Namespace()

	o.PathOptions = kubeconfiglib.NewPathOptions(cmd)

	return nil
}

func (o LoginOptions) Validate(cmd *cobra.Command, serverFlag string, args []string) error {
	if len(args) > 1 {
		return errors.New("Only the server URL may be specified as an argument")
	}

	if (len(serverFlag) > 0) && (len(args) == 1) {
		return errors.New("--server and passing the server URL as an argument are mutually exclusive")
	}

	if (len(o.Server) == 0) && !term.IsTerminal(o.In) {
		return errors.New("A server URL must be specified")
	}

	if len(o.Username) > 0 && len(o.Token) > 0 {
		// return errors.New("--token and --username are mutually exclusive")
	}

	if o.StartingKubeConfig == nil {
		return errors.New("Must have a config file already created")
	}

	return nil
}

// RunLogin contains all the necessary functionality for the OpenShift cli login command
func (o LoginOptions) Run() error {

	// Prompt username and password
	usernamePrompt := promptui.Prompt {
		Label:    "Username ",
	}
	USERNAME, err := usernamePrompt.Run()
	o.Username = USERNAME

	passwordPrompt := promptui.Prompt {
		Label:    "Password ",
		Mask:     '*',
	}
	PASSWORD, err := passwordPrompt.Run()

	// Setup cookie jar
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return err
	}
	// Setup http client
	tr := &http.Transport{
      TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
	client := &http.Client {
		Jar: jar,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    },
	}
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15"

	// Perform initial request
	OSServerNoPortRegex, _ := regexp.Compile("(https?://.*?):")
	OSServerNoPort := OSServerNoPortRegex.FindStringSubmatch(o.Server)[1]
	req, err := http.NewRequest("GET", OSServerNoPort, nil)
	req.Header.Add("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	var nextLocation = resp.Header.Get("Location")

	// First redirect
	req, err = http.NewRequest("GET", nextLocation, nil)
	req.Header.Add("User-Agent", userAgent)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	nextLocation = resp.Header.Get("Location")
	//fmt.Println(nextLocation)

	// Second redirect
	req, err = http.NewRequest("GET", nextLocation, nil)
	req.Header.Add("User-Agent", userAgent)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	nextLocation = resp.Header.Get("Location")
	//fmt.Println(nextLocation)

	// Send auth credentials
	easy := curl.EasyInit()
	htmlForm := ""
	defer easy.Cleanup()
	if easy == nil {
		fmt.Println("Could not init CURL client")
	}
	easy.Setopt(curl.OPT_URL, nextLocation)
	easy.Setopt(curl.OPT_HEADER, true)
	easy.Setopt(curl.OPT_HTTPHEADER, []string{"User-Agent: " + userAgent})
	easy.Setopt(curl.OPT_HTTPAUTH, curl.AUTH_NTLM)
	easy.Setopt(curl.OPT_USERPWD, USERNAME + ":" + PASSWORD)
	easy.Setopt(curl.OPT_WRITEFUNCTION, func(ptr []byte, userdata interface{}) bool {
		htmlForm = htmlForm + string(ptr)
		return true
	})
	easy.Setopt(curl.OPT_WRITEDATA, htmlForm)
	easy.Perform()
	SAMLResponseRegex, _ := regexp.Compile("SAMLResponse\" value=\"(.*?)\"")
	SAMLResponseMatch := SAMLResponseRegex.FindStringSubmatch(htmlForm)
	if len(SAMLResponseMatch) < 1 {
		fmt.Println("Login failed: Invalid credentials!")
		os.Exit(1)
	}
	SAMLResponse := SAMLResponseMatch[1]

	FormActionRegex, _ := regexp.Compile("name=\"hiddenform\" action=\"(.*?)\"")
	FormAction := FormActionRegex.FindStringSubmatch(htmlForm)[1]

	RelayStateRegex, _ := regexp.Compile("RelayState\" value=\"(.*?)\"")
	RelayState := RelayStateRegex.FindStringSubmatch(htmlForm)[1]

	RelayBaseUrlRegex, _ := regexp.Compile("(https?://.*?)/")
	RelayBaseUrl := RelayBaseUrlRegex.FindStringSubmatch(FormAction)[1]

	// Send POST Request
	form := url.Values{}
	form.Add("SAMLResponse", SAMLResponse)
	form.Add("RelayState", RelayState)
	req, err = http.NewRequest("POST", FormAction, strings.NewReader(form.Encode()))
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	nextLocation = resp.Header.Get("Location")
	//fmt.Println(nextLocation)

	// Redirect to Relay
	RelayUrl := RelayBaseUrl + nextLocation
	req, err = http.NewRequest("GET", RelayUrl, nil)
	req.Header.Add("User-Agent", userAgent)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
  bodyString := string(bodyBytes)
	//fmt.Println(bodyString)

	BubbleResponseUrlRegex, _ := regexp.Compile("UnescapeHtml\\('(.*?)'")
	BubbleResponseUrl := BubbleResponseUrlRegex.FindStringSubmatch(bodyString)[1]
	BubbleResponseUrl = html.UnescapeString(BubbleResponseUrl)
	//fmt.Println(BubbleResponseUrl)

	// Redirect to bubble response
	req, err = http.NewRequest("GET", BubbleResponseUrl, nil)
	req.Header.Add("User-Agent", userAgent)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	BubbleAppCookie := resp.Cookies()[0].Name + "=" + resp.Cookies()[0].Value
	//fmt.Println(BubbleAppCookie)

	OSBaseUrlRegex, _ := regexp.Compile("(https?://.*?)\\?|/")
	OSBaseUrl := OSBaseUrlRegex.FindStringSubmatch(BubbleResponseUrl)[1]
	//fmt.Println(OSBaseUrl)

	// Final redirect - get SPX cookie
	req, err = http.NewRequest("GET", OSBaseUrl, nil)
	req.Header.Add("User-Agent", userAgent)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	SPXStickyCloudletCookie := resp.Cookies()[0].Name + "=" + resp.Cookies()[0].Value
	//fmt.Println(resp.Cookies())

	COOKIE_SPX_AUTH_FULL := SPXStickyCloudletCookie + "; " + BubbleAppCookie
	//fmt.Println(COOKIE_SPX_AUTH_FULL)

	// Write cookie to file
	usr, err := user.Current()
	if err != nil {
  	return err
  }
	d1 := []byte(COOKIE_SPX_AUTH_FULL)
	ioutil.WriteFile(filepath.FromSlash(usr.HomeDir + "/oc-login.cookie"), d1, 0644)

	if err := o.GatherInfo(); err != nil {
		return err
	}

	newFileCreated, err := o.SaveConfig()
	if err != nil {
		return err
	}

	if newFileCreated {
		fmt.Fprintf(o.Out, "Welcome! See '%s help' to get started.\n", o.CommandName)
	}
	return nil
}

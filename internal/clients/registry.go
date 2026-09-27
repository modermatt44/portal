package clients

import (
	"runtime"
	"strconv"

	"github.com/modermatt44/portal/internal/detect"
)

// Client describes a program that can talk to a service.
type Client struct {
	// Program is the executable name looked up on PATH.
	Program string
	// Args builds the arguments that connect the program to the target.
	Args func(req Request) []string
	// Install maps an operating system (runtime.GOOS) to an install hint.
	// The "" key is the fallback.
	Install map[string]string
	// When, if set, limits the client to requests it can handle.
	When func(req Request) bool
	// Builtin marks portal's own raw session, which is always available.
	Builtin bool
	// CRLF makes the built-in session send CRLF line endings.
	CRLF bool
}

// InstallHint returns how to install the client on goos.
func (c Client) InstallHint(goos string) string {
	if h, ok := c.Install[goos]; ok {
		return h
	}
	return c.Install[""]
}

func port(req Request) string { return strconv.Itoa(req.Target.Port) }

var (
	sshClient = Client{
		Program: "ssh",
		Args:    func(r Request) []string { return []string{"-p", port(r), r.Target.Host} },
		Install: map[string]string{
			"darwin":  "ssh ships with macOS; check that /usr/bin is on your PATH",
			"windows": `add "OpenSSH Client" under Settings → System → Optional features`,
			"":        "sudo apt install openssh-client (Debian/Ubuntu) or sudo dnf install openssh-clients (Fedora)",
		},
	}
	psqlClient = Client{
		Program: "psql",
		Args:    func(r Request) []string { return []string{"-h", r.Target.Host, "-p", port(r)} },
		Install: map[string]string{
			"darwin":  "brew install libpq && brew link --force libpq",
			"windows": "install PostgreSQL from https://www.postgresql.org/download/windows/ and add its bin folder to PATH",
			"":        "sudo apt install postgresql-client (Debian/Ubuntu) or sudo dnf install postgresql (Fedora)",
		},
	}
	pgcliClient = Client{
		Program: "pgcli",
		Args:    func(r Request) []string { return []string{"-h", r.Target.Host, "-p", port(r)} },
		Install: map[string]string{"darwin": "brew install pgcli", "": "pipx install pgcli"},
	}
	mysqlClient = Client{
		Program: "mysql",
		// --protocol=TCP stops the client from using a local socket for
		// "localhost".
		Args: func(r Request) []string { return []string{"-h", r.Target.Host, "-P", port(r), "--protocol=TCP"} },
		Install: map[string]string{
			"darwin":  "brew install mysql-client",
			"windows": "install MySQL from https://dev.mysql.com/downloads/installer/ or MariaDB from https://mariadb.org/download/",
			"":        "sudo apt install mysql-client or mariadb-client (Debian/Ubuntu), sudo dnf install mariadb (Fedora)",
		},
	}
	mariadbClient = Client{
		Program: "mariadb",
		Args:    mysqlClient.Args,
		Install: map[string]string{"darwin": "brew install mariadb", "": "sudo apt install mariadb-client"},
	}
	mycliClient = Client{
		Program: "mycli",
		Args:    func(r Request) []string { return []string{"-h", r.Target.Host, "-P", port(r)} },
		Install: map[string]string{"darwin": "brew install mycli", "": "pipx install mycli"},
	}
	redisCLIClient = Client{
		Program: "redis-cli",
		Args:    redisArgs,
		Install: map[string]string{
			"darwin":  "brew install redis",
			"windows": "run redis-cli in WSL (sudo apt install redis-tools), or put a redis-cli.exe build on your PATH",
			"":        "sudo apt install redis-tools (Debian/Ubuntu) or sudo dnf install redis (Fedora)",
		},
	}
	valkeyCLIClient = Client{
		Program: "valkey-cli",
		Args:    redisArgs,
		Install: map[string]string{"darwin": "brew install valkey", "": "sudo apt install valkey-tools"},
	}
	mongoshClient = Client{
		Program: "mongosh",
		Args:    mongoArgs,
		Install: map[string]string{
			"darwin":  "brew install mongosh",
			"windows": "winget install MongoDB.Shell",
			"":        "see https://www.mongodb.com/docs/mongodb-shell/install/",
		},
	}
	mongoClient = Client{
		Program: "mongo",
		Args:    mongoArgs,
		Install: mongoshClient.Install,
	}
	curlClient = Client{
		Program: "curl",
		Args:    func(r Request) []string { return []string{"-v", httpURL(r)} },
		Install: map[string]string{
			"darwin":  "curl ships with macOS; check that /usr/bin is on your PATH",
			"windows": `curl.exe ships with Windows 10 and later; check that C:\Windows\System32 is on your PATH`,
			"":        "sudo apt install curl (Debian/Ubuntu) or sudo dnf install curl (Fedora)",
		},
	}
	lftpClient = Client{
		Program: "lftp",
		Args:    func(r Request) []string { return []string{"-p", port(r), r.Target.Host} },
		Install: map[string]string{
			"darwin":  "brew install lftp",
			"windows": "use lftp in WSL, or a graphical client such as WinSCP or FileZilla",
			"":        "sudo apt install lftp (Debian/Ubuntu) or sudo dnf install lftp (Fedora)",
		},
	}
	ftpClient = Client{
		Program: "ftp",
		Args: func(r Request) []string {
			if r.Target.Port == 21 {
				return []string{r.Target.Host}
			}
			return []string{r.Target.Host, port(r)}
		},
		// Windows' ftp.exe cannot take a port on the command line.
		When: func(r Request) bool { return runtime.GOOS != "windows" || r.Target.Port == 21 },
	}
	opensslSMTPClient = Client{
		Program: "openssl",
		Args: func(r Request) []string {
			args := []string{"s_client", "-starttls", "smtp", "-crlf", "-quiet", "-connect", r.Target.Addr()}
			if !r.Target.IsIP() {
				args = append(args, "-servername", r.Target.Host)
			}
			return args
		},
		When: func(r Request) bool { return r.StartTLS && !r.TLS },
	}
	textSession = Client{Builtin: true, CRLF: true}
	rawSession  = Client{Builtin: true}
)

func redisArgs(r Request) []string {
	args := []string{"-h", r.Target.Host, "-p", port(r)}
	if r.TLS {
		args = append(args, "--tls")
	}
	return args
}

func mongoArgs(r Request) []string {
	args := []string{"--host", r.Target.Host, "--port", port(r)}
	if r.TLS {
		args = append(args, "--tls")
	}
	return args
}

// registry lists the clients for each service in order of preference.
// Text protocols without a common interactive client use portal's own
// session with CRLF line endings.
var registry = map[detect.Service][]Client{
	detect.SSH:        {sshClient},
	detect.PostgreSQL: {psqlClient, pgcliClient},
	detect.MySQL:      {mysqlClient, mariadbClient, mycliClient},
	detect.Redis:      {redisCLIClient, valkeyCLIClient},
	detect.MongoDB:    {mongoshClient, mongoClient},
	detect.HTTP:       {curlClient},
	detect.HTTPS:      {curlClient},
	detect.FTP:        {lftpClient, ftpClient},
	detect.SMTP:       {opensslSMTPClient, textSession},
	detect.IMAP:       {textSession},
	detect.POP3:       {textSession},
	detect.Unknown:    {rawSession},
}

// Clients returns the clients that can serve req, in order of preference.
func Clients(req Request) []Client {
	var out []Client
	for _, c := range registry[req.Service] {
		if c.When == nil || c.When(req) {
			out = append(out, c)
		}
	}
	return out
}

// lookupClient finds a known client by program name, for config entries
// that name a program without arguments.
func lookupClient(program string) (Client, bool) {
	for _, list := range registry {
		for _, c := range list {
			if c.Program == program && !c.Builtin {
				return c, true
			}
		}
	}
	return Client{}, false
}

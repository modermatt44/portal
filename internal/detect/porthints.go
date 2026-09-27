package detect

// portHint is the service conventionally found on a port.
type portHint struct {
	service Service
	tls     bool // conventionally spoken inside TLS
}

// portHints is consulted only when no probe matched, or to break ties
// between equally confident candidates. It is never treated as proof.
var portHints = map[int]portHint{
	21:    {service: FTP},
	22:    {service: SSH},
	25:    {service: SMTP},
	80:    {service: HTTP},
	110:   {service: POP3},
	143:   {service: IMAP},
	443:   {service: HTTPS, tls: true},
	465:   {service: SMTP, tls: true},
	587:   {service: SMTP},
	993:   {service: IMAP, tls: true},
	995:   {service: POP3, tls: true},
	2222:  {service: SSH},
	2525:  {service: SMTP},
	3000:  {service: HTTP},
	3306:  {service: MySQL},
	5432:  {service: PostgreSQL},
	6379:  {service: Redis},
	8000:  {service: HTTP},
	8080:  {service: HTTP},
	8443:  {service: HTTPS, tls: true},
	27017: {service: MongoDB},
}

// WellKnownService returns the service conventionally found on port, if any.
func WellKnownService(port int) (Service, bool) {
	h, ok := portHints[port]
	return h.service, ok
}

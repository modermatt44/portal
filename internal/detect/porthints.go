package detect

// portHints is consulted only when no probe matched, or to break ties
// between equally confident candidates. It is never treated as proof.
var portHints = map[int]Service{
	21:    FTP,
	22:    SSH,
	25:    SMTP,
	80:    HTTP,
	110:   POP3,
	143:   IMAP,
	443:   HTTPS,
	465:   SMTP,
	587:   SMTP,
	993:   IMAP,
	995:   POP3,
	2222:  SSH,
	2525:  SMTP,
	3000:  HTTP,
	3306:  MySQL,
	5432:  PostgreSQL,
	6379:  Redis,
	8000:  HTTP,
	8080:  HTTP,
	8443:  HTTPS,
	27017: MongoDB,
}

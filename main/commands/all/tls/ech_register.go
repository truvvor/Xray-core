//go:build go1.26

package tls

func init() {
	CmdTLS.Commands = append(CmdTLS.Commands, cmdECH)
}

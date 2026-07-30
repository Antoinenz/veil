package control

// EnrollPath is the control-plane endpoint that enrolls a device with an invite.
const EnrollPath = "/enroll"

// EnrollRequest is sent by a client to enroll a new device.
type EnrollRequest struct {
	Invite          string `json:"invite"`
	DevicePublicKey string `json:"device_public_key"` // base64 X25519 static key
	Name            string `json:"name,omitempty"`
}

// EnrollResponse returns the information a client needs to connect: the server's
// static public key (pinned for the Noise handshake) and its fingerprint (for
// out-of-band verification).
type EnrollResponse struct {
	ServerPublicKey string `json:"server_public_key"` // base64
	Fingerprint     string `json:"fingerprint"`
}

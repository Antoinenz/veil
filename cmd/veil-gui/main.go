// Command veil-gui is the desktop app for veil: a small window with a Connect
// button that drives the privileged `veil daemon` over the local IPC channel.
package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/veilvpn/veil/internal/client"
	"github.com/veilvpn/veil/internal/daemon"
	"github.com/veilvpn/veil/internal/ipc"
)

func main() {
	a := app.NewWithID("com.veilvpn.gui")
	w := a.NewWindow("Veil")
	w.Resize(fyne.NewSize(380, 260))

	title := widget.NewLabelWithStyle("Veil VPN", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	state := widget.NewLabelWithStyle("—", fyne.TextAlignCenter, fyne.TextStyle{})
	detail := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})

	full := widget.NewCheck("Route all traffic (full tunnel)", nil)
	if runtime.GOOS == "windows" {
		full.Disable() // full-tunnel on Windows is not implemented yet
		full.Text = "Full tunnel (not yet available on Windows)"
	}

	btn := widget.NewButton("Connect", nil)
	btn.Importance = widget.HighImportance

	// applyStatus updates the widgets from a status snapshot (call on UI thread).
	applyStatus := func(st client.Status, reachable bool) {
		if !reachable {
			state.SetText("Daemon not running")
			detail.SetText("Start the Veil service, then reopen.")
			btn.SetText("Connect")
			btn.Disable()
			return
		}
		btn.Enable()
		switch st.State {
		case client.StateConnected:
			state.SetText("Connected")
			d := st.Server
			if st.Transport != "" {
				d += "  ·  " + st.Transport
			}
			if st.AssignedIP != "" {
				d += "  ·  " + st.AssignedIP
			}
			detail.SetText(d)
			btn.SetText("Disconnect")
		case client.StateConnecting:
			state.SetText("Connecting…")
			detail.SetText(st.Server)
			btn.SetText("Cancel")
		case client.StateDisconnecting:
			state.SetText("Disconnecting…")
			detail.SetText("")
			btn.SetText("Disconnect")
		default:
			state.SetText("Disconnected")
			if st.Err != "" {
				detail.SetText(st.Err)
			} else {
				detail.SetText("")
			}
			btn.SetText("Connect")
		}
	}

	btn.OnTapped = func() {
		go func() {
			st, ok := getStatus()
			if ok && (st.State == client.StateConnected || st.State == client.StateConnecting) {
				postDisconnect()
			} else {
				postConnect(full.Checked)
			}
			// Reflect the change promptly; the poller keeps it fresh after.
			st2, ok2 := getStatus()
			fyne.Do(func() { applyStatus(st2, ok2) })
		}()
	}

	// Poll the daemon once a second and update the UI.
	go func() {
		for {
			st, ok := getStatus()
			fyne.Do(func() { applyStatus(st, ok) })
			time.Sleep(time.Second)
		}
	}()

	w.SetContent(container.NewVBox(
		title,
		widget.NewSeparator(),
		state,
		detail,
		widget.NewSeparator(),
		full,
		btn,
	))
	w.ShowAndRun()
}

func getStatus() (client.Status, bool) {
	resp, err := ipc.HTTPClient().Get(ipc.Host + "/v1/status")
	if err != nil {
		return client.Status{}, false
	}
	defer resp.Body.Close()
	var st client.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return client.Status{}, false
	}
	return st, true
}

func postConnect(full bool) {
	b, _ := json.Marshal(daemon.ConnectRequest{Full: full})
	resp, err := ipc.HTTPClient().Post(ipc.Host+"/v1/connect", "application/json", bytes.NewReader(b))
	if err == nil {
		resp.Body.Close()
	}
}

func postDisconnect() {
	resp, err := ipc.HTTPClient().Post(ipc.Host+"/v1/disconnect", "application/json", nil)
	if err == nil {
		resp.Body.Close()
	}
}

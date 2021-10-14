package tun

import(
	"fmt"
	"golang.zx2c4.com/wireguard/tun/wintun"
	"golang.org/x/sys/windows"
	"net"
)


func NewTun(ifname string,mtu int)(Device,error){
	allIfces,err := net.Interfaces()
	if err != nil{
		return nil, err
	}
	var ifceExist bool
	for _,ifce := range allIfces{
		if ifce.Name == ifname{
			ifceExist = true
			break
		}
	}
	var wt *wintun.Adapter
	if ifceExist{
		wt, err = wintun.OpenAdapter(ifname)
	}else{
		wt, err = wintun.CreateAdapter("" ,ifname,nil)
	}
	if err != nil {
		return nil, fmt.Errorf("Error creating interface: %w", err)
	}

	forcedMTU := 1420
	if mtu > 0 {
		forcedMTU = mtu
	}

	tun := &NativeTun{
		wt:        wt,
		name:      ifname,
		handle:    windows.InvalidHandle,
		events:    make(chan Event, 10),
		forcedMTU: forcedMTU,
	}

	tun.session, err = wt.StartSession(0x800000) // Ring capacity, 8 MiB
	if err != nil {
		tun.wt.Close()
		close(tun.events)
		return nil, fmt.Errorf("Error starting session: %w", err)
	}
	tun.readWait = tun.session.ReadWaitEvent()
	return tun, nil
}

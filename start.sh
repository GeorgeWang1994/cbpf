
/usr/bin/probe-loader

if [ -f "/opt/probe.o" ]; then
	export SYSDIG_BPF_PROBE="/opt/probe.o"
fi

/usr/bin/collector --config=/etc/collector/config.yml
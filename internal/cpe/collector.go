package cpe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cpe-api/internal/config"
	"cpe-api/internal/observability"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Collector struct {
	cfg       config.Config
	log       *slog.Logger
	metrics   *observability.Registry
	hostKeyCB ssh.HostKeyCallback

	signerMu    sync.RWMutex
	signerCache map[string]ssh.Signer

	targetGateMu sync.Mutex
	targetGates  map[string]chan struct{}
}

type commandSpec struct {
	key string
	cmd string
}

type commandProfile struct {
	name        string
	commands    []commandSpec
	cfgPrecheck bool
}

type interactiveShell struct {
	session *ssh.Session
	stdin   io.WriteCloser
	outCh   chan []byte
}

type sshAuthProfile struct {
	user     string
	password string
	keyPath  string
}

const (
	keyFileVantiva = "VANTIVA_TAFJORD"
	keyFileP2812   = "P2812_TAFJORD"
	keyFileFMG     = "FMG3542_TAFJORD"
	keyFileVMG     = "VMG8825-EX-AX_TAFJORD"

	shellEnvPath = "export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH"
	shellEnvLib  = "for d in /lib /usr/lib /usr/local/lib /lib/private /lib/public /usr/local/zyxel/lib /data/lib /opt/lib; do " +
		"if [ -d \"$d\" ]; then case \":$LD_LIBRARY_PATH:\" in *\":$d:\"*) ;; *) LD_LIBRARY_PATH=\"${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$d\";; esac; fi; done; export LD_LIBRARY_PATH"
)

var zyxelCommandsWithSFP = []commandSpec{
	{key: "sys_atsh", cmd: "sys atsh"},
	{key: "uptime", cmd: "uptime"},
	{key: "ifconfig", cmd: "ifconfig"},
	{key: "lanhosts", cmd: "cfg lanhosts get"},
	{key: "portmap", cmd: "if cfg lanhosts get >/dev/null 2>&1; then dmesg -c > /dev/null 2>&1; ethswctl -c arldump > /dev/null 2>&1; for line in $(cfg lanhosts get | grep Ethernet | awk '{print $4}' | sed 's/\\://g'); do dmesg | grep \"$line\" | awk '{print $3 \" \" $4}'; done; fi"},
	{key: "arp", cmd: "arp -a | grep br0"},
	{key: "leases", cmd: "cat /var/dnsmasq/dnsmasq.leases"},
	{key: "ethctl", cmd: "cfg ethctl get"},
	{key: "wifi24", cmd: "zywlctl -b 2 assoclist"},
	{key: "wifi50", cmd: "zywlctl -b 5 assoclist"},
	{key: "wlan", cmd: "cfg wlan get"},
	{key: "loadavg", cmd: "cat /proc/loadavg"},
	{key: "sfp", cmd: "zycli sfp show"},
}

var zyxelCommandsNoSFP = []commandSpec{
	{key: "sys_atsh", cmd: "sys atsh"},
	{key: "uptime", cmd: "uptime"},
	{key: "ifconfig", cmd: "ifconfig"},
	{key: "lanhosts", cmd: "cfg lanhosts get"},
	{key: "portmap", cmd: "if cfg lanhosts get >/dev/null 2>&1; then dmesg -c > /dev/null 2>&1; ethswctl -c arldump > /dev/null 2>&1; for line in $(cfg lanhosts get | grep Ethernet | awk '{print $4}' | sed 's/\\://g'); do dmesg | grep \"$line\" | awk '{print $3 \" \" $4}'; done; fi"},
	{key: "arp", cmd: "arp -a | grep br0"},
	{key: "leases", cmd: "cat /var/dnsmasq/dnsmasq.leases"},
	{key: "ethctl", cmd: "cfg ethctl get"},
	{key: "wifi24", cmd: "zywlctl -b 2 assoclist"},
	{key: "wifi50", cmd: "zywlctl -b 5 assoclist"},
	{key: "wlan", cmd: "cfg wlan get"},
	{key: "loadavg", cmd: "cat /proc/loadavg"},
}

var vantivaCommands = []commandSpec{
	{key: "system_info", cmd: "ubus call system info"},
	{key: "env", cmd: "uci show env"},
	{key: "network_device_status", cmd: "ubus call network.device status"},
	{key: "hostmanager_devices", cmd: "ubus call hostmanager.device get"},
	{key: "gpon_info", cmd: "ubus call gpon.trsv get_info"},
}

func NewCollector(cfg config.Config, logger *slog.Logger, metrics *observability.Registry) (*Collector, error) {
	var hostKeyCB ssh.HostKeyCallback
	if cfg.SSHInsecureHostKey {
		hostKeyCB = ssh.InsecureIgnoreHostKey()
	} else {
		cb, err := knownhosts.New(cfg.SSHKnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("known_hosts callback: %w", err)
		}
		hostKeyCB = cb
	}

	if metrics == nil {
		metrics = observability.NewRegistry()
	}

	return &Collector{
		cfg:         cfg,
		log:         logger,
		metrics:     metrics,
		hostKeyCB:   hostKeyCB,
		signerCache: make(map[string]ssh.Signer),
		targetGates: make(map[string]chan struct{}),
	}, nil
}

func (c *Collector) IsAllowedTarget(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range c.cfg.AllowedTargetCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Collector) Collect(ctx context.Context, ip string, port int, options CollectOptions) CollectResponse {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	c.log.Info("collect_start",
		"ip", ip,
		"port", port,
		"model", options.Model,
	)

	response := CollectResponse{
		IP:        ip,
		Port:      port,
		Model:     options.Model,
		Timestamp: time.Now().UTC(),
	}

	releaseTarget, err := c.acquireTargetGate(ctx, ip)
	if err != nil {
		response.SSHFailed = true
		response.Errors = append(response.Errors, "target busy: "+err.Error())
		return response
	}
	defer releaseTarget()

	client, err := c.sshDial(ctx, ip, port, options.Model)
	if err != nil {
		reason, hint := classifySSHDialError(err)
		errorText := "ssh dial: " + err.Error()
		if hint != "" {
			errorText += " (" + hint + ")"
		}
		c.metrics.ObserveSSHDialFailure(options.Model, reason)
		c.log.Error("collect_ssh_dial_failed",
			"ip", ip,
			"port", port,
			"model", options.Model,
			"error", err.Error(),
			"hint", hint,
		)
		response.SSHFailed = true
		response.Errors = append(response.Errors, errorText)
		return response
	}
	defer client.Close()

	c.log.Debug("collect_ssh_dial_ok",
		"ip", ip,
		"port", port,
		"model", options.Model,
	)

	shell, err := c.openInteractiveShell(ctx, client, ip, options.Model)
	if err != nil {
		c.log.Error("collect_shell_handshake_failed",
			"ip", ip,
			"port", port,
			"model", options.Model,
			"error", err.Error(),
		)
		response.SSHFailed = true
		response.Errors = append(response.Errors, "shell handshake: "+err.Error())
		return response
	}
	defer shell.Close()

	profile := commandProfileForModel(options.Model)
	c.log.Info("collect_command_profile_selected",
		"ip", ip,
		"model", options.Model,
		"profile", profile.name,
		"command_count", len(profile.commands),
	)

	cfgAvailable := true
	if profile.cfgPrecheck {
		cfgAvailable = c.isCfgAvailable(ctx, shell, ip, options.Model)
		if !cfgAvailable {
			response.Errors = append(response.Errors, "cfg utility unavailable on this device/firmware; skipped lanhosts/portmap/ethctl/wlan")
		}
	}

	rawOutput := make(map[string]string, len(profile.commands))
	for _, command := range profile.commands {
		if profile.cfgPrecheck && !cfgAvailable && isCfgDependentCommand(command.key) {
			c.metrics.ObserveCommandDuration(profile.name, command.key, "skipped", 0)
			c.log.Info("collect_command_skipped",
				"ip", ip,
				"model", options.Model,
				"key", command.key,
				"reason", "cfg unavailable",
			)
			continue
		}

		cmdStart := time.Now()
		commandCtx, commandCancel := context.WithTimeout(ctx, c.cfg.SSHCommandTimeout)
		output, runErr := shell.RunCommand(commandCtx, command.cmd)
		commandCancel()
		output = normalizeOutput(output)
		duration := time.Since(cmdStart)

		if runErr != nil {
			errMsg := fmt.Sprintf("%s: %v", command.key, runErr)
			if isExitStatus127(runErr) {
				errMsg += " (command unavailable on this device/firmware)"
			}
			response.Errors = append(response.Errors, errMsg)
			result := "error"
			if errorsIsTimeout(runErr) {
				result = "timeout"
			}
			c.metrics.ObserveCommandDuration(profile.name, command.key, result, duration)

			c.log.Warn("collect_command_failed",
				"ip", ip,
				"model", options.Model,
				"key", command.key,
				"duration_ms", duration.Milliseconds(),
				"error", runErr.Error(),
				"output_sample", truncateOneLine(output, 180),
			)
			if errorsIsTimeout(runErr) {
				c.log.Warn("collect_command_timeout_abort_remaining",
					"ip", ip,
					"model", options.Model,
					"key", command.key,
				)
				break
			}
			continue
		}

		rawOutput[command.key] = output
		c.metrics.ObserveCommandDuration(profile.name, command.key, "success", duration)
		c.log.Debug("collect_command_ok",
			"ip", ip,
			"model", options.Model,
			"key", command.key,
			"duration_ms", duration.Milliseconds(),
			"output_bytes", len(output),
		)
	}

	c.populateParsedFields(&response, rawOutput, options)
	if options.IncludeRaw {
		response.Raw = rawOutput
	}

	c.log.Info("collect_done",
		"ip", ip,
		"port", port,
		"model", options.Model,
		"errors", len(response.Errors),
		"ssh_failed", response.SSHFailed,
	)

	return response
}

func (c *Collector) populateParsedFields(out *CollectResponse, raw map[string]string, options CollectOptions) {
	if s := raw["sys_atsh"]; s != "" {
		out.CpeInfo = parseSysAtsh(s)
	}
	if s := raw["uptime"]; s != "" {
		out.Uptime = parseUptime(s)
	}
	if s := raw["loadavg"]; s != "" {
		out.LoadAvg = parseProcLoadavg(s)
	}
	if s := raw["ifconfig"]; s != "" {
		out.Ifaces = parseIfconfig(s)
	}
	if s := raw["lanhosts"]; s != "" {
		out.LanHosts = parseLanHosts(s)
	}
	if s := raw["portmap"]; s != "" {
		out.PortMap = parsePortMap(s)
	}
	if s := raw["arp"]; s != "" {
		out.ARP = parseArp(s)
	}
	if s := raw["leases"]; s != "" {
		out.Leases = parseDnsmasqLeases(s)
	}
	if s := raw["ethctl"]; s != "" {
		out.EthPorts = parseEthctl(s)
	}
	if s := raw["wifi24"]; s != "" {
		out.Wifi2 = parseWifiAssoc(s)
	}
	if s := raw["wifi50"]; s != "" {
		out.Wifi5 = parseWifiAssoc(s)
	}
	if s := raw["wlan"]; s != "" {
		out.WlanCfg = parseWlanCfg(s, options.IncludePSK)
	}
	if s := raw["sfp"]; s != "" {
		out.Sfp = parseSfp(s)
	}
	if s := raw["system_info"]; s != "" {
		systemInfo, uptime := parseUbusSystemInfo(s)
		if len(systemInfo) > 0 {
			if out.CpeInfo == nil {
				out.CpeInfo = make(map[string]string, len(systemInfo))
			}
			for k, v := range systemInfo {
				out.CpeInfo[k] = v
			}
		}
		if out.Uptime == nil && uptime != nil {
			out.Uptime = uptime
		}
	}
}

func (c *Collector) sshDial(ctx context.Context, ip string, port int, model string) (*ssh.Client, error) {
	profile, err := c.resolveAuthProfile(model)
	if err != nil {
		return nil, err
	}

	c.log.Debug("ssh_profile_selected",
		"ip", ip,
		"model", model,
		"user", profile.user,
		"has_password", profile.password != "",
		"key_path", profile.keyPath,
	)

	authMethods, err := c.buildAuthMethods(profile)
	if err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User:            profile.user,
		Auth:            authMethods,
		HostKeyCallback: c.hostKeyCB,
		Timeout:         c.cfg.SSHDialTimeout,
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: c.cfg.SSHDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (c *Collector) acquireTargetGate(ctx context.Context, ip string) (func(), error) {
	c.targetGateMu.Lock()
	ch, ok := c.targetGates[ip]
	if !ok {
		ch = make(chan struct{}, 1)
		c.targetGates[ip] = ch
	}
	c.targetGateMu.Unlock()

	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Collector) buildAuthMethods(profile sshAuthProfile) ([]ssh.AuthMethod, error) {
	methods := make([]ssh.AuthMethod, 0, 2)

	if profile.keyPath != "" {
		signer, err := c.loadSigner(profile.keyPath)
		if err != nil {
			if profile.password == "" {
				return nil, err
			}
			c.log.Warn("ssh_key_load_failed_fallback_password",
				"user", profile.user,
				"key_path", profile.keyPath,
				"error", err.Error(),
			)
		} else {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}

	if profile.password != "" {
		methods = append(methods, ssh.Password(profile.password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no ssh auth method available")
	}

	return methods, nil
}

func (c *Collector) resolveAuthProfile(model string) (sshAuthProfile, error) {
	normalized := strings.ToUpper(strings.TrimSpace(model))

	if normalized != "" {
		if isVantivaModel(normalized) {
			if c.cfg.VantivaCLIUser == "" || c.cfg.VantivaCLIPassword == "" {
				return sshAuthProfile{}, fmt.Errorf("VANTIVA_CPE_CLI_USER and VANTIVA_CPE_CLI_PASSWORD are required for model %q", model)
			}
			if c.cfg.SSHKeysDir == "" {
				return sshAuthProfile{}, fmt.Errorf("CPE_SSH_KEYS_DIR is required for model %q", model)
			}
			keyPath := filepath.Join(c.cfg.SSHKeysDir, keyFileVantiva)
			if !fileExists(keyPath) {
				return sshAuthProfile{}, fmt.Errorf("ssh key not found for model %q at %q", model, keyPath)
			}
			return sshAuthProfile{
				user:     c.cfg.VantivaCLIUser,
				password: c.cfg.VantivaCLIPassword,
				keyPath:  keyPath,
			}, nil
		}

		if keyFile, ok := zyxelKeyForModel(normalized); ok {
			if c.cfg.SSHKeysDir == "" {
				return sshAuthProfile{}, fmt.Errorf("CPE_SSH_KEYS_DIR is required for model %q", model)
			}
			keyPath := filepath.Join(c.cfg.SSHKeysDir, keyFile)
			if !fileExists(keyPath) {
				return sshAuthProfile{}, fmt.Errorf("ssh key not found for model %q at %q", model, keyPath)
			}
			return sshAuthProfile{
				user:    "root",
				keyPath: keyPath,
			}, nil
		}
	}

	keyPath, err := c.resolveKeyPath(model)
	if err != nil && c.cfg.SSHPass == "" {
		return sshAuthProfile{}, err
	}
	if err != nil && c.cfg.SSHPass != "" {
		c.log.Warn("model key resolution failed; falling back to password auth",
			"model", model,
			"error", err.Error(),
		)
	}

	return sshAuthProfile{
		user:     c.cfg.SSHUser,
		password: c.cfg.SSHPass,
		keyPath:  keyPath,
	}, nil
}

func (c *Collector) resolveKeyPath(model string) (string, error) {
	model = strings.TrimSpace(model)
	if model == "" {
		return c.cfg.SSHKeyPath, nil
	}

	if !isModelSafe(model) {
		return "", fmt.Errorf("invalid model format")
	}

	if mapped, ok := c.cfg.SSHModelKeyMap[strings.ToUpper(model)]; ok {
		if filepath.IsAbs(mapped) {
			return mapped, nil
		}
		if c.cfg.SSHKeysDir != "" {
			return filepath.Join(c.cfg.SSHKeysDir, mapped), nil
		}
		return mapped, nil
	}

	if c.cfg.SSHKeysDir != "" {
		candidate := filepath.Join(c.cfg.SSHKeysDir, model)
		if fileExists(candidate) {
			return candidate, nil
		}
	}

	if c.cfg.SSHKeyPath != "" {
		return c.cfg.SSHKeyPath, nil
	}
	return "", fmt.Errorf("no ssh key found for model %q", model)
}

func (c *Collector) loadSigner(keyPath string) (ssh.Signer, error) {
	c.signerMu.RLock()
	if signer, ok := c.signerCache[keyPath]; ok {
		c.signerMu.RUnlock()
		return signer, nil
	}
	c.signerMu.RUnlock()

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %q: %w", keyPath, err)
	}

	var signer ssh.Signer
	if c.cfg.SSHKeyPassphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(c.cfg.SSHKeyPassphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse ssh key %q: %w", keyPath, err)
	}

	c.signerMu.Lock()
	c.signerCache[keyPath] = signer
	c.signerMu.Unlock()
	return signer, nil
}

var modelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func isModelSafe(model string) bool {
	return modelPattern.MatchString(model)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func isVantivaModel(model string) bool {
	return model == "VANTIVA"
}

func zyxelKeyForModel(model string) (string, bool) {
	switch {
	case strings.Contains(model, "P2812"):
		return keyFileP2812, true
	case strings.Contains(model, "FMG"):
		return keyFileFMG, true
	case strings.Contains(model, "VMG"), strings.Contains(model, "AX"), strings.Contains(model, "EX"):
		return keyFileVMG, true
	default:
		return "", false
	}
}

func commandProfileForModel(model string) commandProfile {
	upper := strings.ToUpper(strings.TrimSpace(model))
	switch {
	case isVantivaModel(upper):
		return commandProfile{
			name:        "vantiva-openwrt-v1",
			commands:    vantivaCommands,
			cfgPrecheck: false,
		}
	case strings.Contains(upper, "AX"):
		return commandProfile{
			name:        "zyxel-ax-v1",
			commands:    zyxelCommandsNoSFP,
			cfgPrecheck: true,
		}
	default:
		return commandProfile{
			name:        "zyxel-v1",
			commands:    zyxelCommandsWithSFP,
			cfgPrecheck: true,
		}
	}
}

func isExitStatus127(err error) bool {
	return strings.Contains(err.Error(), "status 127")
}

func truncateOneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (c *Collector) isCfgAvailable(ctx context.Context, shell *interactiveShell, ip, model string) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	_, err := shell.RunCommand(checkCtx, "cfg lanhosts get >/dev/null 2>&1")
	if err == nil {
		return true
	}

	c.log.Warn("cfg_unavailable",
		"ip", ip,
		"model", model,
		"error", err.Error(),
	)
	return false
}

func isCfgDependentCommand(key string) bool {
	switch key {
	case "lanhosts", "portmap", "ethctl", "wlan":
		return true
	default:
		return false
	}
}

func (c *Collector) openInteractiveShell(ctx context.Context, client *ssh.Client, ip, model string) (*interactiveShell, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	term, rows, cols, modes := terminalProfile(model)
	if err := session.RequestPty(term, rows, cols, modes); err != nil {
		_ = session.Close()
		return nil, err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}

	outCh := make(chan []byte, 2048)
	writer := &streamWriter{outCh: outCh}
	session.Stdout = writer
	session.Stderr = writer

	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, err
	}

	go func() {
		_ = session.Wait()
		close(outCh)
	}()

	s := &interactiveShell{
		session: session,
		stdin:   stdin,
		outCh:   outCh,
	}
	_, _ = io.WriteString(s.stdin, "\n")

	readyCtx, cancel := context.WithTimeout(ctx, minDuration(8*time.Second, c.cfg.SSHCommandTimeout))
	defer cancel()
	banner, err := s.readUntilPrompt(readyCtx)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	normalizedBanner := normalizeOutput(banner)
	if !strings.Contains(normalizedBanner, "BusyBox") {
		_ = s.Close()
		return nil, fmt.Errorf("shell not ready: BusyBox banner not detected")
	}

	c.log.Debug("shell_ready",
		"ip", ip,
		"model", model,
		"banner_sample", truncateOneLine(normalizedBanner, 220),
	)

	if err := s.primeEnvironment(readyCtx); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("shell env priming failed: %w", err)
	}

	return s, nil
}

func (s *interactiveShell) RunCommand(ctx context.Context, command string) (string, error) {
	marker := fmt.Sprintf("__CPE_RC_%d__", time.Now().UnixNano())
	full := fmt.Sprintf("%s; echo %s$?\n", command, marker)
	if _, err := io.WriteString(s.stdin, full); err != nil {
		return "", err
	}

	raw, err := s.readUntilMarkerAndPrompt(ctx, marker)
	if err != nil {
		return normalizeOutput(raw), err
	}
	return parseCommandOutput(raw, command, marker)
}

func (s *interactiveShell) readUntilPrompt(ctx context.Context) (string, error) {
	var buf bytes.Buffer
	for {
		current := strings.ReplaceAll(buf.String(), "\r", "")
		if body, ok := trimPromptSuffix(current); ok {
			return body, nil
		}

		select {
		case <-ctx.Done():
			_ = s.session.Close()
			return buf.String(), ctx.Err()
		case chunk, ok := <-s.outCh:
			if !ok {
				return buf.String(), io.EOF
			}
			_, _ = buf.Write(chunk)
		}
	}
}

func (s *interactiveShell) readUntilMarkerAndPrompt(ctx context.Context, marker string) (string, error) {
	var buf bytes.Buffer
	for {
		current := strings.ReplaceAll(buf.String(), "\r", "")
		if strings.Contains(current, marker) {
			if body, ok := trimPromptSuffix(current); ok {
				return body, nil
			}
		}

		select {
		case <-ctx.Done():
			_ = s.session.Close()
			return buf.String(), ctx.Err()
		case chunk, ok := <-s.outCh:
			if !ok {
				return buf.String(), io.EOF
			}
			_, _ = buf.Write(chunk)
		}
	}
}

func (s *interactiveShell) Close() error {
	_ = s.stdin.Close()
	return s.session.Close()
}

func (s *interactiveShell) primeEnvironment(ctx context.Context) error {
	if _, err := s.RunCommand(ctx, shellEnvPath); err != nil {
		return err
	}
	if _, err := s.RunCommand(ctx, shellEnvLib); err != nil {
		return err
	}
	return nil
}

type streamWriter struct {
	outCh chan []byte
}

func (w *streamWriter) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	w.outCh <- cp
	return len(p), nil
}

func trimPromptSuffix(s string) (string, bool) {
	switch {
	case strings.HasSuffix(s, "# "):
		return strings.TrimSuffix(s, "# "), true
	case strings.HasSuffix(s, "#"):
		return strings.TrimSuffix(s, "#"), true
	case strings.HasSuffix(s, "\n# "):
		return strings.TrimSuffix(s, "\n# "), true
	case strings.HasSuffix(s, "\n#"):
		return strings.TrimSuffix(s, "\n#"), true
	default:
		return "", false
	}
}

func parseCommandOutput(raw, command, marker string) (string, error) {
	normalized := strings.ReplaceAll(raw, "\r", "")
	markerPos := strings.LastIndex(normalized, marker)
	if markerPos < 0 {
		body := strings.TrimSpace(normalized)
		return body, fmt.Errorf("command completion marker missing")
	}

	rcText := normalized[markerPos+len(marker):]
	rc := parseLeadingInt(rcText)

	bodyPart := normalized[:markerPos]
	lines := strings.Split(bodyPart, "\n")
	lines = trimEmptyHead(lines)
	lines = trimEchoLines(lines, command, marker)
	body := strings.TrimSpace(strings.Join(lines, "\n"))

	if rc != 0 {
		return body, exitStatusError{code: rc}
	}
	return body, nil
}

type exitStatusError struct {
	code int
}

func (e exitStatusError) Error() string {
	return fmt.Sprintf("Process exited with status %d", e.code)
}

func trimEmptyHead(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	return lines
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func errorsIsTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

func classifySSHDialError(err error) (string, string) {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return "connection_refused", "ssh port is closed/refused; verify SSH is enabled on the CPE and the target port is correct"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "timed out"):
		return "timeout", "tcp connect timed out; verify routing/firewall and target reachability"
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "host is unreachable"):
		return "unreachable", "target unreachable; verify network path and CPE IP"
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "permission denied"):
		return "auth_failed", "authentication failed; verify model credentials and key/passphrase settings"
	default:
		return "other", ""
	}
}

func trimEchoLines(lines []string, command, marker string) []string {
	if len(lines) == 0 {
		return lines
	}

	trimmedCommand := strings.TrimSpace(command)
	echoMarker := "echo " + marker + "$?"
	fullEcho := trimmedCommand + "; " + echoMarker

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		t := strings.TrimSpace(line)
		t = strings.TrimPrefix(t, "# ")
		if t == trimmedCommand || t == echoMarker || t == fullEcho {
			continue
		}
		out = append(out, line)
	}
	return trimEmptyHead(out)
}

func parseLeadingInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var b strings.Builder
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return parseInt(b.String())
}

func terminalProfile(model string) (term string, rows, cols int, modes ssh.TerminalModes) {
	base := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}

	upper := strings.ToUpper(strings.TrimSpace(model))
	switch {
	case upper == "VANTIVA":
		return "xterm", 60, 200, base
	case strings.Contains(upper, "FMG"),
		strings.Contains(upper, "P2812"),
		strings.Contains(upper, "VMG"),
		strings.Contains(upper, "AX"),
		strings.Contains(upper, "EX"):
		return "vt100", 60, 200, base
	default:
		return "xterm", 50, 160, base
	}
}

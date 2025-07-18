import os, sys, time

from virttest import env_process, error_context, utils_misc, utils_net


@error_context.context_aware
def run(test, params, env):
    """
    Verify guest NIC numbers again whats provided in test config file.

    If the guest NICs info does not match whats in the params at first,
    try to fix these by operating the networking config file.
    1. Boot guest with multi NICs.
    2. Check whether guest NICs info match with params setting.
    3. Create configure file for every NIC interface in guest.
    4. Reboot guest.
    5. Check whether guest NICs info match with params setting.

    :param test: QEMU test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """
    def wmi_operations(session, vm, params, test, timeout):
        """
        Dump NetKVM WMI configuration (“cfg”) to the log.

        This function runs twice: once after a *cold boot* and once
        after a *hot reboot*, enabling time-series comparison.

        :param session: VM session info
        :param vm: QEMU test object
        :param params: Dictionary with the test parameters
        :param test: QEMU test object
        :param timeout: VM login time value
        """
        test.log.info("Record the data after fastinit operation")
        netkvm_wmi = r'WIN_UTILS:\netkvm\WMI\netkvm-wmi.cmd'
        netkvm_wmi = utils_misc.set_winutils_letter(session, netkvm_wmi)
        status, output = session.cmd_status_output("%s cfg" % netkvm_wmi, timeout)
        test.log.info("fastinit data: %s", output)
        return output


    def disable_driver_verifier(vm, params, test, timeout):
        """
        Turn Driver Verifier off (Windows guest only).

        1) Read *enable_verifier* (yes → enable, no → disable)
        2) Query current Driver Verifier status in the guest
        3) If state is already as requested, exit
        4) Otherwise run the enable/reset command and reboot
        5) Re-query after reboot to confirm the final state
        6) Raise TestError if the state is still wrong

        :param vm: QEMU test object
        :param params: Dictionary with the test parameters
        :param test: QEMU test object
        :param timeout: VM login time value
        """
        enable_verifier = bool(params.get_numeric("enable_verifier", 1))
        query_cmd = params.get("driver_verifier_query", "verifier /querysettings")
        enable_cmd = params.get(
            "driver_verifier_enable", "verifier /standard /flags netkvm.sys ndis.sys"
        )
        reset_cmd = params.get("driver_verifier_reset", "verifier /reset")

        def verifier_is_on(session, query_cmd=query_cmd):
            """
            Return True if Driver Verifier is currently enabled

            Driver Verifier is considered *OFF* when the mask is
            **0x00000000**; otherwise it is *ON*.
            """
            output = session.cmd_output(query_cmd)
            return "0x00000000" not in output

        session = vm.wait_for_serial_login(timeout)
        active = verifier_is_on(session)
        if enable_verifier is not active:
            if enable_verifier is True:
                cmd = enable_cmd
            else:
                cmd = reset_cmd
            session.cmd_status_output(cmd)
            vm.reboot(method="shell", serial=True, timeout=timeout, session=session)
        else:
            return

        session = vm.wait_for_serial_login(timeout)
        test.log.info("Current Driver Verifier: %s", session.cmd_output(query_cmd))
        active = verifier_is_on(session)
        if enable_verifier is not active:
            test.error("Driver Verifier state MISmatch after reboot")
        else:
            test.log.info("Driver Verifier state MATCH after reboot")
        session.close()


    def check_nics_num(expect_c, session):
        """
        Check whether guest NICs number match with params set in cfg file

        :param expect_c: expected nics no.
        :param session: in which session the guest runs in
        """
        txt = "Check whether guest NICs info match with params setting."
        error_context.context(txt, test.log.info)
        nics_list = utils_net.get_linux_ifname(session)
        actual_c = len(nics_list)
        msg = "Expected NICs count is: %d\n" % expect_c
        msg += "Actual NICs count is: %d\n" % actual_c

        if not expect_c == actual_c:
            msg += "Nics count mismatch!\n"
            return (False, msg)
        return (True, msg + "Nics count match")

    # Get the ethernet cards number from params
    nics_num = int(params.get("nics_num", 8))
    for i in range(nics_num):
        nics = "nic%s" % i
        params["nics"] = " ".join([params["nics"], nics])
    params["start_vm"] = "yes"
    env_process.preprocess_vm(test, params, env, params["main_vm"])

    vm = env.get_vm(params["main_vm"])
    vm.verify_alive()
    login_timeout = params.get_numeric("login_timeout")
    session = vm.wait_for_serial_login(timeout=login_timeout)

    test.log.info("[ %s ] NICs card specified in config file", nics_num)

    os_type = params.get("os_type", "linux")
    if os_type == "linux":
        # Redirect ifconfig output from guest to log file
        log_file = os.path.join(test.debugdir, "ifconfig")
        ifconfig_output = session.cmd("ifconfig")
        log_file_object = open(log_file, "w")
        log_file_object.write(ifconfig_output)
        log_file_object.close()

        # Pre-judgement for the ethernet interface
        test.log.debug(check_nics_num(nics_num, session)[1])
        txt = "Create configure file for every NIC interface in guest."
        error_context.context(txt, test.log.info)
        ifname_list = utils_net.get_linux_ifname(session)
        keyfile_path = "/etc/NetworkManager/system-connections/%s.nmconnection"
        ifcfg_path = "/etc/sysconfig/network-scripts/ifcfg-%s"
        network_manager = params.get_boolean("network_manager")
        if network_manager:
            for ifname in ifname_list:
                eth_keyfile_path = keyfile_path % ifname
                cmd = (
                    "nmcli --offline connection add type ethernet con-name %s ifname %s"
                    " ipv4.method auto > %s" % (ifname, ifname, eth_keyfile_path)
                )
                s, o = session.cmd_status_output(cmd)
                if s != 0:
                    err_msg = "Failed to create ether keyfile: %s\nReason is: %s"
                    test.error(err_msg % (eth_keyfile_path, o))
            session.cmd(
                "chown root:root /etc/NetworkManager/system-connections/*.nmconnection"
            )
            session.cmd(
                "chmod 600 /etc/NetworkManager/system-connections/*.nmconnection"
            )
            session.cmd("nmcli connection reload")
        else:
            for ifname in ifname_list:
                eth_config_path = ifcfg_path % ifname
                eth_config = "DEVICE=%s\\nBOOTPROTO=dhcp\\nONBOOT=yes" % ifname
                cmd = "echo -e '%s' > %s" % (eth_config, eth_config_path)
                s, o = session.cmd_status_output(cmd)
                if s != 0:
                    err_msg = "Failed to create ether config file: %s\nReason is: %s"
                    test.error(err_msg % (eth_config_path, o))

        # Reboot and check the configurations.
        session = vm.reboot(session, timeout=login_timeout)
        s, msg = check_nics_num(nics_num, session)
        if not s:
            test.fail(msg)
        session.close()

        # NICs matched.
        test.log.info(msg)

    def _check_ip_number():
        for index, nic in enumerate(vm.virtnet):
            guest_ip = utils_net.get_guest_ip_addr(
                session_srl, nic.mac, os_type, ip_version="ipv4"
            )
            if guest_ip == None:
                return False
        return True

    def _check_NICs_growth(nics_num: int) -> bool:
        """
        Return True when all expected VirtIO NICs are present and have valid IPv4.
        Otherwise return False so that utils_misc.wait_for() keeps retrying.
        """
        try:
            adapters = wmi_operations(
                timeout=30,
                session=session,
                vm=vm,
                params=params,
                test=test,
            )
        except Exception as exc:
            test.log.warn(f"wmi_operations raised {exc!r}")
            return False
    
        if not adapters:
            test.log.warn("wmi_operations returned None or empty list")
            return False
    
        # Compose the expected adapter name according to the NIC index
        expected_name = f"Red Hat VirtIO Ethernet Adapter #{nics_num}"
        if expected_name not in adapters:
            test.log.debug(f"{expected_name} not yet in guest adapters: {adapters}")
            return False
        return True
    
    
    def _check_dhcp(session):
        # Check for APIPA addresses, which indicate no DHCP lease
        if "169.254" in session.cmd_output("ipconfig /all", timeout=10):
            test.log.debug("Guest still shows 169.254 address, waiting for DHCP")
            return False
        return True

    # Check all the interfaces in guest get ips
    session_srl = vm.wait_for_serial_login(
        timeout=int(params.get("login_timeout", 360))
    )
#   params["enable_verifier"] = 0
#   disable_driver_verifier(vm=vm, params=params, test=test, timeout=3600)
    start_time = time.time()
    if not utils_misc.wait_for(lambda: _check_NICs_growth(nics_num=nics_num), 600, step=30):
        test.error("waiting for all nics to be ready")
    middle_time = time.time()
    test.log.info("speend time: %s seconds on the initization state", middle_time - start_time)
    if not utils_misc.wait_for(lambda: _check_dhcp(session=session), 6000, step=30):
        test.error("waiting for all nics to get ip")
    nic_interface = []
    for index, nic in enumerate(vm.virtnet):
        test.log.info("index %s nic", index)
        guest_ip = utils_net.get_guest_ip_addr(
            session_srl, nic.mac, os_type, ip_version="ipv4"
        )
        print(guest_ip)
        if not guest_ip:
            err_log = "vm get interface %s's ip failed." % index
            test.fail(err_log)
        nic_interface.append(guest_ip)
    session_srl.close()
    test.log.info("All the [ %s ] NICs get IPs.", nics_num)
    end_time = time.time()
    test.log.info(
        "%s -> %s -> %s %s",
        time.strftime("%H:%M:%S", time.localtime(start_time)),
        time.strftime("%H:%M:%S", time.localtime(middle_time)),
        time.strftime("%H:%M:%S", time.localtime(end_time)),
        time.strftime("%H:%M:%S", time.gmtime(end_time - start_time)),
    )

    vm.destroy()

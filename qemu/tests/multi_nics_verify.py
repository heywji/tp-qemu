import os

from virttest import error_context
from virttest import utils_net
from virttest import env_process
from virttest import utils_misc


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
        return (True, msg + 'Nics count match')

    def get_ip_or_renew_dhcp_win(session, mac_addr, timeout=240, count=3):
        """
        Attempt to obtain an IP address via DHCP. If unsuccessful, renew the DHCP lease.
        :param session: The session where the commands will be executed.
        :param mac_addr: The MAC address of the target network adapter.
        :param timeout: Maximum wait time in seconds, default is 240 seconds.
        :param count: The number of retry attempts, default is 3.
        :return: The obtained IP address or None if unsuccessful.
        """
        mac_addr = mac_addr.replace(":", "-")
        attempts = 0
        while attempts < count:
            netadapter_index = (
                f'powershell -Command "(Get-NetAdapter | Where-Object {{ $_.MacAddress -eq {mac_addr} }}).ifIndex"'
            )
            status, netadapter_out = session.cmd_status_output(netadapter_index, timeout=timeout)
            if status != 0:
                test.log.info(f"netadapter_index gets {netadapter_index}")

            check_ip_cmd = (
                f"powershell -Command 'Get-NetIPAddress -InterfaceIndex {netadapter_index}' "
                "| Where-Object { $_.PrefixOrigin -eq 'Dhcp' } | Select-Object -ExpandProperty IPAddress"
            )
            status, ip_out = session.cmd_status_output(check_ip_cmd, timeout=timeout)
            if status == 0 and '10.' in ip_out or '192.168.' in ip_out:
                test.log.info(f"New IP Address obtained: {ip_out}")
                return ip_out
            else:
                test.log.info("No IP Address found. Retrying DHCP...")

            attempts += 1
            test.log.info(f"Attempt {attempts}/{count} to renew DHCP and get IP address...")
            renew_dhcp_cmd = f"powershell -Command 'Restart-NetAdapter -InterfaceIndex {netadapter_index} -Confirm:$false'"
            status, _ = session.cmd_status_output(renew_dhcp_cmd, timeout=timeout)
            if status != 0:
                test.log.info("DHCP renew failed. Retrying...")
            time.sleep(5)
        test.log.info(f"Failed to obtain IP address for MAC {mac_addr} after {count} attempts.")
        return None

    # Get the ethernet cards number from params
    nics_num = int(params.get("nics_num", 8))
    for i in range(nics_num):
        nics = "nic%s" % i
        params["nics"] = ' '.join([params["nics"], nics])
    params["start_vm"] = "yes"
    env_process.preprocess_vm(test, params, env, params["main_vm"])

    vm = env.get_vm(params["main_vm"])
    vm.verify_alive()
    login_timeout = params.get_numeric("login_timeout")
    session = vm.wait_for_login(timeout=login_timeout)

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
                cmd = "nmcli --offline connection add type ethernet con-name %s ifname %s" \
                      " ipv4.method auto > %s" % (ifname, ifname, eth_keyfile_path)
                s, o = session.cmd_status_output(cmd)
                if s != 0:
                    err_msg = "Failed to create ether keyfile: %s\nReason is: %s"
                    test.error(err_msg % (eth_keyfile_path, o))
            session.cmd("chown root:root /etc/NetworkManager/system-connections/*.nmconnection")
            session.cmd("chmod 600 /etc/NetworkManager/system-connections/*.nmconnection")
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
            if os_type == "linux":
                guest_ip = utils_net.get_guest_ip_addr(session_srl, nic.mac, os_type,
                                                       ip_version="ipv4")
            elif os_type == "windows":
                guest_ip = get_ip_or_renew_dhcp_win(session_srl, nic.mac)
            if not guest_ip:
                return False
        return True

    # Check all the interfaces in guest get ips
    session_srl = vm.wait_for_serial_login(timeout=int(params.get("login_timeout", 360)))
    if not utils_misc.wait_for(_check_ip_number, 1000, step=10):
        test.error("Timeout when wait for nics to get ip")

    nic_interface = []
    for index, nic in enumerate(vm.virtnet):
        test.log.info("index %s nic", index)
        guest_ip = utils_net.get_guest_ip_addr(session_srl, nic.mac, os_type,
                                               ip_version="ipv4")
        if not guest_ip:
            err_log = "vm get interface %s's ip failed." % index
            test.fail(err_log)
        nic_interface.append(guest_ip)
    session_srl.close()
    test.log.info("All the [ %s ] NICs get IPs.", nics_num)
    vm.destroy()

import ast
import re

from virttest import data_dir, error_context, utils_misc, utils_net

from provider import virtio_fs_utils, win_driver_installer_test, win_driver_utils
from qemu.tests.balloon_check import BallooningTestWin


@error_context.context_aware
def run(test, params, env):
    """
    Acceptance installer test:

    1) Create shared directories on the host.
    2) Run virtiofsd daemons on the host.
    3) Boot guest with all virtio device.
    4) Delete the virtio fs service on guest.
    5) Install driver from previous virtio-win.iso.
       Or virtio-win-guest-tool.
    6) Start virtio fs service on guest.
    7) Check for ip, gateway and dns consistency before and after
       upgrade driver
    7.1) Set static ip, additional ips, gateway and dns
    7.2) Read registry baseline (IP order, masks, DNS, gateway)
    7.3) Upgrade driver via virtio-win-guest-tools.exe
    7.4) Read registry again, compare IP order against baseline
    7.5) Run ipconfig /all to confirm all IPs and DNS are visible
    7.6) Restore NIC back to DHCP to keep network config consistent
    8) Start virtio fs service on guest.
    9) Verify the qemu-ga version match expected version.
    10) Run driver signature check command in guest.
       Verify target driver.
    11) Run driver function test after virtio-win-guest-tools.exe update.

    :param test: QEMU test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment
    """

    def change_virtio_media(cdrom_virtio):
        """
        change iso for virtio-win.

        :param cdrom_virtio: iso file
        """
        virtio_iso = utils_misc.get_path(data_dir.get_data_dir(), cdrom_virtio)
        test.log.info("Changing virtio iso image to '%s'", virtio_iso)
        vm.change_media("drive_virtio", virtio_iso)

    def get_nic_ifname(session_serial):
        """
        Get NIC connection name via get_windows_nic_attribute.
        PR #4284 adds PowerShell fallback so this works with
        or without wmic.

        :param session_serial: serial session
        :return: NIC connection name string
        """
        return utils_net.get_windows_nic_attribute(
            session_serial, "macaddress", virtio_nic_mac, "netconnectionid"
        )

    def get_nic_guid(session_serial):
        """
        Get the NIC interface GUID via Win32_NetworkAdapterConfiguration
        SettingID. This GUID corresponds to the registry subkey under
        HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\
        Interfaces\\, which is the data source the installer reads.

        :param session_serial: serial session
        :return: NIC interface GUID string (e.g. {XXXXXXXX-...})
        """
        setting_id = utils_net.get_windows_nic_attribute(
            session_serial,
            global_switch="nicconfig",
            key="MACAddress",
            value=virtio_nic_mac,
            target="SettingID",
        )
        setting_id = setting_id.strip().strip('"')
        test.log.info("NIC SettingID (interface GUID): %s", setting_id)
        if not re.match(r"\{[0-9A-Fa-f-]+\}", setting_id):
            test.fail("Failed to get valid NIC GUID, got: %s" % setting_id)
        return setting_id

    def _normalize_ip(ip_str):
        """
        Strip leading zeros from each octet of an IPv4 address.
        Windows registry REG_MULTI_SZ values sometimes store IPs
        with zero-padded octets (e.g. '010.002.002.002') after
        netsh adds them.

        :param ip_str: IPv4 address string, possibly zero-padded
        :return: normalized IPv4 string (e.g. '10.2.2.2')
        """
        return ".".join(str(int(o)) for o in ip_str.split("."))

    def get_registry_ip_order(session_serial, guid):
        """
        Read IP addresses and subnet masks from the registry path
        that the installer actually reads:
        HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\
        Parameters\\Interfaces\\{GUID}

        The installer resolves CurrentControlSet via
        HKLM\\SYSTEM\\Select\\Current -> ControlSet00X, then
        reads IPAddress (REG_MULTI_SZ) and SubnetMask from that
        path. CurrentControlSet is a kernel symlink to the same
        ControlSet, so querying it is equivalent.

        Windows may store IPs with zero-padded octets in
        REG_MULTI_SZ (e.g. '010.002.002.002'), so all returned
        addresses are normalized.

        :param session_serial: serial session
        :param guid: NIC interface GUID
        :return: tuple (ip_list, mask_list) where ip_list is an
                 ordered list of normalized IP strings from the
                 registry
        """
        reg_path = (
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip"
            r"\Parameters\Interfaces\%s" % guid
        )
        ip_cmd = params["reg_query_ip_cmd"] % reg_path
        ip_output = session_serial.cmd_output(ip_cmd)
        test.log.info("Registry IPAddress output:\n%s", ip_output)
        raw_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", ip_output)
        ip_list = [_normalize_ip(ip) for ip in raw_ips]

        mask_cmd = params["reg_query_mask_cmd"] % reg_path
        mask_output = session_serial.cmd_output(mask_cmd)
        test.log.info("Registry SubnetMask output:\n%s", mask_output)
        raw_masks = re.findall(r"(\d+\.\d+\.\d+\.\d+)", mask_output)
        mask_list = [_normalize_ip(m) for m in raw_masks]

        return ip_list, mask_list

    def read_registry_baseline(session_serial):
        """
        Read IP order, DNS servers and gateway from registry as
        the authoritative baseline before driver upgrade.

        :param session_serial: serial session
        :return: dict with keys 'ip_list', 'mask_list', 'dns', 'gateway'
        """
        ip_check_timeout = int(params.get("ip_check_timeout", 30))
        ip_check_interval = int(params.get("ip_check_interval", 5))

        guid = get_nic_guid(session_serial)
        test.log.info("NIC interface GUID: %s", guid)

        def _get_registry_ip_list():
            reg_ips, reg_masks = get_registry_ip_order(session_serial, guid)
            test.log.info(
                "Registry IPAddress (ordered): %s, SubnetMask: %s",
                reg_ips,
                reg_masks,
            )
            return (reg_ips, reg_masks) if reg_ips else None

        result = utils_misc.wait_for(
            _get_registry_ip_list,
            timeout=ip_check_timeout,
            step=ip_check_interval,
            text="Waiting for IPAddress to appear in registry",
            first=5,
        )
        if not result:
            test.fail(
                "No IPAddress found in registry after waiting "
                "%s seconds" % ip_check_timeout
            )
        reg_ip_list, reg_mask_list = result

        expected_ip = params["static_ip"]
        if reg_ip_list[0] != expected_ip:
            test.fail(
                "Registry IP order is wrong after setup: expected "
                "primary IP %s as the first entry but got %s "
                "(full registry list: %s)" % (expected_ip, reg_ip_list[0], reg_ip_list)
            )

        expected_all_ips = [expected_ip] + params.get("additional_ips", "").split()
        for ip in expected_all_ips:
            if ip not in reg_ip_list:
                test.fail(
                    "IP %s is missing from registry after setup, "
                    "current registry list: %s" % (ip, reg_ip_list)
                )

        dns_str = utils_net.get_windows_nic_attribute(
            session_serial,
            global_switch="nicconfig",
            key="MACAddress",
            value=virtio_nic_mac,
            target="DNSServerSearchOrder",
        )
        test.log.info("Baseline DNS servers: %s", dns_str)

        ifname = get_nic_ifname(session_serial)
        gw_cmd = 'netsh interface ip show addresses "%s"' % ifname
        gw_output = session_serial.cmd_output(gw_cmd)
        gw_match = re.search(r"Default Gateway:\s+(\d+\.\d+\.\d+\.\d+)", gw_output)
        gateway = gw_match.group(1) if gw_match else None
        test.log.info("Baseline gateway: %s", gateway)

        baseline = {
            "ip_list": reg_ip_list,
            "mask_list": reg_mask_list,
            "dns": dns_str,
            "gateway": gateway,
            "guid": guid,
        }
        test.log.info("Network baseline captured: %s", baseline)
        return baseline

    def check_network_config(session_serial, baseline):
        """
        Verify IP order, DNS and gateway are preserved after driver
        upgrade by comparing the current registry state against the
        pre-upgrade baseline.

        Optionally run ``ipconfig /all`` to confirm all IPs and DNS
        servers are visible from the OS network stack.

        :param session_serial: serial session
        :param baseline: dict returned by read_registry_baseline()
        """
        ip_check_timeout = int(params.get("ip_check_timeout", 30))
        ip_check_interval = int(params.get("ip_check_interval", 5))
        guid = baseline["guid"]

        def _get_registry_ip_list():
            reg_ips, reg_masks = get_registry_ip_order(session_serial, guid)
            test.log.info(
                "Post-upgrade registry IPAddress (ordered): %s, SubnetMask: %s",
                reg_ips,
                reg_masks,
            )
            return (reg_ips, reg_masks) if reg_ips else None

        result = utils_misc.wait_for(
            _get_registry_ip_list,
            timeout=ip_check_timeout,
            step=ip_check_interval,
            text="Waiting for IPAddress to appear in registry after upgrade",
            first=5,
        )
        if not result:
            test.fail(
                "No IPAddress found in registry after upgrade "
                "(waited %s seconds)" % ip_check_timeout
            )
        post_ip_list, post_mask_list = result

        if post_ip_list[0] != baseline["ip_list"][0]:
            test.fail(
                "Primary IP changed after upgrade: baseline %s, "
                "current %s (full list: %s)"
                % (baseline["ip_list"][0], post_ip_list[0], post_ip_list)
            )
        if set(post_ip_list) != set(baseline["ip_list"]):
            test.fail(
                "IP set changed after upgrade: baseline %s, "
                "current %s" % (baseline["ip_list"], post_ip_list)
            )
        if post_ip_list != baseline["ip_list"]:
            test.log.info(
                "Additional IP order changed after upgrade "
                "(known installer behavior): baseline %s, current %s",
                baseline["ip_list"],
                post_ip_list,
            )

        post_dns = utils_net.get_windows_nic_attribute(
            session_serial,
            global_switch="nicconfig",
            key="MACAddress",
            value=virtio_nic_mac,
            target="DNSServerSearchOrder",
        )
        test.log.info("Post-upgrade DNS servers: %s", post_dns)
        for dns in params.get("static_dns_list", "").split():
            if dns not in post_dns:
                test.fail(
                    "DNS %s is lost after upgrade, baseline DNS: %s, "
                    "current DNS: %s" % (dns, baseline["dns"], post_dns)
                )

        ifname = get_nic_ifname(session_serial)
        gw_cmd = 'netsh interface ip show addresses "%s"' % ifname
        gw_output = session_serial.cmd_output(gw_cmd)
        gw_match = re.search(r"Default Gateway:\s+(\d+\.\d+\.\d+\.\d+)", gw_output)
        post_gateway = gw_match.group(1) if gw_match else None
        if baseline["gateway"] and post_gateway != baseline["gateway"]:
            test.fail(
                "Gateway changed after upgrade: baseline %s, current %s"
                % (baseline["gateway"], post_gateway)
            )

        ipconfig_output = session_serial.cmd_output("ipconfig /all")
        test.log.info("ipconfig /all output:\n%s", ipconfig_output)
        for ip in baseline["ip_list"]:
            if ip not in ipconfig_output:
                test.fail(
                    "IP %s is missing from ipconfig /all after upgrade, "
                    "baseline IPs: %s" % (ip, baseline["ip_list"])
                )
        for dns in params.get("static_dns_list", "").split():
            if dns not in ipconfig_output:
                test.fail("DNS %s is missing from ipconfig /all after upgrade" % dns)
        test.log.info(
            "Network config verified: IP order, DNS and gateway "
            "are consistent with baseline"
        )

    def restore_network_config(session_serial):
        """
        Restore NIC network configuration back to DHCP after the
        static IP check is done, to ensure the network config is
        consistent with the original state before the test.

        :param session_serial: session_serial
        """
        ifname = get_nic_ifname(session_serial)
        test.log.info("Restoring NIC '%s' to DHCP", ifname)
        session_serial.cmd_status('netsh interface ip set address "%s" dhcp' % ifname)
        session_serial.cmd_status('netsh interface ip set dns "%s" dhcp' % ifname)
        test.log.info("NIC '%s' has been restored to DHCP", ifname)

    def setup_network_config(session_serial):
        """
        Set up static IP, additional IPs, gateway and DNS on the
        virtio NIC, then capture a registry baseline for later
        comparison after driver upgrade.

        :param session_serial: serial session
        :return: baseline dict from read_registry_baseline(), or
                 None if the NIC is not virtio-net-pci
        """
        if vm.virtnet[1].nic_model != "virtio-net-pci":
            return None
        ifname = get_nic_ifname(session_serial)

        setup_ip_cmd = params["setup_ip_cmd"] % ifname
        test.log.info("Setting up primary static IP: %s", params["static_ip"])
        session_serial.cmd_status(setup_ip_cmd)

        additional_ips = params.get("additional_ips", "").split()
        additional_masks = params.get("additional_masks", "").split()

        for i, ip in enumerate(additional_ips):
            mask = additional_masks[i] if i < len(additional_masks) else "255.0.0.0"
            cmd = params["add_ip_cmd"] % (ifname, ip, mask)
            test.log.info("Adding additional IP: %s with mask %s", ip, mask)
            session_serial.cmd_status(cmd)

        dns_list = params.get("static_dns_list", "").split()
        for i, dns in enumerate(dns_list):
            cmd = params["add_dns_cmd"] % (ifname, dns, i + 1)
            test.log.info("Adding DNS server: %s at index %s", dns, i + 1)
            session_serial.cmd_status(cmd)

        return read_registry_baseline(session_serial)

    devcon_path = params["devcon_path"]
    run_install_cmd = params["run_install_cmd"]
    media_type = params["virtio_win_media_type"]

    # gagent version check test config
    qemu_ga_pkg = params["qemu_ga_pkg"]
    gagent_pkg_info_cmd = params["gagent_pkg_info_cmd"]
    gagent_install_cmd = params["gagent_install_cmd"]
    gagent_uninstall_cmd = params["gagent_uninstall_cmd"]

    vm = env.get_vm(params["main_vm"])
    session = vm.wait_for_login()

    virtio_nic_mac = vm.virtnet[1].mac

    expected_gagent_version = win_driver_installer_test.install_gagent(
        session, test, qemu_ga_pkg, gagent_install_cmd, gagent_pkg_info_cmd
    )

    win_driver_installer_test.uninstall_gagent(session, test, gagent_uninstall_cmd)

    error_context.context("Delete the viofs service at guest...")
    virtio_fs_utils.delete_viofs_serivce(test, params, session)

    win_driver_installer_test.win_uninstall_all_drivers(session, test, params)
    change_virtio_media(params["cdrom_virtio_downgrade"])

    session = vm.reboot(session)

    if params.get("update_from_previous_installer", "no") == "yes":
        error_context.context("install drivers from previous installer", test.log.info)
        session = win_driver_installer_test.run_installer_with_interaction(
            vm, session, test, params, run_install_cmd, copy_files_params=params
        )
    else:
        for driver_name, device_name, device_hwid in zip(
            win_driver_installer_test.driver_name_list,
            win_driver_installer_test.device_name_list,
            win_driver_installer_test.device_hwid_list,
        ):
            if params.get("boot_with_viomem", "no") == "no":
                if driver_name == "viomem":
                    continue
            win_driver_utils.install_driver_by_virtio_media(
                session, test, devcon_path, media_type, driver_name, device_hwid
            )
        win_driver_installer_test.install_gagent(
            session, test, qemu_ga_pkg, gagent_install_cmd, gagent_pkg_info_cmd
        )

    session_serial = vm.wait_for_serial_login()
    error_context.context(
        "Set up static IP/DNS on virtio NIC before upgrade", test.log.info
    )
    network_baseline = setup_network_config(session_serial)
    session_serial.close()

    error_context.context("Run viofs service...")
    virtio_fs_utils.run_viofs_service(test, params, session)

    error_context.context("Upgrade virtio driver to original", test.log.info)
    change_virtio_media(params["cdrom_virtio"])
    session = win_driver_installer_test.run_installer_with_interaction(
        vm, session, test, params, run_install_cmd, copy_files_params=params
    )

    if network_baseline:
        session_serial = vm.wait_for_serial_login()
        error_context.context(
            "Check network config after driver upgrade", test.log.info
        )
        check_network_config(session_serial, network_baseline)
        error_context.context(
            "Restore network config to DHCP after upgrade check", test.log.info
        )
        restore_network_config(session_serial)
        session_serial.close()

    error_context.context("Run viofs service after upgrade...")
    virtio_fs_utils.run_viofs_service(test, params, session)

    win_driver_installer_test.check_gagent_version(
        session, test, gagent_pkg_info_cmd, expected_gagent_version
    )
    win_driver_installer_test.driver_check(session, test, params)

    error_context.context("Run driver function test after update", test.log.info)
    fail_tests = []
    test_drivers = params.get(
        "test_drivers", win_driver_installer_test.driver_name_list
    )
    if params.get("test_drivers"):
        test_drivers = params["test_drivers"].split()
    for driver_name in test_drivers:
        test_name = params.get("driver_test_name_%s" % driver_name)
        test_func = "win_driver_installer_test.%s_test" % test_name
        driver_test_params = params.get("driver_test_params_%s" % driver_name, "{}")
        if driver_name == "balloon":
            balloon_test_win = BallooningTestWin(test, params, env)
            driver_test_params = {"balloon_test_win": balloon_test_win}
        else:
            driver_test_params = ast.literal_eval(driver_test_params)
        try:
            eval("%s(test, params, vm, **driver_test_params)" % test_func)
        except Exception as e:
            fail_tests.append("%s:\n%s" % (test_name, str(e)))
    if fail_tests:
        test.fail("Function test failed list is %s after update" % fail_tests)

    session.close()

import logging

from virttest import error_context, utils_misc

LOG_JOB = logging.getLogger("avocado.test")


@error_context.context_aware
def run(test, params, env):
    """
    just ready for wji to test or debug some function's work.

    1) Start the VM.
    2) Configure and verify the advanced parameters of the NIC.
    3) Use TraceView.exe to apply filters and capture relevant keywords.
    4) Restart the NIC.
    5) Monitor the output in TraceView.exe and extract the captured keywords.
    6) Restore the default parameter value

    :param test: QEMU test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    timeout = params.get_numeric("login_timeout", 240)
    vm_name = params["main_vm"]
    vm = env.get_vm(vm_name)
    vm.verify_alive()
    session = vm.wait_for_serial_login(timeout=timeout)

    key = "VolumeName='virtio-win*'"
    try:
        vol_virtio = utils_misc.get_win_disk_vol(session, condition=key)
    except Exception:
        test.error("Could not get virtio-win disk vol!")
    print(f"wjiwji: vol_virtio is {vol_virtio}")

    session.close()

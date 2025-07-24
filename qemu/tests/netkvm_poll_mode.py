from virttest import utils_net
from virtio_win import get_keyword_from_traceview

def run(test, params, env):
    """
    Test net adapter after set NetAdapterrss, this case will:

    1) Boot up VM with specific smp and queues
    2) Configure RSS in VM
    3) Check ndis Poll Mode state
    4) Check traceview output

    :param test: QEMU test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environmen.
    """

    vm = env.get_vm(params["main_vm"])
    session = vm.wait_for_login()

    # Enable RSS and setup RSS Queues value
    rss_queues = params["rss_queues"]
    rss, rss_value = params["enable_rss"].split(" ")
    rss_queues, rss_queues_value = (params["setup_rss_queues"] % rss_queues).split(" ")
    utils_net.set_netkvm_param_value(vm, rss, rss_value)
    utils_net.set_netkvm_param_value(vm, rss_queues, rss_queues_value)

    #Check ndis poll mode state
    output = utils_net.get_netkvm_param_value(vm, "*NdisPoll")
    test.log.info("ndis poll mode is %s" % output)

    #Check the traceview content
    keyword = params.get(keyword)
    result = get_keyword_from_traceview(session, vm, params, keyword)
    test.log.info("Found '%s' in TraceView logs" % result)
    
    session.close()
